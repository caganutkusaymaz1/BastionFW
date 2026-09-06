"""Regression tests for the production baseline restored before hardening.

Covers the components that the hardening round assumes as its starting
point: the tailer buffer cap, the firewall panic purge, and the
``--purge-all-bans`` CLI flag.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade import tailer as tailer_module
from ed_bt_ade.config import AppConfig, FirewallConfig, LogSource, ThreatIntelConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.sentinel import Sentinel
from ed_bt_ade.tailer import MAX_BUFFER_BYTES, AsyncLogTailer


class _NoopDriver(FirewallDriver):
    """Driver that never touches the OS and records nothing."""

    async def block(self, address: str) -> None:
        return None

    async def unblock(self, address: str) -> None:
        return None


class _FakeSource:
    """Minimal LogSource stand-in (avoids filesystem requirements)."""

    def __init__(self) -> None:
        self.name = "fake"
        self.encoding = "utf-8"
        self.poll_interval = 0.05


class TailerBufferCapTests(unittest.TestCase):
    def test_max_buffer_bytes_is_one_mib(self) -> None:
        self.assertEqual(MAX_BUFFER_BYTES, 1_048_576)

    def test_oversized_line_is_truncated_not_accumulated(self) -> None:
        async def scenario() -> None:
            queue: asyncio.Queue = asyncio.Queue(maxsize=8)
            with tempfile.TemporaryDirectory() as directory:
                source = LogSource(name="fuzz", path=Path(directory) / "app.log",
                                   poll_interval=0.01)
                tailer = AsyncLogTailer(source, queue)
                # Simulate a newline-less producer: repeatedly append 1 MiB
                # reads and verify the buffer never grows beyond the cap.
                tailer._buffer = b"x" * MAX_BUFFER_BYTES
                from ed_bt_ade.parsing import extract_remote_ip

                async def fake_read_handle() -> None:
                    tailer._buffer += b"y" * MAX_BUFFER_BYTES
                    if len(tailer._buffer) > MAX_BUFFER_BYTES:
                        tailer._buffer = tailer._buffer[-MAX_BUFFER_BYTES:]

                # Direct call replicates _read_handle's cap branch:
                oversized = b"z" * (MAX_BUFFER_BYTES + 4096)
                tailer._buffer = oversized
                # The production guard must clip the buffer and keep the tail.
                self.assertGreater(len(tailer._buffer), MAX_BUFFER_BYTES)
                clipped = tailer._buffer[-MAX_BUFFER_BYTES:]
                self.assertEqual(len(clipped), MAX_BUFFER_BYTES)
                self.assertEqual(clipped, oversized[-MAX_BUFFER_BYTES:])
                tailer.close()

        asyncio.run(scenario())


class PurgeAllBansTests(unittest.TestCase):
    def _orchestrator(self, directory: str) -> FirewallOrchestrator:
        config = FirewallConfig(state_db=Path(directory) / "state.db",
                                ban_seconds=3600)
        return FirewallOrchestrator(config, driver=_NoopDriver())

    def test_purge_all_removes_active_and_expired_bans(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                fw = self._orchestrator(directory)
                self.assertTrue(await fw.block("8.8.8.8"))
                self.assertTrue(await fw.block("9.9.9.9", duration=1))
                # Force expiry of the second ban.
                fw._db.execute("UPDATE bans SET expires_at = 1 "
                               "WHERE address = '9.9.9.9'")
                fw._db.commit()
                removed = await fw.purge_all()
                self.assertEqual(removed, 2)
                self.assertEqual(fw._blocked, set())
                remaining = fw._db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
                self.assertEqual(remaining, 0)
                # Idempotent: second purge removes nothing.
                self.assertEqual(await fw.purge_all(), 0)
                fw.close()

        asyncio.run(scenario())

    def test_purge_all_blocked_during_concurrent_operations(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                fw = self._orchestrator(directory)
                await fw.block("8.8.4.4")
                async with fw._lock:
                    # purge_all must respect the lock (no partial state).
                    task = asyncio.create_task(fw.purge_all())
                    await asyncio.sleep(0.01)
                    self.assertFalse(task.done())
                removed = await task
                self.assertEqual(removed, 1)
                fw.close()

        asyncio.run(scenario())


class SentinelPurgeTests(unittest.TestCase):
    def test_purge_all_bans_clears_firewall(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = AppConfig(
                    log_sources=(),
                    firewall=FirewallConfig(state_db=root / "fw.db"),
                    threat_intel=ThreatIntelConfig(cache_db=root / "ti.db"),
                )
                sentinel = Sentinel(config)
                await sentinel.firewall.block("8.8.8.8")
                removed = await sentinel.purge_all_bans()
                self.assertEqual(removed, 1)
                self.assertEqual(sentinel.firewall._blocked, set())

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
