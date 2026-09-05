import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.rollback import (
    DEFAULT_ROLLBACK_SECONDS,
    DeadmanSwitch,
    RollbackCoordinator,
    build_deadman_script,
    renewal_interval,
    resolve_rollback_seconds,
    validate_state_dir_for_script,
)


class RecordingDriver:
    def __init__(self) -> None:
        self.blocked: list[str] = []
        self.unblocked: list[str] = []

    async def block(self, address: str) -> None:
        self.blocked.append(address)

    async def unblock(self, address: str) -> None:
        self.unblocked.append(address)


class RollbackTests(unittest.TestCase):
    def test_deadman_renews_liveness_file_and_cleans_up(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                switch = DeadmanSwitch(Path(directory), rollback_seconds=DEFAULT_ROLLBACK_SECONDS)
                switch.start()
                path = switch.path
                self.assertTrue(path.exists())
                first = path.stat().st_mtime_ns
                await asyncio.sleep(0.01)
                switch.renew()
                self.assertGreaterEqual(path.stat().st_mtime_ns, first)
                await switch.close()
                self.assertFalse(path.exists())

        asyncio.run(scenario())

    def test_rollback_coordinator_removes_all_active_bans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = FirewallConfig(state_db=Path(directory) / "state.db")
            firewall = FirewallOrchestratorStub(config)
            coordinator = RollbackCoordinator(firewall)
            removed = asyncio.run(coordinator.rollback_all_bans())
            self.assertEqual(removed, 2)
            self.assertEqual(firewall.state, {})

    def test_deadman_script_is_posix_sh_and_self_contained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = build_deadman_script(Path(directory), 120)
            self.assertIn("#!/bin/sh", script)
            self.assertIn("ROLLBACK_SECONDS=120", script)
            self.assertIn("nft delete element", script)
            self.assertIn("iptables -D INPUT", script)
            self.assertNotIn("python", script.lower().replace("python-free", ""))

    def test_env_override_respects_minimum(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_ROLLBACK_SECONDS": "5"}):
            self.assertEqual(resolve_rollback_seconds(), DEFAULT_ROLLBACK_SECONDS)
        with patch.dict(os.environ, {"ED_BT_ADE_ROLLBACK_SECONDS": "600"}):
            self.assertEqual(resolve_rollback_seconds(), 600)
        with patch.dict(os.environ, {"ED_BT_ADE_ROLLBACK_SECONDS": "abc"}):
            self.assertEqual(resolve_rollback_seconds(), DEFAULT_ROLLBACK_SECONDS)

    def test_renewal_interval_is_inside_rollback_window(self) -> None:
        self.assertLess(renewal_interval(120), 120)
        self.assertGreaterEqual(renewal_interval(120), 1.0)

    def test_state_dir_with_shell_metacharacters_is_rejected(self) -> None:
        for hostile in ('/tmp/ev"il', '/tmp/e$v"il', '/tmp/e`vil',
                        '/tmp/evil\\', '/tmp/e\nvil'):
            with self.assertRaises(ValueError):
                validate_state_dir_for_script(Path(hostile))
        # A clean path still resolves.
        self.assertEqual(validate_state_dir_for_script(Path('/var/lib/bastionfw')),
                         '/var/lib/bastionfw')

    def test_deadman_script_refuses_hostile_state_dir(self) -> None:
        with self.assertRaises(ValueError):
            build_deadman_script(Path('/tmp/e"vil'), 120)


class SentinelRollbackWindowTests(unittest.TestCase):
    def test_sentinel_uses_env_rollback_window(self) -> None:
        """The runtime deadman window must honor the documented env override."""
        from ed_bt_ade.config import AppConfig
        from ed_bt_ade.sentinel import Sentinel

        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(
                log_sources=(),
                firewall=FirewallConfig(state_db=Path(directory) / 'state.db'),
            )
            with patch.dict(os.environ, {'ED_BT_ADE_ROLLBACK_SECONDS': '600'}):
                sentinel = Sentinel(config)
                try:
                    self.assertEqual(sentinel.deadman.seconds, 600)
                finally:
                    sentinel.firewall.close()


class FirewallOrchestratorStub:
    """Minimal stand-in exposing the unblock_expired() contract."""

    def __init__(self, config: FirewallConfig) -> None:
        self.state: dict[str, float] = {
            "8.8.8.8": time.time() + 3600,
            "9.9.9.9": time.time() + 3600,
        }

    async def unblock_expired(self) -> int:
        if not self.state:
            return 0
        count = len(self.state)
        self.state.clear()
        return count


if __name__ == "__main__":
    unittest.main()
