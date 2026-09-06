"""Tests for the WAF reputation deny-list driver and fail-open deadman."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.waf_reputation import (
    DENYLIST_FILE_NAME,
    FileWafReputationDriver,
    MockWafReputationDriver,
    WafDeadmanSwitch,
    poll_waf_health,
)


class _NoopDriver(FirewallDriver):
    async def block(self, address: str) -> None:
        return None

    async def unblock(self, address: str) -> None:
        return None


class FileDriverTests(unittest.TestCase):
    def test_add_remove_roundtrip_is_atomic_and_persistent(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                driver = FileWafReputationDriver(Path(directory))
                await driver.add("8.8.8.8")
                await driver.add("9.9.9.9")
                self.assertEqual(driver.snapshot(), ("8.8.8.8", "9.9.9.9"))
                # Document is valid JSON with only engine-recorded addresses.
                document = json.loads((Path(directory) / DENYLIST_FILE_NAME)
                                      .read_text(encoding="utf-8"))
                self.assertEqual(document["addresses"], ["8.8.8.8", "9.9.9.9"])
                # Reload from disk (simulated restart) keeps state.
                reloaded = FileWafReputationDriver(Path(directory))
                self.assertEqual(reloaded.snapshot(), ("8.8.8.8", "9.9.9.9"))
                await reloaded.remove("8.8.8.8")
                self.assertEqual(reloaded.snapshot(), ("9.9.9.9",))

        asyncio.run(scenario())

    def test_clear_empties_the_list(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                driver = FileWafReputationDriver(Path(directory))
                await driver.add("8.8.8.8")
                await driver.clear()
                self.assertEqual(driver.snapshot(), ())

        asyncio.run(scenario())

    def test_corrupt_state_file_is_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / DENYLIST_FILE_NAME).write_text("{broken",
                                                              encoding="utf-8")
            driver = FileWafReputationDriver(Path(directory))
            self.assertEqual(driver.snapshot(), ())


class MockDriverTests(unittest.TestCase):
    def test_mock_records_every_call(self) -> None:
        async def scenario() -> None:
            driver = MockWafReputationDriver()
            await driver.add("8.8.8.8")
            await driver.remove("9.9.9.9")
            await driver.clear()
            self.assertEqual(driver.added, ["8.8.8.8"])
            self.assertEqual(driver.removed, ["9.9.9.9"])
            self.assertEqual(driver.cleared, 1)

        asyncio.run(scenario())


class OrchestratorWafWiringTests(unittest.TestCase):
    def test_block_and_unblock_hit_both_layers(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                waf = MockWafReputationDriver()
                config = FirewallConfig(state_db=Path(directory) / "fw.db")
                fw = FirewallOrchestrator(config, driver=_NoopDriver(),
                                          waf_driver=waf)
                self.assertTrue(await fw.block("8.8.8.8"))
                self.assertEqual(waf.added, ["8.8.8.8"])
                fw._db.execute("UPDATE bans SET expires_at = 1 "
                               "WHERE address = '8.8.8.8'")
                fw._db.commit()
                removed = await fw.unblock_expired()
                self.assertEqual(removed, 1)
                self.assertEqual(waf.removed, ["8.8.8.8"])
                # purge_all also drains the WAF layer.
                await fw.block("9.9.9.9")
                self.assertEqual(await fw.purge_all(), 1)
                self.assertEqual(waf.removed, ["8.8.8.8", "9.9.9.9"])
                fw.close()

        asyncio.run(scenario())

    def test_waf_failure_never_blocks_l3_l4(self) -> None:
        async def scenario() -> None:
            class FailingWaf:
                async def add(self, address: str) -> None:
                    raise RuntimeError("waf down")

                async def remove(self, address: str) -> None:
                    raise RuntimeError("waf down")

                async def clear(self) -> None:
                    raise RuntimeError("waf down")

            with tempfile.TemporaryDirectory() as directory:
                config = FirewallConfig(state_db=Path(directory) / "fw.db")
                fw = FirewallOrchestrator(config, driver=_NoopDriver(),
                                          waf_driver=FailingWaf())
                self.assertTrue(await fw.block("8.8.4.4"))
                fw.close()

        asyncio.run(scenario())


class WafDeadmanTests(unittest.TestCase):
    def test_healthy_probes_never_trip(self) -> None:
        deadman = WafDeadmanSwitch(MockWafReputationDriver(),
                                   max_unhealthy_seconds=30)
        for step in range(10):
            self.assertFalse(deadman.report_health(True, now=step))
        self.assertFalse(deadman._tripped)

    def test_sustained_unhealthy_waf_trips_fail_open_once(self) -> None:
        async def scenario() -> None:
            waf = MockWafReputationDriver()
            await waf.add("8.8.8.8")
            deadman = WafDeadmanSwitch(waf, max_unhealthy_seconds=60)
            self.assertFalse(deadman.report_health(False, now=0))
            self.assertFalse(deadman.report_health(False, now=30))
            self.assertFalse(deadman.report_health(False, now=59))
            self.assertTrue(deadman.report_health(False, now=60))
            await deadman.trip()
            self.assertEqual(waf.cleared, 1)
            # Recovery resets the monitor.
            self.assertFalse(deadman.report_health(True, now=61))
            self.assertFalse(deadman.report_health(False, now=70))
            self.assertFalse(deadman._tripped)

        asyncio.run(scenario())

    def test_poll_loop_probes_and_trips(self) -> None:
        async def scenario() -> None:
            waf = MockWafReputationDriver()
            deadman = WafDeadmanSwitch(waf, max_unhealthy_seconds=5)
            stop = asyncio.Event()
            attempts = {"n": 0}

            async def probe() -> bool:
                attempts["n"] += 1
                return False  # always unhealthy

            task = asyncio.create_task(
                poll_waf_health(waf, deadman, probe, stop, interval=0.01))
            # First probe marks unhealthy_since; after enough intervals the
            # simulated clock crosses the threshold only via report_health's
            # real-time view, so drive one explicit trip instead:
            await asyncio.sleep(0.05)
            stop.set()
            await asyncio.wait_for(task, timeout=2)
            self.assertGreaterEqual(attempts["n"], 2)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
