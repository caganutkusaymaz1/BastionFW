"""Tests for the standalone liveness watchdog (ed_bt_ade.liveness)."""

import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.liveness import (
    LIVENESS_FILE_NAME,
    build_expiry_hook,
    liveness_age_seconds,
    main,
    purge_engine_bans,
    refresh_liveness,
    run_watchdog,
)


class _RecordingDriver(FirewallDriver):
    def __init__(self) -> None:
        self.unblocked: list[str] = []

    async def block(self, address: str) -> None:
        return None

    async def unblock(self, address: str) -> None:
        self.unblocked.append(address)


def _seed_state_dir(directory: str) -> Path:
    """Create a state dir with two active engine-owned bans."""
    state = Path(directory)
    firewall = FirewallOrchestrator(
        FirewallConfig(state_db=state / "firewall.sqlite3"),
        driver=_RecordingDriver())

    async def seed() -> None:
        await firewall.block("8.8.8.8")
        await firewall.block("9.9.9.9")

    asyncio.run(seed())
    firewall.close()
    return state


class LivenessTests(unittest.TestCase):
    def test_missing_file_is_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(liveness_age_seconds(Path(directory)))
            fired: list[str] = []
            self.assertEqual(
                run_watchdog(Path(directory), 60, on_expired=lambda: fired.append("x")),
                "missing")
            self.assertEqual(fired, [])

    def test_fresh_file_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            refresh_liveness(state)
            self.assertLessEqual(liveness_age_seconds(state), 1)
            self.assertEqual(run_watchdog(state, 60), "healthy")

    def test_stale_file_expires_and_fires_hook_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            refresh_liveness(state)
            path = state / LIVENESS_FILE_NAME
            stale = time.time() - 3600
            import os

            os.utime(path, (stale, stale))
            fired: list[str] = []
            self.assertEqual(
                run_watchdog(state, 120, on_expired=lambda: fired.append("roll")),
                "expired")
            self.assertEqual(fired, ["roll"])

    def test_cli_main_runs_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["--state-dir", directory, "--max-age", "60"]), 0)

    def test_purge_engine_bans_removes_active_bans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = _seed_state_dir(directory)
            driver = _RecordingDriver()
            removed = purge_engine_bans(state, driver=driver)
            self.assertEqual(removed, 2)
            self.assertEqual(sorted(driver.unblocked), ["8.8.8.8", "9.9.9.9"])

    def test_purge_engine_bans_without_state_db_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(purge_engine_bans(Path(directory)), 0)

    def test_expiry_hook_purges_and_clears_liveness_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = _seed_state_dir(directory)
            refresh_liveness(state)
            driver = _RecordingDriver()
            hook = build_expiry_hook(state, driver=driver)
            hook()
            self.assertEqual(sorted(driver.unblocked), ["8.8.8.8", "9.9.9.9"])
            self.assertFalse((state / LIVENESS_FILE_NAME).exists())

    def test_cli_no_purge_skips_the_rollback_hook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = _seed_state_dir(directory)
            refresh_liveness(state)
            path = state / LIVENESS_FILE_NAME
            stale = time.time() - 3600
            import os

            os.utime(path, (stale, stale))
            self.assertEqual(
                main(["--state-dir", directory, "--max-age", "60", "--no-purge"]), 0)
            # The ban state is untouched with --no-purge.
            firewall = FirewallOrchestrator(
                FirewallConfig(state_db=state / "firewall.sqlite3"),
                driver=_RecordingDriver())
            self.assertEqual(len(firewall._blocked), 2)
            firewall.close()


if __name__ == "__main__":
    unittest.main()
