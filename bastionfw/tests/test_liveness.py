"""Tests for the standalone liveness watchdog (ed_bt_ade.liveness)."""

import tempfile
import time
import unittest
from pathlib import Path

from ed_bt_ade.liveness import (
    LIVENESS_FILE_NAME,
    liveness_age_seconds,
    main,
    refresh_liveness,
    run_watchdog,
)


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


if __name__ == "__main__":
    unittest.main()
