import asyncio
import tempfile
import unittest
from pathlib import Path
from typing import Callable

from ed_bt_ade.config import WafConfig
from ed_bt_ade.rollback import (
    WafDeadmanSwitch,
    engine_line_for_mode,
    read_engine_mode,
    write_engine_mode,
)


class FakeMetrics:
    def __init__(self) -> None:
        self.values: dict[str, float] = {}

    def set(self, name: str, value: float) -> None:
        self.values[name] = value


class FlakyDeadmanSwitch(WafDeadmanSwitch):
    """Deadman whose probes are scripted per call."""

    def __init__(self, config: WafConfig, metrics: object,
                 results: list[bool], notify=None) -> None:
        super().__init__(config, metrics, notify=notify)
        self._results = list(results)
        self.calls = 0

    async def _probe(self) -> bool:
        self.calls += 1
        if not self._results:
            return True
        return self._results.pop(0)


class RollbackTests(unittest.TestCase):
    def test_engine_mode_files_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "engine-mode.conf"
            write_engine_mode("block", path)
            self.assertEqual(read_engine_mode(path), "block")
            write_engine_mode("detect", path)
            self.assertEqual(read_engine_mode(path), "detect")
            self.assertIn("On", engine_line_for_mode("block"))
            self.assertIn("DetectionOnly", engine_line_for_mode("detect"))

    @staticmethod
    def _run_until(deadman: WafDeadmanSwitch, predicate: Callable[[], bool]) -> None:
        async def scenario() -> None:
            stop = asyncio.Event()
            task = asyncio.create_task(deadman.run(stop))
            while not predicate():
                await asyncio.sleep(0.01)
                if task.done():
                    break
            stop.set()
            await task

        asyncio.run(scenario())

    def test_deadman_trips_and_fails_open_after_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = WafConfig(
                enabled=True,
                data_dir=Path(directory),
                health_url="",
                health_interval_seconds=0.05,
                failure_threshold=2,
            )
            metrics = FakeMetrics()
            alerts: list[dict[str, object]] = []
            deadman = FlakyDeadmanSwitch(config, metrics,
                                         results=[False, False, False],
                                         notify=alerts.append)
            self._run_until(deadman, lambda: deadman.tripped)
            self.assertTrue(deadman.tripped)
            self.assertEqual(deadman.engine_mode, "detect")
            self.assertEqual(metrics.values.get("waf_fail_open_active"), 1.0)
            self.assertEqual(read_engine_mode(config.engine_mode_path), "detect")
            self.assertTrue(config.fail_open_flag_path.exists())
            self.assertTrue(any(alert.get("rule") == "waf_fail_open"
                                for alert in alerts))

    def test_deadman_recovery_clears_flag_but_keeps_detect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = WafConfig(
                enabled=True,
                data_dir=Path(directory),
                health_url="",
                health_interval_seconds=0.05,
                failure_threshold=1,
            )
            metrics = FakeMetrics()
            deadman = FlakyDeadmanSwitch(config, metrics,
                                         results=[False, True, True])
            self._run_until(deadman,
                            lambda: deadman.tripped
                            and not config.fail_open_flag_path.exists())
            self.assertTrue(deadman.tripped)
            self.assertFalse(config.fail_open_flag_path.exists())
            self.assertEqual(read_engine_mode(config.engine_mode_path), "detect")
            self.assertEqual(metrics.values.get("waf_fail_open_active"), 1.0)

    def test_disabled_deadman_does_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = WafConfig(enabled=False, data_dir=Path(directory))
            deadman = FlakyDeadmanSwitch(config, FakeMetrics(), results=[])
            asyncio.run(deadman.run(asyncio.Event()))
            self.assertFalse(deadman.tripped)
            self.assertFalse(config.engine_mode_path.exists())


if __name__ == "__main__":
    unittest.main()
