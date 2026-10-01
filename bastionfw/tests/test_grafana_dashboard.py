"""Static checks for deploy/grafana-dashboard.json."""

import json
import unittest
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[2] / "bastionfw" / "deploy" / "grafana-dashboard.json"

# Metric names the engine actually exposes (see logger.py / sentinel.py).
EXPECTED_METRICS = (
    "sentinel_logs_processed_total",
    "sentinel_threats_detected_total",
    "sentinel_ips_blocked_total",
    "sentinel_pipeline_errors_total",
    "sentinel_pipeline_latency_seconds",
)


@unittest.skipUnless(DASHBOARD.is_file(), "grafana dashboard not present")
class GrafanaDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(DASHBOARD.read_text(encoding="utf-8"))

    def test_dashboard_is_valid_and_titled(self) -> None:
        self.assertEqual(self.document["title"], "BastionFW — Operations")
        self.assertTrue(self.document["panels"])

    def test_every_panel_targets_a_prometheus_datasource(self) -> None:
        for panel in self.document["panels"]:
            self.assertEqual(panel["datasource"]["type"], "prometheus")
            self.assertTrue(panel["targets"])

    def test_expressions_cover_the_exposed_metrics(self) -> None:
        expressions = " ".join(
            target["expr"]
            for panel in self.document["panels"]
            for target in panel["targets"])
        for metric in EXPECTED_METRICS:
            self.assertIn(metric, expressions)

    def test_prometheus_datasource_variable_exists(self) -> None:
        names = [item["name"] for item in self.document["templating"]["list"]]
        self.assertIn("DS_PROMETHEUS", names)


if __name__ == "__main__":
    unittest.main()
