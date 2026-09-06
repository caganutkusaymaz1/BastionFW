import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig, WafConfig, load_config
from ed_bt_ade.detector import LogEvent
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.sentinel import Sentinel
from ed_bt_ade.waf_reputation import (
    FileWafReputationDriver,
    MockWafReputationDriver,
    detect_waf_reputation_driver,
)


class RecordingFirewallDriver(FirewallDriver):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def block(self, address: str) -> None:
        self.calls.append(("block", address))

    async def unblock(self, address: str) -> None:
        self.calls.append(("unblock", address))


class FileWafReputationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.config = WafConfig(enabled=True, data_dir=Path(self._directory.name))
        self.driver = FileWafReputationDriver(self.config)

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_block_writes_state_and_caddy_include(self) -> None:
        expires = time.time() + 3600
        asyncio.run(self.driver.block("198.51.100.9", expires))
        state = json.loads(self.config.deny_list_path.read_text())
        self.assertEqual(state["entries"][0]["address"], "198.51.100.9")
        include = self.config.deny_include_path.read_text()
        self.assertIn("remote_ip 198.51.100.9", include)
        self.assertIn("respond @bastionfw_denied", include)
        self.assertEqual(self.driver.active_count(), 1)

    def test_unblock_and_purge_expired_clear_entries(self) -> None:
        asyncio.run(self.driver.block("198.51.100.9", time.time() + 3600))
        asyncio.run(self.driver.block("203.0.113.8", time.time() - 5))
        asyncio.run(self.driver.purge_expired())
        self.assertEqual(self.driver.active_count(), 1)
        include = self.config.deny_include_path.read_text()
        self.assertNotIn("203.0.113.8", include)
        asyncio.run(self.driver.unblock("198.51.100.9"))
        self.assertEqual(self.driver.active_count(), 0)
        self.assertEqual(self.config.deny_include_path.read_text(), "")

    def test_disabled_config_yields_mock(self) -> None:
        driver = detect_waf_reputation_driver(WafConfig(enabled=False))
        self.assertIsInstance(driver, MockWafReputationDriver)
        driver = detect_waf_reputation_driver(self.config)
        self.assertIsInstance(driver, FileWafReputationDriver)


class BidirectionalSyncTests(unittest.TestCase):
    def test_block_and_expiry_sync_across_both_layers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            firewall_driver = RecordingFirewallDriver()
            waf_driver = MockWafReputationDriver()
            config = FirewallConfig(state_db=Path(directory) / "state.db")
            firewall = FirewallOrchestrator(config, firewall_driver, waf=waf_driver)
            self.assertTrue(asyncio.run(firewall.block("8.8.8.8", duration=3600)))
            self.assertTrue(asyncio.run(firewall.block("1.1.1.1", duration=3600)))
            self.assertEqual(waf_driver.active_count(), 2)
            # Force the second ban to expire without waiting on a clock.
            firewall._db.execute("UPDATE bans SET expires_at = ? WHERE address = ?",
                                 (time.time() - 1, "1.1.1.1"))
            firewall._db.commit()
            self.assertEqual(asyncio.run(firewall.unblock_expired()), 1)
            self.assertEqual(waf_driver.active_count(), 1)
            self.assertIn("8.8.8.8", waf_driver.entries)
            self.assertNotIn("1.1.1.1", waf_driver.entries)
            firewall.close()


class SentinelWafIntegrationTests(unittest.TestCase):
    def _sentinel(self, directory: str) -> Sentinel:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps({
            "log_sources": [
                {"name": "coraza_waf", "path": "/tmp/audit.json",
                 "source_type": "coraza_audit"},
            ],
            "firewall": {"backend": "dry-run",
                         "state_db": str(Path(directory) / "fw.sqlite3")},
            "threat_intel": {"cache_db": str(Path(directory) / "ti.sqlite3")},
            "waf": {"enabled": False, "data_dir": str(Path(directory) / "waf")},
        }))
        return Sentinel(load_config(config_path))

    def test_coraza_pipeline_bans_and_tracks_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = self._sentinel(directory)
            line = json.dumps({
                "transaction": {
                    "client_ip": "8.8.8.8",
                    "is_interrupted": True,
                    "request": {"method": "GET", "uri": "/?q=union+select"},
                    "response": {"status": 403},
                },
                "messages": [
                    {"message": "SQL Injection Attack Detected",
                     "data": {"id": 942100, "severity": "CRITICAL",
                              "msg": "Detects SQL injection", "data": "union select"}},
                    {"message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
                     "data": {"id": 949110, "severity": "CRITICAL",
                              "msg": "Inbound Anomaly Score Exceeded"}},
                ],
            })
            sentinel.stop.set()
            sentinel.queue.put_nowait(LogEvent("coraza_waf", line,
                                               source_type="coraza_audit"))
            asyncio.run(sentinel._process())
            self.assertIn("8.8.8.8", sentinel.firewall.active_addresses())
            self.assertEqual(sentinel.metrics.value("sentinel_ips_blocked_total"), 1)
            self.assertEqual(sentinel.metrics.value("waf_requests_blocked_total"), 1)
            self.assertEqual(sentinel.metrics.value("waf_rule_matches_total"), 2)
            snapshot = sentinel.dashboard_snapshot()
            self.assertEqual(snapshot["waf"]["requests_blocked"], 1)
            top = snapshot["waf"]["top_rules"]
            self.assertEqual([item["rule_id"] for item in top],
                             ["942100", "949110"])
            sentinel.firewall.close()
            asyncio.run(sentinel.threat_intel.close())

    def test_snapshot_waf_aggregates_and_deny_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sentinel = self._sentinel(directory)
            sentinel.metrics.inc("waf_requests_blocked_total", 4)
            sentinel.metrics.inc("waf_rule_matches_total",
                                 labels={"rule_id": "942100"})
            sentinel.metrics.inc("waf_rule_matches_total", 3,
                                 labels={"rule_id": "920350"})
            snapshot = sentinel.dashboard_snapshot()
            waf = snapshot["waf"]
            self.assertEqual(waf["requests_blocked"], 4)
            self.assertEqual(waf["rule_matches"], 4)
            self.assertEqual(waf["deny_list_count"], 0)
            by_rule = {item["rule_id"]: item["count"] for item in waf["top_rules"]}
            self.assertEqual(by_rule, {"942100": 1, "920350": 3})
            sentinel.firewall.close()
            asyncio.run(sentinel.threat_intel.close())


if __name__ == "__main__":
    unittest.main()
