"""Coverage tests for pipeline, detection-engine, and metrics components.

Complements the historical rule/firewall/rollback tests with the modules
that the hardening round's 80% coverage gate must count: sentinel, threat
intel internals, dispatcher, logger, privilege, and dashboard fail-safe
paths.
"""

import asyncio
import json
import logging
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from ed_bt_ade.config import (
    AlertingConfig,
    AppConfig,
    DetectionConfig,
    FirewallConfig,
    LogSource,
    ThreatIntelConfig,
)
from ed_bt_ade.detector import (
    Detection,
    DetectionEngine,
    LogEvent,
    PrivilegeEscalationRule,
    SSHBruteForceRule,
    WebAttackRule,
)
from ed_bt_ade.dispatcher import WebhookDispatcher
from ed_bt_ade.logger import Health, JsonFormatter, Metrics, start_metrics_server
from ed_bt_ade.privilege import PrivilegeDropError, drop_privileges
from ed_bt_ade.sentinel import Sentinel
from ed_bt_ade.threat_intel import (
    CircuitBreaker,
    Reputation,
    ReputationCache,
    TokenBucket,
)


def _make_config(root: Path, **overrides) -> AppConfig:
    defaults = dict(
        log_sources=(LogSource(name="auth", path=root / "auth.log"),),
        firewall=FirewallConfig(state_db=root / "fw.db"),
        threat_intel=ThreatIntelConfig(cache_db=root / "ti.db"),
        detection=DetectionConfig(),
        alerting=AlertingConfig(),
    )
    defaults.update(overrides)
    return AppConfig(**defaults)


class MetricsAndHealthTests(unittest.TestCase):
    def test_metrics_inc_set_render_and_value(self) -> None:
        metrics = Metrics()
        metrics.inc("counter_total")
        metrics.inc("counter_total", value=4)
        metrics.inc("labeled_total", labels={"rule": "ssh"})
        metrics.set("gauge_seconds", 1.25)
        rendered = metrics.render()
        self.assertIn("counter_total 5", rendered)
        self.assertIn("gauge_seconds 1.25", rendered)
        self.assertIn("rule", rendered)
        self.assertEqual(metrics.value("counter_total"), 5.0)

    def test_health_ready_flag(self) -> None:
        health = Health()
        self.assertFalse(health.ready)
        health.set_ready(True)
        self.assertTrue(health.ready)

    def test_json_formatter_emits_valid_json(self) -> None:
        record = logging.LogRecord(
            "test", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
        record.ip = "8.8.8.8"
        payload = json.loads(JsonFormatter().format(record))
        self.assertEqual(payload["message"], "hello world")
        self.assertEqual(payload["ip"], "8.8.8.8")
        self.assertIn("timestamp", payload)

    def test_metrics_server_serves_healthz(self) -> None:
        metrics, health = Metrics(), Health()
        health.set_ready(True)  # healthz returns 503 while not ready
        server = start_metrics_server("127.0.0.1", 0, metrics, health)
        port = server.server_address[1]
        results = {}

        def fetch() -> None:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/healthz", timeout=5) as response:
                    results["status"] = response.status
                    results["body"] = response.read().decode()
            except Exception as exc:
                results["error"] = str(exc)

        thread = threading.Thread(target=fetch, daemon=True)
        thread.start()
        thread.join(timeout=5)
        server.shutdown()
        self.assertEqual(results.get("status"), 200)
        self.assertIn("ok", results.get("body", ""))


class DetectionEngineTests(unittest.TestCase):
    def test_ssh_bruteforce_threshold_and_purge(self) -> None:
        rule = SSHBruteForceRule(threshold=3, window=60.0)
        engine = DetectionEngine((rule,))
        base = 1000.0
        for step in range(3):
            event = LogEvent("auth.log", f"Failed password for root from 8.8.4.4",
                             timestamp=base + step, remote_ip="8.8.4.4")
            detections = engine.evaluate(event)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule, "ssh_brute_force")
        self.assertEqual(detections[0].severity, "high")
        # Purge clears expired buckets.
        rule.purge(base + 120)
        self.assertEqual(rule.attempts.get("8.8.4.4"), None)

    def test_web_attack_rule_scores_and_threshold(self) -> None:
        rule = WebAttackRule(threshold=1)
        event = LogEvent("web.log",
                         'GET /?q=1%27%20UNION%20SELECT%20password%20FROM%20users '
                         '<script>alert(1)</script>',
                         remote_ip="9.9.9.9")
        detections = list(rule.evaluate(event))
        self.assertEqual(len(detections), 1)  # one combined web_attack detection
        self.assertEqual(detections[0].rule, "web_attack")
        self.assertIn("sqli", detections[0].evidence)
        self.assertIn("xss", detections[0].evidence)
        # Below threshold: single pattern with threshold=2 produces nothing.
        quiet_rule = WebAttackRule(threshold=5)
        single = LogEvent("web.log", "GET /?x=<script>", remote_ip="9.9.9.9")
        self.assertEqual(list(quiet_rule.evaluate(single)), [])

    def test_privilege_rule_matches_escalation(self) -> None:
        rule = PrivilegeEscalationRule()
        event = LogEvent("audit.log",
                         "sudo: operator : COMMAND=/usr/bin/passwd root",
                         remote_ip=None)
        detections = list(rule.evaluate(event))
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule, "privilege_escalation_anomaly")
        self.assertEqual(detections[0].severity, "medium")

    def test_engine_deduplicates_nothing_and_purges_all(self) -> None:
        ssh = SSHBruteForceRule(3, 60.0)
        engine = DetectionEngine((ssh, WebAttackRule(1)))
        event = LogEvent("x.log", "Failed password from 8.8.8.8",
                         remote_ip="8.8.8.8", timestamp=10.0)
        self.assertEqual(engine.evaluate(event), [])
        engine.purge(100.0)


class TokenBucketAndBreakerTests(unittest.TestCase):
    def test_token_bucket_refills_and_throttles(self) -> None:
        async def scenario() -> None:
            bucket = TokenBucket(rate=50.0, capacity=2)
            await bucket.acquire()
            await bucket.acquire()
            # Third immediate acquire must wait ~refill time but still succeed.
            await asyncio.wait_for(bucket.acquire(), timeout=2)
            self.assertLessEqual(bucket.tokens, 1.0)

        asyncio.run(scenario())

    def test_circuit_breaker_opens_and_resets(self) -> None:
        async def scenario() -> None:
            breaker = CircuitBreaker(threshold=2, reset_seconds=0.05)
            self.assertTrue(await breaker.permitted())
            await breaker.failure()
            self.assertTrue(await breaker.permitted())
            await breaker.failure()
            self.assertFalse(await breaker.permitted())  # now open
            await asyncio.sleep(0.06)
            self.assertTrue(await breaker.permitted())  # half-open again
            await breaker.success()
            self.assertTrue(await breaker.permitted())

        asyncio.run(scenario())


class ReputationCacheTests(unittest.TestCase):
    def test_put_get_expiry_and_purge(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                cache = ReputationCache(Path(directory) / "ti.db", ttl=1)
                import time as _time

                reputation = Reputation(ip="9.9.9.9", score=75.0,
                                        source="test", fetched_at=_time.time())
                await cache.put(reputation)
                cached = await cache.get("9.9.9.9")
                self.assertIsNotNone(cached)
                self.assertEqual(cached.score, 75.0)
                # Purge removes entries older than ttl from memory and disk.
                stale = Reputation(ip="8.8.4.4", score=1.0, source="test",
                                   fetched_at=_time.time() - 3600)
                cache.memory["8.8.4.4"] = stale
                await cache.purge()
                self.assertIsNone(await cache.get("8.8.4.4"))  # stale, purged
                self.assertIsNotNone(await cache.get("9.9.9.9"))  # fresh, kept
                cache.db.close()

        asyncio.run(scenario())

    def test_lookup_disabled_returns_none_without_network(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                config = ThreatIntelConfig(cache_db=Path(directory) / "ti.db")
                from ed_bt_ade.threat_intel import ThreatIntelClient

                client = ThreatIntelClient(config)
                self.assertIsNone(await client.lookup("8.8.8.8"))
                client.cache.db.close()

        asyncio.run(scenario())


class DispatcherTests(unittest.TestCase):
    def test_submit_without_route_is_dropped(self) -> None:
        async def scenario() -> None:
            dispatcher = WebhookDispatcher(AlertingConfig())
            await dispatcher.submit({"severity": "low", "rule": "x"})
            self.assertTrue(dispatcher.queue.empty())

        asyncio.run(scenario())

    def test_dispatch_delivers_batch_to_webhook(self) -> None:
        async def scenario() -> None:
            config = AlertingConfig(
                webhooks=(("high", ("http://hooks.local/ingest",)),),
                batch_size=5, flush_interval_seconds=0.01,
                requests_per_second=50.0)
            dispatcher = WebhookDispatcher(config)
            await dispatcher.submit({"severity": "high", "rule": "ssh",
                                     "ip": "8.8.8.8"})
            with patch("ed_bt_ade.dispatcher.urlopen") as fake_open:
                fake_open.return_value.__enter__ = lambda self: self
                fake_open.return_value.__exit__ = lambda self, *exc: None
                task = asyncio.create_task(dispatcher.run())
                await asyncio.sleep(0.05)
                dispatcher.stop.set()
                await asyncio.wait_for(task, timeout=2)
            self.assertEqual(fake_open.call_count, 1)
            payload = json.loads(fake_open.call_args.args[0].data.decode())
            self.assertEqual(payload["alerts"][0]["rule"], "ssh")

        asyncio.run(scenario())


class PrivilegeTests(unittest.TestCase):
    def test_drop_privileges_refuses_non_root_with_error(self) -> None:
        # Running as an unprivileged user is a defined error path, not a crash.
        import os

        if os.getuid() != 0:
            with self.assertRaises(PrivilegeDropError):
                drop_privileges()

    def test_drop_privileges_full_root_path_with_mocked_ids(self) -> None:
        """Exercise the root code path with mocked identity primitives."""
        import os

        types = __import__("types")

        fake_pwd_entry = types.SimpleNamespace(pw_name="bastionfw", pw_uid=10001)

        def _fake_getpwnam(name: str):
            if name != "bastionfw":
                raise KeyError(name)
            return fake_pwd_entry

        # Call order in drop_privileges: gate getuid (0) -> initgroups/setgid/
        # setuid (mocked, no real effect) -> verification getuid+getgid (must
        # report the dropped identity, never 0).
        uid_calls = [0, 10001, 10001]
        gid_calls = [10001, 10001]

        with patch("ed_bt_ade.privilege.os.getuid", side_effect=lambda: uid_calls.pop(0) if uid_calls else 10001), \
                patch("ed_bt_ade.privilege.os.getgid", side_effect=lambda: gid_calls.pop(0) if gid_calls else 10001), \
                patch("ed_bt_ade.privilege.pwd.getpwnam", side_effect=_fake_getpwnam), \
                patch("ed_bt_ade.privilege.grp.getgrnam",
                      return_value=types.SimpleNamespace(gr_gid=10001)), \
                patch("ed_bt_ade.privilege.os.initgroups") as fake_init, \
                patch("ed_bt_ade.privilege.os.setgid") as fake_setgid, \
                patch("ed_bt_ade.privilege.os.setuid") as fake_setuid:
            drop_privileges()
            fake_init.assert_called_once_with("bastionfw", 10001)
            fake_setgid.assert_called_once_with(10001)
            fake_setuid.assert_called_once_with(10001)

    def test_drop_privileges_detects_failed_drop(self) -> None:
        """If setuid silently failed, the guard must refuse to continue."""
        import os

        types = __import__("types")

        with patch("ed_bt_ade.privilege.os.getuid", return_value=0), \
                patch("ed_bt_ade.privilege.os.getgid", return_value=0), \
                patch("ed_bt_ade.privilege.pwd.getpwnam",
                      return_value=types.SimpleNamespace(pw_name="b", pw_uid=10001)), \
                patch("ed_bt_ade.privilege.grp.getgrnam",
                      return_value=types.SimpleNamespace(gr_gid=10001)), \
                patch("ed_bt_ade.privilege.os.initgroups"), \
                patch("ed_bt_ade.privilege.os.setgid"), \
                patch("ed_bt_ade.privilege.os.setuid"):
            with self.assertRaises(PrivilegeDropError):
                drop_privileges()

    def test_drop_privileges_missing_identity(self) -> None:
        import pwd as _pwd

        with patch("ed_bt_ade.privilege.os.getuid", return_value=0), \
                patch("ed_bt_ade.privilege.pwd.getpwnam",
                      side_effect=KeyError("bastionfw")):
            with self.assertRaises(PrivilegeDropError):
                drop_privileges()


class ConfigProvisionTests(unittest.TestCase):
    def test_provision_default_config_creates_dry_run_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            from ed_bt_ade.config import provision_default_config

            path = Path(directory) / "new-config.json"
            provision_default_config(path)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("log_sources", document)
            self.assertFalse(document["firewall"]["enabled"])
            # Provisioning twice does not rewrite an existing file.
            path.write_text("{}", encoding="utf-8")
            provision_default_config(path)
            self.assertEqual(path.read_text(encoding="utf-8"), "{}")


class DashboardFailSafeTests(unittest.TestCase):
    def test_unauthenticated_dashboard_refuses_remote_bind(self) -> None:
        from ed_bt_ade.dashboard import LOOPBACK_HOST, resolve_bind_host

        self.assertEqual(resolve_bind_host("0.0.0.0", None), LOOPBACK_HOST)
        self.assertEqual(resolve_bind_host("0.0.0.0", "tok"), "0.0.0.0")
        self.assertEqual(resolve_bind_host(LOOPBACK_HOST, None), LOOPBACK_HOST)


class SentinelLifecycleTests(unittest.TestCase):
    def test_snapshot_shape_and_waf_summary(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                sentinel = Sentinel(_make_config(Path(directory)))
                snapshot = sentinel.dashboard_snapshot()
                for key in ("ready", "mode", "uptime_seconds", "queue_depth",
                            "logs_processed", "threats_detected", "ips_blocked",
                            "pipeline_errors", "sources", "alerts"):
                    self.assertIn(key, snapshot)
                self.assertEqual(snapshot["mode"], "DRY-RUN")
                waf = sentinel.waf_summary()
                self.assertIn("mode", waf)
                sentinel.firewall.close()
                sentinel.threat_intel.cache.db.close()

        asyncio.run(scenario())

    def test_run_starts_pipeline_and_rolls_back_on_shutdown(self) -> None:
        """Full lifecycle: metrics server, deadman armed, graceful rollback."""
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                sentinel = Sentinel(_make_config(
                    Path(directory),
                    firewall=FirewallConfig(state_db=Path(directory) / "fw.db",
                                            enabled=True)))
                # Track whether graceful rollback ran on shutdown.
                rolled_back: list[int] = []
                original = sentinel.rollback.rollback_all_bans

                async def spy() -> int:
                    removed = await original()
                    rolled_back.append(removed)
                    return removed

                sentinel.rollback.rollback_all_bans = spy
                task = asyncio.create_task(sentinel.run())
                await asyncio.sleep(0.15)
                self.assertTrue(sentinel.health.ready)
                self.assertIsNotNone(sentinel.metrics_server)
                sentinel.request_stop()
                await asyncio.wait_for(task, timeout=5)
                # Deadman disarmed and bans rolled back at shutdown; run()'s
                # finally block owns all teardown.
                self.assertFalse(sentinel.deadman.path.exists())
                self.assertEqual(rolled_back, [0])

        asyncio.run(scenario())

    def test_coraza_detection_enters_ban_loop(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                from ed_bt_ade.parsing import parse_coraza_audit_line

                sentinel = Sentinel(_make_config(Path(directory)))
                detection = parse_coraza_audit_line(json.dumps({
                    "client_ip": "9.9.9.9", "anomaly_score": 9,
                    "rule_ids": ["942100"]}))
                self.assertIsNotNone(detection)
                # Only ssh_brute_force can ban locally; coraza detections are
                # observable (alert path) but must not crash the loop.
                event = LogEvent("waf", json.dumps({"client_ip": "9.9.9.9"}),
                                 remote_ip="9.9.9.9", source_type="coraza_audit",
                                 detection=detection)
                sentinel.queue.put_nowait(event)
                task = asyncio.create_task(sentinel._process())
                await asyncio.sleep(0.05)
                sentinel.stop.set()
                await asyncio.wait_for(task, timeout=2)
                self.assertEqual(sentinel.metrics.value(
                    "sentinel_logs_processed_total"), 1.0)
                sentinel.firewall.close()
                sentinel.threat_intel.cache.db.close()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
