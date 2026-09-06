"""Application lifecycle and asynchronous orchestration."""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
import logging
import signal
import threading
import time
from pathlib import Path

from .config import AppConfig, load_config
from .detector import (
    CorazaAuditRule,
    DetectionEngine,
    LogEvent,
    PrivilegeEscalationRule,
    SSHBruteForceRule,
    WebAttackRule,
)
from .dispatcher import WebhookDispatcher
from .firewall import FirewallOrchestrator
from .logger import Health, Metrics, configure_logging, start_metrics_server
from .rollback import WafDeadmanSwitch
from .tailer import AsyncLogTailer
from .threat_intel import ThreatIntelClient

LOGGER = logging.getLogger("ed_bt_ade")


class Sentinel:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=config.queue_size)
        self.stop = asyncio.Event()
        self.metrics = Metrics()
        self.health = Health()
        self.source_types: dict[str, str] = {}
        for source in config.log_sources:
            self.source_types[source.name] = source.source_type
        generic_rules = (
            SSHBruteForceRule(config.detection.ssh_failures,
                              config.detection.ssh_window_seconds),
            WebAttackRule(config.detection.web_score_threshold),
            PrivilegeEscalationRule(),
        )
        self.engines: dict[str, DetectionEngine] = {
            "plain": DetectionEngine(generic_rules),
            "coraza_audit": DetectionEngine((CorazaAuditRule(),)),
        }
        self.firewall = FirewallOrchestrator(config.firewall)
        self.threat_intel = ThreatIntelClient(config.threat_intel)
        self.dispatcher = WebhookDispatcher(config.alerting)
        self.deadman = (WafDeadmanSwitch(config.waf, self.metrics,
                                         notify=self._push_alert)
                        if config.waf.enabled else None)
        self._loop: asyncio.AbstractEventLoop | None = None
        self.metrics_server = None
        self.started_at = time.time()
        self.recent_alerts: deque[dict[str, object]] = deque(maxlen=100)
        self._alerts_lock = threading.Lock()

    def _push_alert(self, entry: dict[str, object]) -> None:
        """Thread-safe append to the dashboard alert ring buffer."""
        with self._alerts_lock:
            self.recent_alerts.appendleft(entry)

    def _engine_for(self, event: LogEvent) -> DetectionEngine:
        return self.engines.get(self.source_types.get(event.source, "plain"),
                                self.engines["plain"])

    async def _process(self) -> None:
        while not self.stop.is_set() or not self.queue.empty():
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                started = time.perf_counter()
                self.metrics.inc("sentinel_logs_processed_total")
                detections = self._engine_for(event).evaluate(event)
                for detection in detections:
                    self.metrics.inc("sentinel_threats_detected_total",
                                     labels={"rule": detection.rule})
                    LOGGER.warning("threat detected", extra={
                        "event": "threat_detected", "source": detection.source,
                        "ip": detection.ip or "", "rule": detection.rule,
                    })
                    self._push_alert({
                        "timestamp": time.time(),
                        "rule": detection.rule,
                        "severity": detection.severity,
                        "source": detection.source,
                        "ip": detection.ip,
                        "evidence": detection.evidence,
                    })
                    await self.dispatcher.submit({
                        "rule": detection.rule,
                        "severity": detection.severity,
                        "source": detection.source,
                        "ip": detection.ip,
                        "evidence": detection.evidence,
                    })
                    if detection.rule == "coraza_waf":
                        for rule_id in detection.rule_ids:
                            self.metrics.inc("waf_rule_matches_total",
                                             labels={"rule_id": rule_id})
                        if detection.interrupted:
                            self.metrics.inc("waf_requests_blocked_total")
                    if detection.ip and detection.severity in {"high", "critical"}:
                        should_block = False
                        if detection.rule == "ssh_brute_force":
                            reputation = await self.threat_intel.lookup(detection.ip)
                            # Only the strongest local signal can trigger a ban when
                            # TI is unavailable; ambiguous detections stay observable.
                            should_block = reputation is None or reputation.score >= 50
                        elif detection.rule == "coraza_waf":
                            # CRS already scored the transaction; block when the
                            # aggregate anomaly score clears the configured floor.
                            should_block = (detection.score >=
                                            self.config.detection.coraza_block_score)
                        if should_block and await self.firewall.block(detection.ip):
                            self.metrics.inc("sentinel_ips_blocked_total")
                self.metrics.set("sentinel_pipeline_latency_seconds",
                                 time.perf_counter() - started)
            except Exception:
                # A malformed event or an unavailable enforcement backend
                # must not kill the shared processor task.
                self.metrics.inc("sentinel_pipeline_errors_total")
                LOGGER.exception("pipeline event failed",
                                 extra={"event": "pipeline_error"})
            finally:
                self.queue.task_done()

    async def _gc(self) -> None:
        while not self.stop.is_set():
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                self.detector_purge()
                await self.threat_intel.cache.purge()

    def detector_purge(self) -> None:
        """Purge per-IP state in every engine and the legacy ruleset API."""
        self.engines["plain"].purge()

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self.metrics_server = start_metrics_server(
            self.config.metrics_host, self.config.metrics_port, self.metrics, self.health)
        tailers = [AsyncLogTailer(source, self.queue, self.config.trusted_proxies)
               for source in self.config.log_sources]
        tasks = [asyncio.create_task(tailer.run(), name=f"tailer:{tailer.source.name}")
                 for tailer in tailers]
        tasks.extend((asyncio.create_task(self._process(), name="processor"),
                      asyncio.create_task(self.dispatcher.run(), name="alert-dispatcher"),
                      asyncio.create_task(self._gc(), name="garbage-collector"),
                      asyncio.create_task(self.firewall.cleanup_loop(self.stop),
                                          name="firewall-cleaner")))
        if self.deadman is not None:
            tasks.append(asyncio.create_task(self.deadman.run(self.stop),
                                             name="waf-deadman"))
        self.health.set_ready(True)
        LOGGER.info("sentinel started", extra={"event": "startup"})
        try:
            await self.stop.wait()
        finally:
            self.health.set_ready(False)
            for tailer in tailers:
                tailer.close()
            self.dispatcher.close()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.threat_intel.close()
            self.firewall.close()
            if self.metrics_server:
                self.metrics_server.shutdown()

    def request_stop(self) -> None:
        self.stop.set()

    def dashboard_snapshot(self) -> dict[str, object]:
        """Return a thread-safe, JSON-serializable dashboard snapshot."""
        with self._alerts_lock:
            alerts = list(self.recent_alerts)
        firewall_enforcing = self.config.firewall.enabled
        deadman_tripped = bool(self.deadman is not None and self.deadman.tripped)
        waf_engine_mode = (self.deadman.engine_mode
                           if self.deadman is not None else self.config.waf.mode)
        rule_series = self.metrics.series("waf_rule_matches_total")
        top_rules = sorted(rule_series, key=lambda item: item[1], reverse=True)[:10]
        return {
            "project": "BastionFW",
            "developer": "Cagan Utku Saymaz",
            "ready": self.health.ready,
            "mode": "ENFORCING" if firewall_enforcing else "DRY-RUN",
            "uptime_seconds": max(0, int(time.time() - self.started_at)),
            "queue_depth": self.queue.qsize(),
            "logs_processed": self.metrics.value("sentinel_logs_processed_total"),
            "threats_detected": self.metrics.value("sentinel_threats_detected_total"),
            "ips_blocked": self.metrics.value("sentinel_ips_blocked_total"),
            "pipeline_errors": self.metrics.value("sentinel_pipeline_errors_total"),
            "pipeline_latency_seconds": self.metrics.value(
                "sentinel_pipeline_latency_seconds"),
            "protected_sources": len(self.config.log_sources),
            "blocked_addresses": self.firewall.active_addresses(),
            "sources": [
                {"name": source.name, "path": str(source.path),
                 "source_type": source.source_type}
                for source in self.config.log_sources
            ],
            "services": [
                {
                    "name": "sentinel",
                    "state": "running" if self.health.ready else "stopped",
                    "detail": f"{len(self.config.log_sources)} log sources protected",
                },
                {
                    "name": "firewall",
                    "state": "running" if firewall_enforcing else "stopped",
                    "detail": ("Live L3/L4 + Coraza deny-list enforcement"
                               if firewall_enforcing else "Dry-run safety mode"),
                },
                {
                    "name": "threat-intel",
                    "state": ("running" if self.config.threat_intel.enabled
                              else "stopped"),
                    "detail": ("AbuseIPDB enrichment"
                               if self.config.threat_intel.enabled
                               else "Provider disabled"),
                },
            ],
            "threat_intel": {
                "enabled": self.config.threat_intel.enabled,
                "provider": ("AbuseIPDB" if self.config.threat_intel.enabled
                             and self.config.threat_intel.abuseipdb_url else ""),
                "status": ("healthy" if self.config.threat_intel.enabled
                           else "disabled"),
                "started_at": self.started_at,
            },
            "waf": {
                "enabled": self.config.waf.enabled,
                "mode": self.config.waf.mode,
                "engine_mode": waf_engine_mode,
                "deadman_tripped": deadman_tripped,
                "requests_blocked": self.metrics.value("waf_requests_blocked_total"),
                "rule_matches": self.metrics.value("waf_rule_matches_total"),
                "top_rules": [
                    {"rule_id": labels.get("rule_id", ""), "count": int(value)}
                    for labels, value in top_rules
                ],
            },
            "alerts": alerts,
        }

    def run_coro(self, coroutine: object) -> "asyncio.Future[object]":
        """Schedule a coroutine on the event loop from another thread."""
        if self._loop is None:
            raise RuntimeError("sentinel event loop is not running")
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop)  # type: ignore[arg-type]


def _install_signals(sentinel: Sentinel) -> None:
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, sentinel.request_stop)
        except NotImplementedError:
            signal.signal(signum, lambda *_args: sentinel.request_stop())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.example.json")
    parser.add_argument(
        "--purge-all-bans",
        action="store_true",
        help="instantly clear every active and expired ban from all enforcement "
             "layers (L3/L4 and WAF deny-list), then exit",
    )
    args = parser.parse_args()
    config = load_config(Path(args.config))
    if args.purge_all_bans:
        configure_logging(config.log_level, config.log_file)
        firewall = FirewallOrchestrator(config.firewall)
        try:
            purged = asyncio.run(firewall.purge_all())
        finally:
            firewall.close()
        LOGGER.warning("purged %d ban(s) from all enforcement layers",
                       purged, extra={"event": "bans_purged", "count": purged})
        print(f"purged {purged} ban(s)")
        return
    configure_logging(config.log_level, config.log_file)
    sentinel = Sentinel(config)

    async def runner() -> None:
        _install_signals(sentinel)
        await sentinel.run()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
