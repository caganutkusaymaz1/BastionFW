"""Application lifecycle and asynchronous orchestration."""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
import logging
import os
import signal
import threading
import time
from pathlib import Path

from .config import AppConfig, load_config
from .detector import DetectionEngine, LogEvent, PrivilegeEscalationRule, SSHBruteForceRule, WebAttackRule
from .dispatcher import WebhookDispatcher
from .firewall import FirewallOrchestrator
from .logger import Health, Metrics, configure_logging, start_metrics_server
from .privilege import PrivilegeDropError, drop_privileges
from .rollback import DeadmanSwitch, RollbackCoordinator, resolve_rollback_seconds
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
        self.detector = DetectionEngine((
            SSHBruteForceRule(config.detection.ssh_failures,
                              config.detection.ssh_window_seconds),
            WebAttackRule(config.detection.web_score_threshold),
            PrivilegeEscalationRule(),
        ))
        self.firewall = FirewallOrchestrator(config.firewall)
        self.threat_intel = ThreatIntelClient(config.threat_intel)
        self.dispatcher = WebhookDispatcher(config.alerting)
        # Honor ED_BT_ADE_ROLLBACK_SECONDS so the lock-out protection window
        # is operator-tunable; unset or invalid values fall back to 120s.
        self.deadman = DeadmanSwitch(config.firewall.state_db.parent,
                                     resolve_rollback_seconds())
        self.rollback = RollbackCoordinator(self.firewall)
        self.metrics_server = None
        self.started_at = time.time()
        self.recent_alerts: deque[dict[str, object]] = deque(maxlen=100)
        self._alerts_lock = threading.Lock()

    async def _process(self) -> None:
        while not self.stop.is_set() or not self.queue.empty():
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                started = time.perf_counter()
                self.metrics.inc("sentinel_logs_processed_total")
                if event.source_type == "coraza_audit" and event.detection is not None:
                    # Pre-parsed Coraza WAF audit event: bypass text detection
                    # rules and enter the normal ban loop directly.
                    detections: tuple = (event.detection,)
                else:
                    detections = self.detector.evaluate(event)
                for detection in detections:
                    self.metrics.inc("sentinel_threats_detected_total",
                                     labels={"rule": detection.rule})
                    LOGGER.warning("threat detected", extra={
                        "event": "threat_detected", "source": detection.source,
                        "ip": detection.ip or "", "rule": detection.rule,
                    })
                    with self._alerts_lock:
                        self.recent_alerts.appendleft({
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
                    if detection.ip and detection.severity == "high":
                        reputation = await self.threat_intel.lookup(detection.ip)
                        # Only the strongest local signal can trigger a ban when
                        # TI is unavailable; ambiguous detections stay observable.
                        should_block = detection.rule == "ssh_brute_force" and (
                            reputation is None or reputation.score >= 50)
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
                self.detector.purge()
                await self.threat_intel.cache.purge()

    async def purge_all_bans(self) -> int:
        """Operator panic switch: drop every ban and the deadman liveness file.

        Clears the firewall table immediately so the next ``sentinel`` start is
        clean. Returns the number of removed bans.
        """
        removed = await self.firewall.purge_all()
        self.deadman.request_stop()
        return removed

    async def run(self) -> None:
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
        # Arm the deadman switch only while the pipeline is actually running:
        # the external watchdog rolls back bans if this loop ever stops
        # renewing while bans are still active.
        self.deadman.start()
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
            # Disarm the watchdog, then roll back every engine-owned ban so a
            # graceful stop never leaves the host with active DROP rules.
            await self.deadman.close()
            await self.rollback.rollback_all_bans()
            self.firewall.close()
            if self.metrics_server:
                self.metrics_server.shutdown()

    def waf_summary(self) -> dict[str, object]:
        """WAF enforcement aggregates (populated by the Coraza integration)."""
        return {"denied_requests_total": 0, "top_rule_ids": [], "mode": "detect"}

    def request_stop(self) -> None:
        self.stop.set()

    def dashboard_snapshot(self) -> dict[str, object]:
        """Return a thread-safe, JSON-serializable dashboard snapshot."""
        with self._alerts_lock:
            alerts = list(self.recent_alerts)
        return {
            "project": "BastionFW",
            "developer": "Cagan Utku Saymaz",
            "ready": self.health.ready,
            "mode": "ENFORCING" if self.config.firewall.enabled else "DRY-RUN",
            "uptime_seconds": max(0, int(time.time() - self.started_at)),
            "queue_depth": self.queue.qsize(),
            "logs_processed": self.metrics.value("sentinel_logs_processed_total"),
            "threats_detected": self.metrics.value("sentinel_threats_detected_total"),
            "ips_blocked": self.metrics.value("sentinel_ips_blocked_total"),
            "pipeline_errors": self.metrics.value("sentinel_pipeline_errors_total"),
            "pipeline_latency_seconds": self.metrics.value(
                "sentinel_pipeline_latency_seconds"),
            "sources": [
                {"name": source.name, "path": str(source.path)}
                for source in self.config.log_sources
            ],
            "alerts": alerts,
        }


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
    parser.add_argument("--no-privilege-drop", action="store_true",
                        help="skip privilege drop (development hosts only)")
    parser.add_argument("--purge-all-bans", action="store_true",
                        help="remove all active and expired bans, then exit")
    args = parser.parse_args()
    config = load_config(Path(args.config))
    configure_logging(config.log_level, config.log_file)
    # Drop root as early as possible: config and log files are open, firewall
    # nftables/iptables work happens later through CAP_NET_ADMIN (systemd) or
    # a dedicated setcap wrapper, not through full root.
    if os.getuid() == 0 and not args.no_privilege_drop:
        try:
            drop_privileges()
        except PrivilegeDropError as exc:
            parser.error(f"refusing to run as root without privilege separation: {exc}")
    sentinel = Sentinel(config)
    if args.purge_all_bans:
        removed = asyncio.run(sentinel.purge_all_bans())
        LOGGER.info("purged %d ban(s)", removed, extra={"event": "purge_all_bans"})
        return
    async def runner() -> None:
        _install_signals(sentinel)
        await sentinel.run()
    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
