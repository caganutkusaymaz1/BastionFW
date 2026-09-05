"""Configuration loading and strict validation.

The loader deliberately uses a small, dependency-free schema. YAML is
supported when PyYAML is installed; JSON is always supported.
"""

from __future__ import annotations

import json
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class LogSource:
    name: str
    path: Path
    encoding: str = "utf-8"
    poll_interval: float = 0.25


@dataclass(frozen=True, slots=True)
class FirewallConfig:
    enabled: bool = False
    backend: str = "auto"
    state_db: Path = Path("state/firewall.sqlite3")
    ban_seconds: int = 86_400
    whitelist: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ThreatIntelConfig:
    enabled: bool = False
    cache_db: Path = Path("state/threat-intel.sqlite3")
    cache_ttl_seconds: int = 3_600
    requests_per_second: float = 2.0
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 60.0
    abuseipdb_url: str = ""


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    ssh_failures: int = 8
    ssh_window_seconds: float = 60.0
    web_score_threshold: int = 2
    session_ttl_seconds: int = 3_600


@dataclass(frozen=True, slots=True)
class AlertingConfig:
    """Severity-to-webhook routing configuration."""

    webhooks: tuple[tuple[str, tuple[str, ...]], ...] = ()
    batch_size: int = 20
    flush_interval_seconds: float = 1.0
    requests_per_second: float = 5.0


@dataclass(frozen=True, slots=True)
class AppConfig:
    log_sources: tuple[LogSource, ...]
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    queue_size: int = 50_000
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9109
    log_level: str = "INFO"


def _as_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise ConfigError(f"{key} must be a boolean")


def _positive(value: Any, key: str, integer: bool = False) -> int | float:
    try:
        result = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be numeric") from exc
    if result <= 0:
        raise ConfigError(f"{key} must be greater than zero")
    return result


def _mapping(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be an object")
    return value


def _validated_url(value: Any, key: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ConfigError(f"{key} must be an HTTP(S) URL")
    if not value and allow_empty:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"{key} must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ConfigError(f"{key} must not contain embedded credentials")
    return value


def _load_document(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON: {exc}") from exc
    else:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ConfigError("YAML requires PyYAML; use JSON or install PyYAML") from exc
        value = yaml.safe_load(raw)
    return _mapping(value, "root")


def provision_default_config(path: str | Path) -> Path:
    """Create a conservative dry-run config exactly once when missing."""
    destination = Path(path)
    if destination.exists():
        return destination
    document = {
        "log_sources": [
            {"name": "auth", "path": "/var/log/auth.log", "poll_interval": 0.25},
            {"name": "nginx", "path": "/var/log/nginx/access.log", "poll_interval": 0.25},
        ],
        "queue_size": 50000,
        "metrics_host": "127.0.0.1",
        "metrics_port": 9109,
        "log_level": "INFO",
        "firewall": {
            "enabled": False,
            "backend": "dry-run",
            "state_db": "state/firewall.sqlite3",
            "ban_seconds": 86400,
            "whitelist": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        },
        "threat_intel": {
            "enabled": False,
            "cache_db": "state/threat-intel.sqlite3",
            "cache_ttl_seconds": 3600,
            "requests_per_second": 2,
            "circuit_failure_threshold": 5,
            "circuit_reset_seconds": 60,
            "abuseipdb_url": "",
        },
        "detection": {
            "ssh_failures": 8,
            "ssh_window_seconds": 60,
            "web_score_threshold": 1,
            "session_ttl_seconds": 3600,
        },
        "alerting": {
            "webhooks": {"high": [], "critical": []},
            "batch_size": 20,
            "flush_interval_seconds": 1,
            "requests_per_second": 5,
        },
    }
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
    except FileExistsError:
        pass
    except OSError as exc:
        raise ConfigError(f"cannot provision config {destination}: {exc}") from exc
    return destination


def load_config(path: str | Path, environ: dict[str, str] | None = None) -> AppConfig:
    """Load and validate a JSON/YAML configuration file.

    Environment overrides are intentionally narrow and predictable:
    ``ED_BT_ADE_DRY_RUN`` maps to ``firewall.enabled`` (false means dry-run),
    and ``ED_BT_ADE_LOG_LEVEL`` maps to the logging level.
    """
    source = _load_document(provision_default_config(path))
    raw_sources = source.get("log_sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigError("log_sources must be a non-empty list")

    sources: list[LogSource] = []
    for index, item in enumerate(raw_sources):
        item = _mapping(item, f"log_sources[{index}]")
        name = item.get("name")
        log_path = item.get("path")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"log_sources[{index}].name is required")
        if not isinstance(log_path, str) or not log_path:
            raise ConfigError(f"log_sources[{index}].path is required")
        poll = _positive(item.get("poll_interval", 0.25), "poll_interval")
        sources.append(
            LogSource(name=name, path=Path(log_path),
                      encoding=str(item.get("encoding", "utf-8")),
                      poll_interval=poll)
        )

    firewall_raw = _mapping(source.get("firewall", {}), "firewall")
    backend = str(firewall_raw.get("backend", "auto")).lower()
    if backend not in {"auto", "dry-run", "nftables", "iptables", "ufw", "firewalld"}:
        raise ConfigError("firewall.backend is invalid")
    whitelist = firewall_raw.get("whitelist", [])
    if not isinstance(whitelist, list) or not all(isinstance(x, str) for x in whitelist):
        raise ConfigError("firewall.whitelist must be a list of strings")
    for item in whitelist:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(f"invalid firewall whitelist CIDR: {item}") from exc
        if network.version != 4:
            raise ConfigError("firewall whitelist supports IPv4 CIDRs only")
    firewall = FirewallConfig(
        enabled=_as_bool(firewall_raw.get("enabled", False), "firewall.enabled"),
        backend=backend,
        state_db=Path(str(firewall_raw.get("state_db", "state/firewall.sqlite3"))),
        ban_seconds=_positive(firewall_raw.get("ban_seconds", 86_400),
                               "firewall.ban_seconds", integer=True),
        whitelist=tuple(whitelist),
    )

    ti_raw = _mapping(source.get("threat_intel", {}), "threat_intel")
    ti = ThreatIntelConfig(
        enabled=_as_bool(ti_raw.get("enabled", False), "threat_intel.enabled"),
        cache_db=Path(str(ti_raw.get("cache_db", "state/threat-intel.sqlite3"))),
        cache_ttl_seconds=_positive(ti_raw.get("cache_ttl_seconds", 3_600),
                                     "threat_intel.cache_ttl_seconds", integer=True),
        requests_per_second=_positive(ti_raw.get("requests_per_second", 2.0),
                                       "threat_intel.requests_per_second"),
        circuit_failure_threshold=_positive(
            ti_raw.get("circuit_failure_threshold", 5),
            "threat_intel.circuit_failure_threshold", integer=True),
        circuit_reset_seconds=_positive(ti_raw.get("circuit_reset_seconds", 60.0),
                                        "threat_intel.circuit_reset_seconds"),
        abuseipdb_url=_validated_url(ti_raw.get("abuseipdb_url", ""),
                         "threat_intel.abuseipdb_url", allow_empty=True),
    )

    detection_raw = _mapping(source.get("detection", {}), "detection")
    detection = DetectionConfig(
        ssh_failures=_positive(detection_raw.get("ssh_failures", 8),
                               "detection.ssh_failures", integer=True),
        ssh_window_seconds=_positive(detection_raw.get("ssh_window_seconds", 60.0),
                                     "detection.ssh_window_seconds"),
        web_score_threshold=_positive(detection_raw.get("web_score_threshold", 2),
                                      "detection.web_score_threshold", integer=True),
        session_ttl_seconds=_positive(detection_raw.get("session_ttl_seconds", 3_600),
                                      "detection.session_ttl_seconds", integer=True),
    )
    alerting_raw = _mapping(source.get("alerting", {}), "alerting")
    raw_webhooks = alerting_raw.get("webhooks", {})
    if not isinstance(raw_webhooks, dict):
        raise ConfigError("alerting.webhooks must be an object")
    webhooks: list[tuple[str, tuple[str, ...]]] = []
    for severity, urls in raw_webhooks.items():
        if severity not in {"low", "medium", "high", "critical"}:
            raise ConfigError(f"invalid alert severity: {severity}")
        if not isinstance(urls, list) or not all(isinstance(url, str) and url for url in urls):
            raise ConfigError(f"alerting.webhooks.{severity} must be a list of URLs")
        webhooks.append((severity, tuple(
            _validated_url(url, f"alerting.webhooks.{severity}") for url in urls)))
    alerting = AlertingConfig(
        webhooks=tuple(webhooks),
        batch_size=_positive(alerting_raw.get("batch_size", 20),
                             "alerting.batch_size", integer=True),
        flush_interval_seconds=_positive(
            alerting_raw.get("flush_interval_seconds", 1.0),
            "alerting.flush_interval_seconds"),
        requests_per_second=_positive(alerting_raw.get("requests_per_second", 5.0),
                                       "alerting.requests_per_second"),
    )

    env = os.environ if environ is None else environ
    enabled = firewall.enabled
    if "ED_BT_ADE_DRY_RUN" in env:
        enabled = not _as_bool(env["ED_BT_ADE_DRY_RUN"], "ED_BT_ADE_DRY_RUN")
    level = env.get("ED_BT_ADE_LOG_LEVEL", str(source.get("log_level", "INFO"))).upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError("log_level is invalid")
    queue_size = _positive(source.get("queue_size", 50_000), "queue_size", integer=True)
    port = _positive(source.get("metrics_port", 9109), "metrics_port", integer=True)
    if port > 65_535:
        raise ConfigError("metrics_port must be <= 65535")
    return AppConfig(
        log_sources=tuple(sources),
        firewall=FirewallConfig(enabled=enabled, backend=firewall.backend,
                                state_db=firewall.state_db,
                                ban_seconds=firewall.ban_seconds,
                                whitelist=firewall.whitelist),
        threat_intel=ti,
        detection=detection,
        alerting=alerting,
        queue_size=queue_size,
        metrics_host=str(source.get("metrics_host", "127.0.0.1")),
        metrics_port=port,
        log_level=level,
    )
