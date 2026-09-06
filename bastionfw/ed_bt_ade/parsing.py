"""Small, tolerant parsers for common Linux/web log representations."""

from __future__ import annotations

from dataclasses import dataclass
import json
import html
import re
import unicodedata
from ipaddress import IPv4Address, ip_address, ip_network
from urllib.parse import unquote_plus
from typing import Any, Mapping, Sequence

from .validation import ValidationError, parse_ip


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_DETECTION_INPUT = 64 * 1024
MAX_URL_DECODE_ROUNDS = 4


@dataclass(frozen=True, slots=True)
class CorazaAuditEvent:
    """Normalized single-request view of a Coraza JSON audit-log line."""

    ip: str | None
    anomaly_score: int = 0
    severity: str = "low"
    rule_ids: tuple[str, ...] = ()
    evidence: str = ""
    method: str = ""
    uri: str = ""
    interrupted: bool = False
    timestamp: float | None = None


_SEVERITY_SCORE = {"low": 2, "medium": 3, "high": 4, "critical": 5}
_TOTAL_SCORE = re.compile(r"total\s+score\s*[:=]\s*(\d+)", re.I)


def _severity_label(value: Any) -> str:
    """Map Coraza/CRS severity names onto BastionFW severities."""
    mapping = {
        "CRITICAL": "critical", "ERROR": "high", "WARNING": "medium",
        "NOTICE": "low", "INFO": "low", "DEBUG": "low", "EMERGENCY": "critical",
        "ALERT": "critical", "EMERG": "critical",
    }
    if isinstance(value, str) and value.strip().upper() in mapping:
        return mapping[value.strip().upper()]
    return "low"


def _split_host(value: Any) -> str:
    """Strip an optional port from a host string and canonicalize it."""
    if not isinstance(value, str) or not value.strip():
        return ""
    candidate = value.strip()
    if ":" in candidate:
        head, _separator, tail = candidate.rpartition(":")
        # IPv6 literals keep their brackets; only strip a trailing numeric port.
        if tail.isdigit() and head:
            candidate = head
    candidate = candidate.strip("[]")
    try:
        return str(parse_ip(candidate))
    except ValidationError:
        return ""


def _mapping_at(payload: Mapping[str, Any], *paths: str) -> Mapping[str, Any] | None:
    current: Any = payload
    for key in paths:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current if isinstance(current, Mapping) else None


def parse_coraza_audit_line(line: str) -> CorazaAuditEvent | None:
    """Parse one Coraza JSON audit-log line into a normalized event.

    Accepts the Coraza v3 ``SecAuditLogFormat json`` schema (``transaction``
    plus structured ``messages``) as well as legacy ``audit_data`` layouts.
    The client IP is validated and canonicalized through
    :func:`validation.parse_ip`; entries without a usable client IP or a
    valid JSON object yield ``None`` so the pipeline can skip them silently.
    """
    stripped = line.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    transaction = _mapping_at(payload, "transaction") or {}
    client = transaction.get("client_ip") or payload.get("client_ip")
    if not client:
        client = transaction.get("remote_address") or payload.get("remote_address")
    ip = _split_host(client)
    if not ip:
        return None

    request = _mapping_at(payload, "request") or _mapping_at(payload, "transaction", "request") or {}
    method = str(request.get("method", "")).strip()
    uri = str(request.get("uri", "")).strip()
    if not method and not uri:
        request_line = str(request.get("request_line", ""))
        parts = request_line.split()
        method = parts[0] if parts else ""
        uri = parts[1] if len(parts) > 1 else ""

    messages: list[Mapping[str, Any]] = []
    raw_messages = payload.get("messages")
    if isinstance(raw_messages, list):
        messages = [item for item in raw_messages if isinstance(item, Mapping)]
    audit_data = _mapping_at(payload, "audit_data")
    if audit_data is not None:
        nested = audit_data.get("messages")
        if isinstance(nested, list):
            messages.extend(item for item in nested if isinstance(item, Mapping))

    rule_ids: list[str] = []
    messages_text: list[str] = []
    highest = "low"
    for item in messages:
        data = _mapping_at(item, "data") or item
        rule_id = item.get("rule_id") or data.get("id")
        if rule_id is not None:
            rule_ids.append(str(rule_id))
        rule_severity = item.get("severity") or data.get("severity")
        label = _severity_label(rule_severity or
                                transaction.get("highest_severity"))
        if _SEVERITY_SCORE[label] > _SEVERITY_SCORE[highest]:
            highest = label
        detail = (item.get("message") or data.get("msg")
                  or item.get("msg") or data.get("data") or "")
        if isinstance(detail, str) and detail:
            messages_text.append(detail)

    joined = " ".join(messages_text)
    anomaly = 0
    for candidate in (audit_data.get("anomaly_score") if audit_data else None,
                      (transaction.get("tx") if isinstance(transaction.get("tx"), Mapping)
                       else None) and transaction["tx"].get("anomaly_score"),
                      payload.get("anomaly_score")):
        if isinstance(candidate, (int, float)) and candidate > 0:
            anomaly = int(candidate)
            break
    total = _TOTAL_SCORE.search(joined)
    if anomaly <= 0 and total is not None:
        anomaly = int(total.group(1))
    if anomaly <= 0:
        anomaly = _SEVERITY_SCORE[highest] if messages else 0

    response = _mapping_at(payload, "response") or _mapping_at(payload, "transaction", "response") or {}
    interrupted = bool(transaction.get("is_interrupted") or payload.get("is_interrupted"))
    blocked = interrupted or int(response.get("status", 0) or 0) in {403, 429}
    if highest == "low" and blocked:
        highest = "high"

    transaction_ts = transaction.get("unix_timestamp")
    timestamp = float(transaction_ts) if isinstance(transaction_ts, (int, float)) else None
    return CorazaAuditEvent(
        ip=ip,
        anomaly_score=anomaly,
        severity=highest,
        rule_ids=tuple(dict.fromkeys(rule_ids)),
        evidence=joined[:1024],
        method=method[:128],
        uri=uri[:1024],
        interrupted=blocked,
        timestamp=timestamp,
    )


def normalize_for_detection(line: str, rounds: int = MAX_URL_DECODE_ROUNDS) -> str:
    """Apply bounded decoding and canonicalization before security matching."""
    value = str(line)[:MAX_DETECTION_INPUT]
    for _ in range(min(max(rounds, 0), MAX_URL_DECODE_ROUNDS)):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded[:MAX_DETECTION_INPUT]
    value = html.unescape(value)
    value = unicodedata.normalize("NFC", value)
    return value.casefold()[:MAX_DETECTION_INPUT]


def normalize_request_data(query: str = "", headers: Mapping[str, str] | None = None,
                           body: str = "") -> str:
    """Normalize query, header, and body data through one bounded WAF pipeline."""
    header_values = headers.values() if headers else ()
    return normalize_for_detection(" ".join((query, *header_values, body)))


def _trusted_peer(value: str, trusted_proxies: Sequence[str]) -> bool:
    try:
        peer = ip_address(value)
    except ValueError:
        return False
    for item in trusted_proxies:
        try:
            if peer in ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def _valid_ipv4(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        address = IPv4Address(value.strip())
    except ValueError:
        return None
    return str(address)


def _forwarded_client_ip(value: Any) -> str | None:
    if isinstance(value, str):
        for candidate in value.split(","):
            address = _valid_ipv4(candidate)
            if address:
                return address
    return _valid_ipv4(value)


def extract_remote_ip(line: str, trusted_proxies: Sequence[str] = ()) -> str | None:
    """Extract an IPv4 address from JSON, Nginx/Apache, syslog, or journal text."""
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            peer = None
            for key in ("remote_addr", "client_ip", "source_ip", "src_ip", "ip"):
                value = _valid_ipv4(payload.get(key))
                if value:
                    peer = value
                    break
            headers = payload.get("headers")
            if peer and _trusted_peer(peer, trusted_proxies) and isinstance(headers, dict):
                forwarded = _forwarded_client_ip(
                    headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or
                    headers.get("x-real-ip") or headers.get("X-Real-IP"))
                if forwarded:
                    return forwarded
            if peer:
                return peer
            # systemd journal fields are often nested or named "_SOURCE_REALTIME_TIMESTAMP";
            # falling through still handles the common MESSAGE field.
            message = payload.get("MESSAGE")
            if isinstance(message, str):
                match = _IP.search(message)
                return _valid_ipv4(match.group(0)) if match else None
    match = _IP.search(line)
    return _valid_ipv4(match.group(0)) if match else None
