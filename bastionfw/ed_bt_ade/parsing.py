"""Small, tolerant parsers for common Linux/web log representations."""

from __future__ import annotations

import json
import html
import re
import unicodedata
from ipaddress import IPv4Address, ip_address, ip_network
from urllib.parse import unquote_plus
from typing import Any, Mapping, Sequence

import logging

LOGGER = logging.getLogger(__name__)


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_DETECTION_INPUT = 64 * 1024
MAX_URL_DECODE_ROUNDS = 4

# Coraza audit JSON guard rails: refuse absurd inputs before parsing.
MAX_CORAZA_LINE_BYTES = 1_048_576
MAX_CORAZA_JSON_DEPTH = 64
MAX_CORAZA_RULE_IDS = 32

# OWASP CRS anomaly-score style fields accepted in the Coraza audit payload.
_CORAZA_SCORE_FIELDS = ("anomaly_score", "score", "tx.anomaly_score")


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_CORAZA_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_json_depth(v, depth + 1) for v in value.values()), default=depth)
    if isinstance(value, (list, tuple)):
        return max((_json_depth(v, depth + 1) for v in value), default=depth)
    return depth


def _coraza_ip(candidate: Any) -> str | None:
    """Canonicalize a Coraza-provided address through validation.parse_ip."""
    if not isinstance(candidate, str) or not candidate.strip():
        return None
    try:
        from .validation import ValidationError, parse_ip

        return str(parse_ip(candidate.strip()))
    except Exception:  # ValidationError or import issues never escape a parser
        return None


def _coraza_nested_ip(document: Any) -> str | None:
    """Search the audit document for the first parseable client address."""
    if isinstance(document, dict):
        for key in ("client_ip", "remote_addr", "client_address", "ip"):
            found = _coraza_ip(document.get(key))
            if found is not None:
                return found
        for value in document.values():
            found = _coraza_nested_ip(value)
            if found is not None:
                return found
    elif isinstance(document, list):
        for value in document:
            found = _coraza_nested_ip(value)
            if found is not None:
                return found
    return None


def _coraza_rule_ids(document: Any) -> tuple[str, ...]:
    """Collect matched rule IDs from any common Coraza payload shape."""
    ids: list[str] = []
    if isinstance(document, dict):
        for key in ("rule_ids", "matched_rules", "rules"):
            value = document.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, (int, float)) or isinstance(item, str):
                        text = str(item).strip()
                        if text and len(text) <= 64:
                            ids.append(text)
            elif isinstance(value, str):
                text = value.strip()
                if text and len(text) <= 64:
                    ids.append(text)
        for child in document.values():
            if len(ids) >= MAX_CORAZA_RULE_IDS:
                break
            ids.extend(_coraza_rule_ids(child) if isinstance(child, (dict, list)) else [])
    elif isinstance(document, list):
        for child in document:
            if len(ids) >= MAX_CORAZA_RULE_IDS:
                break
            ids.extend(_coraza_rule_ids(child))
    seen: set[str] = set()
    ordered: list[str] = []
    for rule_id in ids[:MAX_CORAZA_RULE_IDS]:
        if rule_id not in seen:
            seen.add(rule_id)
            ordered.append(rule_id)
    return tuple(ordered)


def _coraza_anomaly_score(document: Any) -> int:
    if isinstance(document, dict):
        for key in _CORAZA_SCORE_FIELDS:
            value = document.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str):
                try:
                    return int(float(value))
                except ValueError:
                    continue
        for child in document.values():
            if isinstance(child, (dict, list)):
                found = _coraza_anomaly_score(child)
                if found > 0:
                    return found
    elif isinstance(document, list):
        for child in document:
            found = _coraza_anomaly_score(child)
            if found > 0:
                return found
    return 0


def parse_coraza_audit_line(line: str) -> Detection | None:
    """Parse one Coraza WAF JSON audit line into a :class:`Detection`.

    Accepts the JSON shapes Coraza emits (top-level fields or the nested
    ``transaction``/``messages`` structures). The client address is
    canonicalized through ``validation.parse_ip``: unparseable or hostile
    addresses yield ``None``. Depth- and size-limited so hostile audit data
    cannot exhaust the parser. Never raises on malformed input.
    """
    from .detector import Detection

    if not isinstance(line, str):
        return None
    if len(line.encode("utf-8", errors="replace")) > MAX_CORAZA_LINE_BYTES:
        LOGGER.warning("coraza audit line exceeds size limit; skipping",
                       extra={"event": "coraza_audit_oversized"})
        return None
    try:
        document = json.loads(line)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    try:
        if _json_depth(document) > MAX_CORAZA_JSON_DEPTH:
            LOGGER.warning("coraza audit JSON exceeds depth limit; skipping",
                           extra={"event": "coraza_audit_deep"})
            return None
    except RecursionError:
        return None
    client_ip = _coraza_nested_ip(document)
    if client_ip is None:
        return None
    score = _coraza_anomaly_score(document)
    rule_ids = _coraza_rule_ids(document)
    severity = "high" if score >= 5 else ("medium" if score > 0 else "low")
    evidence_source = document.get("transaction") if isinstance(
        document.get("transaction"), dict) else document
    uri = evidence_source.get("uri") if isinstance(evidence_source, dict) else None
    rule_summary = ",".join(rule_ids[:8])
    if uri and rule_summary:
        evidence = f"{rule_summary} {str(uri)[:200]}"
    elif uri:
        evidence = str(uri)[:256]
    else:
        evidence = rule_summary or "coraza_audit"
    return Detection(
        rule="coraza_waf_match" if rule_ids else "coraza_audit",
        severity=severity,
        source="coraza_audit",
        ip=client_ip,
        evidence=evidence,
        score=max(score, 1),
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
