"""Small, tolerant parsers for common Linux/web log representations."""

from __future__ import annotations

import json
import html
import re
import unicodedata
from ipaddress import IPv4Address, ip_address, ip_network
from urllib.parse import unquote_plus
from typing import Any, Mapping, Sequence


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_DETECTION_INPUT = 64 * 1024
MAX_URL_DECODE_ROUNDS = 4


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
