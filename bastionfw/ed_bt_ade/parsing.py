"""Small, tolerant parsers for common Linux/web log representations."""

from __future__ import annotations

import json
import re
from urllib.parse import unquote_plus


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def normalize_for_detection(line: str, rounds: int = 3) -> str:
    """Decode common URL obfuscation without allowing unbounded expansion."""
    value = line
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def extract_remote_ip(line: str) -> str | None:
    """Extract an IPv4 address from JSON, Nginx/Apache, syslog, or journal text."""
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            for key in ("remote_addr", "client_ip", "source_ip", "src_ip", "ip"):
                value = payload.get(key)
                if isinstance(value, str) and _IP.fullmatch(value):
                    return value
            # systemd journal fields are often nested or named "_SOURCE_REALTIME_TIMESTAMP";
            # falling through still handles the common MESSAGE field.
            message = payload.get("MESSAGE")
            if isinstance(message, str):
                match = _IP.search(message)
                return match.group(0) if match else None
    match = _IP.search(line)
    return match.group(0) if match else None
