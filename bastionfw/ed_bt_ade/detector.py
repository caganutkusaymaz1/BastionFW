"""Pluggable, bounded detection rules for common defensive use cases."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import re
import time
from typing import Iterable, Protocol

from .parsing import extract_remote_ip, normalize_for_detection


@dataclass(frozen=True, slots=True)
class LogEvent:
    source: str
    line: str
    timestamp: float = field(default_factory=time.time)
    remote_ip: str | None = None
    user_agent: str | None = None
    request_uri: str | None = None


@dataclass(frozen=True, slots=True)
class Detection:
    rule: str
    severity: str
    source: str
    ip: str | None
    evidence: str
    score: int = 1


class DetectionRule(Protocol):
    def evaluate(self, event: LogEvent) -> Iterable[Detection]:
        ...


class SSHBruteForceRule:
    _failed = re.compile(r"(?:failed password|authentication failure|invalid user)", re.I)

    def __init__(self, threshold: int, window: float) -> None:
        self.threshold = threshold
        self.window = window
        self.attempts: defaultdict[str, deque[float]] = defaultdict(deque)

    def evaluate(self, event: LogEvent) -> Iterable[Detection]:
        if not self._failed.search(event.line):
            return ()
        ip = event.remote_ip or extract_remote_ip(event.line)
        if not ip:
            return ()
        bucket = self.attempts[ip]
        bucket.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.threshold:
            return (Detection("ssh_brute_force", "high", event.source, ip,
                              f"{len(bucket)} failed attempts/{self.window:.0f}s", len(bucket)),)
        return ()

    def purge(self, now: float) -> None:
        cutoff = now - self.window
        for ip in list(self.attempts):
            bucket = self.attempts[ip]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                del self.attempts[ip]


class WebAttackRule:
    _patterns = {
        "sqli": re.compile(
            r"(?:union\s+(?:all\s+)?select|select\s+.+\s+from|"
            r"(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
            r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay|"
            r"sql\s+syntax|mysql_fetch|unclosed\s+quotation)",
            re.I,
        ),
        "xss": re.compile(
            r"(?:<script|javascript:|data:text/html|on(?:error|load|mouseover)\s*=|"
            r"<svg|expression\s*\()",
            re.I,
        ),
        "rfi": re.compile(r"(?:https?://|ftp://|php://|data://).*(?:include|require)", re.I),
        "lfi_path_traversal": re.compile(
            r"(?:\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/proc/self/environ|"
            r"(?:boot|win)\.ini|\x00)",
            re.I,
        ),
        "web_shell": re.compile(
            r"(?:\beval\s*\(|\bassert\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|"
            r"\bpassthru\s*\(|\bbase64_decode\s*\()",
            re.I,
        ),
        "command_injection": re.compile(
            r"(?:[;&|]\s*(?:id|whoami|uname|cat|curl|wget|nc)\b|\$\([^)]{1,120}\))",
            re.I,
        ),
        "request_smuggling": re.compile(r"(?:transfer-encoding\s*:.*content-length|content-length\s*:.*transfer-encoding)", re.I),
    }

    def __init__(self, threshold: int = 1) -> None:
        self.threshold = threshold

    def evaluate(self, event: LogEvent) -> Iterable[Detection]:
        line = normalize_for_detection(
            " ".join(part for part in (event.line, event.user_agent, event.request_uri) if part)
        )
        matches = [name for name, pattern in self._patterns.items()
                   if pattern.search(line)]
        if len(matches) < self.threshold:
            return ()
        return (Detection("web_attack", "high", event.source,
                          event.remote_ip or extract_remote_ip(event.line),
                          ",".join(matches), len(matches)),)


class TokenBucket:
    """Bounded token bucket for burst control outside the ingestion loop."""

    def __init__(self, capacity: float, refill_per_second: float) -> None:
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("capacity and refill_per_second must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.tokens = capacity
        self.updated_at = time.monotonic()

    def allow(self, cost: float = 1.0, now: float | None = None) -> bool:
        if cost <= 0:
            raise ValueError("cost must be positive")
        current = time.monotonic() if now is None else now
        elapsed = max(0.0, current - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = current
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class WebRateLimitRule:
    """Rate-limit by IP, user agent, and URI using a bounded sliding window."""

    def __init__(self, threshold: int, window: float) -> None:
        if threshold <= 0 or window <= 0:
            raise ValueError("threshold and window must be positive")
        self.threshold = threshold
        self.window = window
        self.attempts: defaultdict[str, deque[float]] = defaultdict(deque)

    def evaluate(self, event: LogEvent) -> Iterable[Detection]:
        ip = event.remote_ip or extract_remote_ip(event.line) or "unknown"
        keys = {
            f"ip:{ip}",
            f"ua:{normalize_for_detection(event.user_agent or 'unknown')[:160]}",
            f"uri:{normalize_for_detection(event.request_uri or event.line)[:300]}",
        }
        matches: list[str] = []
        for key in keys:
            bucket = self.attempts[key]
            bucket.append(event.timestamp)
            cutoff = event.timestamp - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.threshold:
                matches.append(key.split(":", 1)[0])
        if not matches:
            return ()
        return (
            Detection(
                "http_rate_limit",
                "high",
                event.source,
                ip if ip != "unknown" else None,
                f"{','.join(sorted(set(matches)))} exceeded {self.threshold}/{self.window:.0f}s",
                len(matches),
            ),
        )

    def purge(self, now: float) -> None:
        cutoff = now - self.window
        for key in list(self.attempts):
            bucket = self.attempts[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                del self.attempts[key]


class PrivilegeEscalationRule:
    _pattern = re.compile(
        r"(?:sudo:.*COMMAND|session opened for user root|(?:modified|opened).*/etc/(?:passwd|sudoers)|"
        r"new cron|crontab|su:.*session opened)", re.I)

    def evaluate(self, event: LogEvent) -> Iterable[Detection]:
        if self._pattern.search(event.line):
            return (Detection("privilege_escalation_anomaly", "medium", event.source,
                              event.remote_ip or extract_remote_ip(event.line),
                              event.line[:300]),)
        return ()


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self.rules = tuple(rules)

    def evaluate(self, event: LogEvent) -> list[Detection]:
        detections: list[Detection] = []
        for rule in self.rules:
            detections.extend(rule.evaluate(event))
        return detections

    def purge(self, now: float | None = None) -> None:
        for rule in self.rules:
            purge = getattr(rule, "purge", None)
            if purge:
                purge(now or time.time())
