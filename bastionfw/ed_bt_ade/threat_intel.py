"""Asynchronous threat-intelligence enrichment with bounded failure behavior."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

from .validation import parse_ip

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Reputation:
    ip: str
    score: float
    source: str
    fetched_at: float


class TokenBucket:
    def __init__(self, rate: float, capacity: int | None = None) -> None:
        self.rate = rate
        self.capacity = capacity or max(1, int(rate))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                delay = (1 - self.tokens) / self.rate
            await asyncio.sleep(delay)


class CircuitBreaker:
    def __init__(self, threshold: int, reset_seconds: float) -> None:
        self.threshold = threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_at: float | None = None
        self.lock = asyncio.Lock()

    async def permitted(self) -> bool:
        async with self.lock:
            if self.opened_at is None:
                return True
            if time.monotonic() - self.opened_at >= self.reset_seconds:
                self.opened_at = None
                self.failures = 0
                return True
            return False

    async def success(self) -> None:
        async with self.lock:
            self.failures = 0
            self.opened_at = None

    async def failure(self) -> None:
        async with self.lock:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_at = time.monotonic()


class ReputationCache:
    def __init__(self, path: Path, ttl: int, max_entries: int = 10_000) -> None:
        self.path = path
        self.ttl = ttl
        self.max_entries = max_entries
        self.memory: OrderedDict[str, Reputation] = OrderedDict()
        self.lock = asyncio.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS reputation "
                        "(ip TEXT PRIMARY KEY, score REAL, source TEXT, fetched_at REAL)")
        self.db.commit()

    async def get(self, ip: str) -> Reputation | None:
        async with self.lock:
            item = self.memory.get(ip)
            if item and time.time() - item.fetched_at < self.ttl:
                self.memory.move_to_end(ip)
                return item
            row = await asyncio.to_thread(
                self._get_row, ip)
            if row and time.time() - row[3] < self.ttl:
                item = Reputation(*row)
                self.memory[ip] = item
                self.memory.move_to_end(ip)
                self._trim()
                return item
            return None

    async def put(self, item: Reputation) -> None:
        async with self.lock:
            self.memory[item.ip] = item
            self.memory.move_to_end(item.ip)
            self._trim()
            await asyncio.to_thread(self._put_row, item)

    def _get_row(self, ip: str) -> tuple[object, ...] | None:
        return self.db.execute(
            "SELECT ip, score, source, fetched_at FROM reputation WHERE ip = ?", (ip,)
        ).fetchone()

    def _put_row(self, item: Reputation) -> None:
        self.db.execute("INSERT OR REPLACE INTO reputation VALUES (?, ?, ?, ?)",
                        (item.ip, item.score, item.source, item.fetched_at))
        self.db.commit()

    def _trim(self) -> None:
        while len(self.memory) > self.max_entries:
            self.memory.popitem(last=False)

    async def purge(self) -> None:
        async with self.lock:
            cutoff = time.time() - self.ttl
            await asyncio.to_thread(self._purge_rows, cutoff)
            for ip, item in list(self.memory.items()):
                if item.fetched_at < cutoff:
                    del self.memory[ip]

    def _purge_rows(self, cutoff: float) -> None:
        self.db.execute("DELETE FROM reputation WHERE fetched_at < ?", (cutoff,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


class ThreatIntelClient:
    def __init__(self, config: object) -> None:
        self.enabled = bool(getattr(config, "enabled"))
        self.url = str(getattr(config, "abuseipdb_url"))
        self.cache = ReputationCache(getattr(config, "cache_db"),
                                      int(getattr(config, "cache_ttl_seconds")))
        self.bucket = TokenBucket(float(getattr(config, "requests_per_second")))
        self.breaker = CircuitBreaker(int(getattr(config, "circuit_failure_threshold")),
                                      float(getattr(config, "circuit_reset_seconds")))
        try:
            os.chmod(getattr(config, "cache_db"), 0o600)
        except OSError:  # pragma: no cover - non-POSIX or read-only filesystem
            LOGGER.warning("could not harden threat-intel cache permissions",
                           extra={"event": "state_permissions_failed"})

    async def lookup(self, ip: str) -> Reputation | None:
        if not self.enabled or not self.url:
            return None
        cached = await self.cache.get(ip)
        if cached:
            return cached
        if not await self.breaker.permitted():
            return None
        await self.bucket.acquire()
        for attempt in range(3):
            try:
                item = await asyncio.wait_for(asyncio.to_thread(self._request, ip), 8)
                await self.breaker.success()
                await self.cache.put(item)
                return item
            except Exception as exc:  # external systems must not stop ingestion
                await self.breaker.failure()
                if attempt == 2:
                    LOGGER.warning("threat intel unavailable: %s", exc)
                    return None
                await asyncio.sleep(0.25 * (2 ** attempt))
        return None

    def _request(self, ip: str) -> Reputation:
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("ED_BT_ADE_ABUSEIPDB_KEY")
        if api_key:
            headers["Key"] = api_key
        # encode the caller-supplied address; a malformed value must not
        # turn into a query-string injection via raw interpolation.
        request = Request(
            self.url + "?ipAddress=" + quote(str(parse_ip(ip))), headers=headers)
        with urlopen(request, timeout=7) as response:  # noqa: S310 - configured endpoint
            data = json.loads(response.read().decode())
        score = float(data.get("data", {}).get("abuseConfidenceScore", 0))
        return Reputation(ip, score, "abuseipdb", time.time())

    async def close(self) -> None:
        self.cache.close()
