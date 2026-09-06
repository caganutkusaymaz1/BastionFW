"""Bi-directional WAF enforcement: IP reputation flows back to the WAF layer.

When the engine bans an address at L3/L4 (nftables/iptables) it also writes
the address into the WAF layer so requests arriving through proxies/CDNs are
cut at HTTP level too (see ``WafReputationDriver``). Expiry removal
(``unblock_expired``/``purge_all``) removes the address from both layers.

Design notes:
- The file-based driver maintains an atomically-replaced deny-list document
  that a Coraza/Caddy sidecar can watch and reload; it never calls the WAF
  API directly, keeping the engine dependency-free.
- All writes go through ``os.replace`` so readers never observe a partial
  file.
- ``WafDeadmanSwitch`` implements fail-open: if the WAF container is
  unhealthy longer than ``max_unhealthy_seconds``, the deny-list is cleared
  so the WAF path degrades to detect-only and the application stays
  reachable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Protocol, Sequence

LOGGER = logging.getLogger(__name__)

DENYLIST_FILE_NAME = "waf-denylist.json"


class WafReputationDriver(Protocol):
    """Interface between the engine's reputation layer and the WAF."""

    async def add(self, address: str) -> None:
        """Record a banned address at the WAF layer."""
        ...

    async def remove(self, address: str) -> None:
        """Remove an address from the WAF layer."""
        ...

    async def clear(self) -> None:
        """Remove every engine-recorded address (deadman/fail-open path)."""
        ...


class MockWafReputationDriver:
    """In-memory driver for unit tests and dry-run deployments."""

    def __init__(self) -> None:
        self.added: list[str] = []
        self.removed: list[str] = []
        self.cleared = 0

    async def add(self, address: str) -> None:
        self.added.append(address)

    async def remove(self, address: str) -> None:
        self.removed.append(address)

    async def clear(self) -> None:
        self.cleared += 1


class FileWafReputationDriver:
    """Writes the deny-list as an atomically-replaced JSON document.

    The document contains only the addresses the engine itself recorded, so
    removing it can never delete operator-managed WAF rules.
    """

    def __init__(self, state_dir: Path) -> None:
        self.path = Path(state_dir) / DENYLIST_FILE_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._addresses: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(document, dict) and isinstance(document.get("addresses"), list):
            self._addresses = {str(item) for item in document["addresses"]}

    def _flush(self) -> None:
        document = {
            "version": 1,
            "updated": int(asyncio.get_event_loop().time()),
            "addresses": sorted(self._addresses),
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(document, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - best effort hardening
            pass

    async def add(self, address: str) -> None:
        if address not in self._addresses:
            self._addresses.add(address)
            self._flush()

    async def remove(self, address: str) -> None:
        if address in self._addresses:
            self._addresses.discard(address)
            self._flush()

    async def clear(self) -> None:
        if self._addresses:
            self._addresses.clear()
            self._flush()

    def snapshot(self) -> tuple[str, ...]:
        return tuple(sorted(self._addresses))


class WafDeadmanSwitch:
    """Fail-open monitor: clears the WAF deny-list when the WAF goes unhealthy.

    Polled from the engine's event loop. If the WAF health probe has been
    failing for longer than ``max_unhealthy_seconds``, the deny-list is
    cleared once and an operator-visible warning is logged. The application
    behind a broken WAF must stay reachable (fail-open), while the L3/L4
    layer and the root deadman watchdog keep their independent protection.
    """

    def __init__(self, driver: WafReputationDriver,
                 max_unhealthy_seconds: float = 60.0) -> None:
        self.driver = driver
        self.max_unhealthy_seconds = max_unhealthy_seconds
        self.unhealthy_since: float | None = None
        self._tripped = False

    def report_health(self, healthy: bool, now: float | None = None) -> bool:
        """Record one health probe result; return True when fail-open trips."""
        import time

        current = time.time() if now is None else now
        if healthy:
            self.unhealthy_since = None
            self._tripped = False
            return False
        if self.unhealthy_since is None:
            self.unhealthy_since = current
            return False
        if (not self._tripped
                and current - self.unhealthy_since >= self.max_unhealthy_seconds):
            self._tripped = True
            return True
        return False

    async def trip(self) -> None:
        LOGGER.warning(
            "WAF unhealthy for %.0fs; clearing dynamic deny-list (fail-open)",
            self.max_unhealthy_seconds,
            extra={"event": "waf_deadman_tripped"})
        await self.driver.clear()


async def poll_waf_health(driver: WafReputationDriver,
                          deadman: WafDeadmanSwitch,
                          probe, stop: asyncio.Event,
                          interval: float = 15.0) -> None:
    """Periodically probe WAF health and enforce the fail-open policy.

    ``probe`` is an async callable returning a bool. Any exception from the
    probe is treated as unhealthy.
    """
    while not stop.is_set():
        try:
            healthy = bool(await probe())
        except Exception:
            healthy = False
        if deadman.report_health(healthy):
            await deadman.trip()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
