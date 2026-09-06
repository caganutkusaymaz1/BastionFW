"""Bidirectional L7 deny-list drivers for the Coraza/Caddy WAF.

Every banned IP must be enforced on two layers at once:

- L3/L4 (nftables/iptables) is handled by the firewall orchestrator;
- L7 is handled here: the IP is written to the Coraza WAF dynamic deny-list.

The deny-list is a JSON state file (the source of truth, including expiries)
plus a generated Caddy matcher include (``deny.caddy``) that makes Caddy
respond 403 before Coraza and the proxy run. After every mutation the driver
asks Caddy to gracefully reload through its admin API, which re-parses the
imported include without dropping traffic.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
import json
import logging
import time
from typing import Any

from .config import WafConfig
from .rollback import caddy_admin_reload

LOGGER = logging.getLogger(__name__)

DENY_STATE_VERSION = 1
DENY_RESPONSE = "blocked by BastionFW dynamic deny-list"


class WafReputationError(RuntimeError):
    """A WAF deny-list operation could not be completed."""


class WafReputationDriver(ABC):
    @abstractmethod
    async def block(self, address: str, expires_at: float) -> None:
        """Add ``address`` to the L7 deny-list until ``expires_at``."""

    @abstractmethod
    async def unblock(self, address: str) -> None:
        """Remove ``address`` from the L7 deny-list."""

    @abstractmethod
    async def purge_expired(self) -> int:
        """Drop expired entries; return how many were removed."""

    @abstractmethod
    def active_count(self) -> int:
        """Number of addresses currently present in the deny-list."""


class MockWafReputationDriver(WafReputationDriver):
    """In-memory driver for tests and hosts without a WAF deployment."""

    def __init__(self) -> None:
        self.entries: dict[str, float] = {}
        self.calls: list[tuple[str, str]] = []

    async def block(self, address: str, expires_at: float) -> None:
        self.calls.append(("block", address))
        self.entries[address] = expires_at

    async def unblock(self, address: str) -> None:
        self.calls.append(("unblock", address))
        self.entries.pop(address, None)

    async def purge_expired(self) -> int:
        now = time.time()
        expired = [address for address, expires in self.entries.items()
                   if expires <= now]
        for address in expired:
            self.entries.pop(address, None)
        return len(expired)

    def active_count(self) -> int:
        return len(self.entries)


class FileWafReputationDriver(WafReputationDriver):
    """Persistent deny-list driver synchronized with the Coraza/Caddy WAF."""

    def __init__(self, config: WafConfig) -> None:
        self.config = config
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._load()
        LOGGER.info("waf deny-list initialized at %s", config.deny_list_path,
                    extra={"event": "waf_deny_list_init"})

    # -- state --------------------------------------------------------------
    def _load(self) -> None:
        path = self.config.deny_list_path
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            LOGGER.warning("deny-list file is corrupt; starting empty: %s", path)
            return
        entries = document.get("entries") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            if isinstance(address, str) and address not in self._entries:
                self._entries[address] = entry

    def _active_entries(self) -> list[dict[str, Any]]:
        now = time.time()
        return [entry for entry in self._entries.values()
                if float(entry.get("expires_at", 0)) > now]

    def _persist(self) -> None:
        self.config.deny_list_path.parent.mkdir(parents=True, exist_ok=True)
        document = {"version": DENY_STATE_VERSION, "entries": list(self._entries.values())}
        temporary = self.config.deny_list_path.with_suffix(
            self.config.deny_list_path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, separators=(",", ":")),
                             encoding="utf-8")
        temporary.replace(self.config.deny_list_path)

    def _deny_include_text(self) -> str:
        addresses = sorted(entry["address"] for entry in self._active_entries())
        if not addresses:
            return ""
        joined = " ".join(addresses)
        return (f"@bastionfw_denied remote_ip {joined}\n"
                f"respond @bastionfw_denied \"{DENY_RESPONSE}\" 403\n")

    def _regenerate_deny_include(self) -> None:
        self.config.deny_include_path.parent.mkdir(parents=True, exist_ok=True)
        content = self._deny_include_text()
        temporary = self.config.deny_include_path.with_suffix(
            self.config.deny_include_path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(self.config.deny_include_path)

    async def _apply(self) -> None:
        """Persist state, regenerate the Caddy include, and reload if wired."""
        await asyncio.to_thread(self._persist)
        await asyncio.to_thread(self._regenerate_deny_include)
        if self.config.admin_url and self.config.caddyfile_path is not None:
            ok = await caddy_admin_reload(self.config.admin_url,
                                          self.config.caddyfile_path)
            if not ok:
                LOGGER.warning(
                    "deny-list updated but the WAF was not reloaded; changes "
                    "apply on the next reload/restart")
        elif not self.config.admin_url:
            LOGGER.info("no waf.admin_url configured; deny-list kept in %s",
                        self.config.deny_list_path)

    # -- driver API ---------------------------------------------------------
    async def block(self, address: str, expires_at: float) -> None:
        async with self._lock:
            existing = self._entries.get(address)
            if existing is None:
                self._entries[address] = {
                    "address": address,
                    "expires_at": expires_at,
                    "created_at": time.time(),
                }
            else:
                existing["expires_at"] = expires_at
            await self._apply()

    async def unblock(self, address: str) -> None:
        async with self._lock:
            if address not in self._entries:
                return
            del self._entries[address]
            await self._apply()

    async def purge_expired(self) -> int:
        async with self._lock:
            now = time.time()
            expired = [address for address, entry in self._entries.items()
                       if float(entry.get("expires_at", 0)) <= now]
            if not expired:
                return 0
            for address in expired:
                del self._entries[address]
            await self._apply()
            return len(expired)

    def active_count(self) -> int:
        return len(self._active_entries())


def detect_waf_reputation_driver(config: WafConfig) -> WafReputationDriver:
    """Return a mock driver unless the WAF integration is explicitly enabled."""
    if not config.enabled:
        return MockWafReputationDriver()
    return FileWafReputationDriver(config)
