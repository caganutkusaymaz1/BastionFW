"""Safe firewall abstraction with persistent temporary-ban state."""

from __future__ import annotations

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
import sqlite3
import time
from typing import Callable, Sequence

from .config import FirewallConfig
from .validation import parse_ip, parse_network

LOGGER = logging.getLogger(__name__)


class FirewallError(RuntimeError):
    """A firewall operation could not be completed."""


class FirewallUnavailable(FirewallError):
    """The selected firewall is unavailable in the current environment."""


class FirewallDriver(ABC):
    @abstractmethod
    async def block(self, address: str) -> None:
        raise NotImplementedError

    @abstractmethod
    async def unblock(self, address: str) -> None:
        raise NotImplementedError


class MockFirewallDriver(FirewallDriver):
    """No-op driver for development hosts without firewall privileges."""

    async def block(self, address: str) -> None:
        LOGGER.info("firewall mock block", extra={"event": "firewall_mock", "ip": address})

    async def unblock(self, address: str) -> None:
        LOGGER.info("firewall mock unblock", extra={"event": "firewall_mock", "ip": address})


class CommandFirewallDriver(FirewallDriver):
    """Runs a fixed executable/argument shape; user data is never shell-parsed."""

    def __init__(self, executable: str, block_args: Sequence[str],
                 unblock_args: Sequence[str], enabled: bool,
                 block_builder: Callable[[str], Sequence[str]] | None = None,
                 unblock_builder: Callable[[str], Sequence[str]] | None = None) -> None:
        self.executable = executable
        self.block_args = tuple(block_args)
        self.unblock_args = tuple(unblock_args)
        self.enabled = enabled
        self.block_builder = block_builder
        self.unblock_builder = unblock_builder

    async def _run(self, args: Sequence[str]) -> None:
        if not self.enabled:
            LOGGER.warning("firewall dry-run", extra={"event": "firewall_dry_run"})
            return
        try:
            process = await asyncio.create_subprocess_exec(
                self.executable, *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError as exc:
            raise FirewallUnavailable(
                f"firewall executable not found: {self.executable}") from exc
        except PermissionError as exc:
            raise FirewallUnavailable(
                f"firewall executable is not permitted: {self.executable}") from exc
        _stdout, stderr = await process.communicate()
        if process.returncode != 0:
            message = stderr.decode(errors="replace").strip()
            if process.returncode in {1, 126, 127} or "permission denied" in message.lower():
                raise FirewallUnavailable(message or "firewall command is unavailable")
            raise FirewallError(message or "firewall command failed")

    async def block(self, address: str) -> None:
        args = self.block_builder(address) if self.block_builder else [*self.block_args, address]
        await self._run(args)

    async def unblock(self, address: str) -> None:
        args = self.unblock_builder(address) if self.unblock_builder else [*self.unblock_args, address]
        await self._run(args)


class NftablesDriver(CommandFirewallDriver):
    def __init__(self, enabled: bool) -> None:
        super().__init__(
            "nft", (), (), enabled,
            lambda ip: ("add", "element", "inet", "ed_bt_ade", "blacklist",
                        "{", ip, "}"),
            lambda ip: ("delete", "element", "inet", "ed_bt_ade", "blacklist",
                        "{", ip, "}"),
        )


class IptablesDriver(CommandFirewallDriver):
    def __init__(self, enabled: bool) -> None:
        super().__init__(
            "iptables", (), (), enabled,
            lambda ip: ("-I", "INPUT", "-s", ip, "-j", "DROP"),
            lambda ip: ("-D", "INPUT", "-s", ip, "-j", "DROP"),
        )


class UfwDriver(CommandFirewallDriver):
    def __init__(self, enabled: bool) -> None:
        super().__init__(
            "ufw", (), (), enabled,
            lambda ip: ("deny", "from", ip),
            lambda ip: ("delete", "deny", "from", ip),
        )


class FirewalldDriver(CommandFirewallDriver):
    def __init__(self, enabled: bool) -> None:
        super().__init__(
            "firewall-cmd", (), (), enabled,
            lambda ip: ("--add-rich-rule", f'rule family="ipv4" source address="{ip}" drop'),
            lambda ip: ("--remove-rich-rule", f'rule family="ipv4" source address="{ip}" drop'),
        )


def detect_driver(config: FirewallConfig) -> FirewallDriver:
    if config.backend == "dry-run":
        return MockFirewallDriver()
    candidates = {
        "nftables": ("nft", NftablesDriver),
        "iptables": ("iptables", IptablesDriver),
        "ufw": ("ufw", UfwDriver),
        "firewalld": ("firewall-cmd", FirewalldDriver),
    }
    if config.backend != "auto":
        executable, factory = candidates[config.backend]
        if not shutil.which(executable):
            LOGGER.warning("configured firewall unavailable; using mock driver",
                           extra={"event": "firewall_fallback", "executable": executable})
            return MockFirewallDriver()
        return factory(config.enabled)
    for executable, factory in candidates.values():
        if shutil.which(executable):
            return factory(config.enabled)
    LOGGER.warning("no firewall executable found; using dry-run driver")
    return MockFirewallDriver()


class FirewallOrchestrator:
    """Enforces IP/CIDR safety policy before touching the operating system."""

    def __init__(self, config: FirewallConfig, driver: FirewallDriver | None = None,
                 waf: object | None = None) -> None:
        """``waf`` is an optional L7 deny-list driver kept in lock-step with L3/L4."""
        self.config = config
        self.driver = driver or detect_driver(config)
        self.waf = waf
        self._blocked: set[str] = set()
        self._lock = asyncio.Lock()
        config.state_db.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(config.state_db, check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS bans "
            "(address TEXT PRIMARY KEY, expires_at REAL NOT NULL)")
        self._db.commit()
        self._load_active()

    def _load_active(self) -> None:
        now = time.time()
        rows = self._db.execute("SELECT address FROM bans WHERE expires_at > ?", (now,))
        self._blocked = {row[0] for row in rows}
        self._db.execute("DELETE FROM bans WHERE expires_at <= ?", (now,))
        self._db.commit()

    def _allowed(self, value: str) -> bool:
        try:
            network = parse_ip(value)
        except ValueError:
            return False
        if network.version != 4 or not network.is_global:
            return False
        forbidden = (
            parse_network("127.0.0.0/8"),
            parse_network("10.0.0.0/8"),
            parse_network("172.16.0.0/12"),
            parse_network("192.168.0.0/16"),
            parse_network("169.254.0.0/16"),
        )
        if any(network in item for item in forbidden):
            return False
        return not any(network in parse_network(item)
                       for item in self.config.whitelist)

    async def block(self, value: str, duration: int | None = None) -> bool:
        """Block a single public IPv4 address; return whether a new ban was added."""
        try:
            address = str(parse_ip(value))
        except ValueError:
            LOGGER.warning("invalid block address", extra={"ip": value})
            return False
        if not self._allowed(address):
            LOGGER.warning("firewall safety policy rejected address", extra={"ip": address})
            return False
        async with self._lock:
            if address in self._blocked:
                return False
            if duration is not None and duration <= 0:
                raise ValueError("duration must be greater than zero")
            try:
                await self.driver.block(address)
            except FirewallUnavailable as exc:
                LOGGER.warning("firewall unavailable; switching to mock driver",
                               extra={"event": "firewall_fallback", "reason": str(exc)})
                self.driver = MockFirewallDriver()
                return False
            expires = time.time() + (duration if duration is not None else self.config.ban_seconds)
            self._db.execute("INSERT OR REPLACE INTO bans VALUES (?, ?)", (address, expires))
            self._db.commit()
            self._blocked.add(address)
            try:
                waf = getattr(self, "waf", None)
                if waf is not None:
                    await waf.block(address, expires)
            except Exception:
                LOGGER.exception("waf deny-list block failed for %s; L3/L4 ban kept",
                                 address)
            return True

    async def unblock(self, address: str) -> bool:
        """Remove a single address from every enforcement layer; return whether it was banned."""
        try:
            canonical = str(parse_ip(address))
        except ValueError:
            return False
        async with self._lock:
            if canonical not in self._blocked:
                return False
            await self.driver.unblock(canonical)
            await self._sync_waf_unblock(canonical)
            self._blocked.discard(canonical)
            self._db.execute("DELETE FROM bans WHERE address = ?", (canonical,))
            self._db.commit()
            return True

    async def unblock_expired(self) -> int:
        async with self._lock:
            now = time.time()
            rows = list(self._db.execute("SELECT address FROM bans WHERE expires_at <= ?", (now,)))
            for (address,) in rows:
                await self.driver.unblock(address)
                await self._sync_waf_unblock(address)
                self._blocked.discard(address)
                self._db.execute("DELETE FROM bans WHERE address = ?", (address,))
            self._db.commit()
            purged = await self._sync_waf_purge_expired()
            return len(rows) + purged

    async def purge_all(self) -> int:
        """Instantly clear every active and expired ban from all layers."""
        async with self._lock:
            rows = list(self._db.execute("SELECT address FROM bans"))
            for (address,) in rows:
                try:
                    await self.driver.unblock(address)
                except FirewallUnavailable as exc:
                    LOGGER.warning("firewall unavailable during purge; switching to mock",
                                   extra={"event": "firewall_fallback", "reason": str(exc)})
                    self.driver = MockFirewallDriver()
                except FirewallError:
                    LOGGER.exception("firewall purge failed for %s", address)
                await self._sync_waf_unblock(address)
            self._db.execute("DELETE FROM bans")
            self._db.commit()
            self._blocked.clear()
            await self._sync_waf_purge_expired()
            return len(rows)

    def active_addresses(self) -> list[str]:
        """Return the currently banned addresses (safe for cross-thread reads)."""
        return sorted(self._blocked)

    async def _sync_waf_unblock(self, address: str) -> None:
        """Remove the address from the L7 deny-list; failures are logged only."""
        waf = getattr(self, "waf", None)
        if waf is None:
            return
        try:
            await waf.unblock(address)
        except Exception:
            LOGGER.exception("waf deny-list unblock failed for %s", address)

    async def _sync_waf_purge_expired(self) -> int:
        waf = getattr(self, "waf", None)
        if waf is None:
            return 0
        try:
            return await waf.purge_expired()
        except Exception:
            LOGGER.exception("waf deny-list expiry purge failed")
            return 0

    async def cleanup_loop(self, stop: asyncio.Event, interval: float = 30.0) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                await self.unblock_expired()

    def close(self) -> None:
        self._db.close()
