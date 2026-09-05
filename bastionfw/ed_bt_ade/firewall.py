"""Safe firewall abstraction with persistent temporary-ban state."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
import sqlite3
import time
from typing import Callable, Sequence

from .config import FirewallConfig

LOGGER = logging.getLogger(__name__)


class FirewallError(RuntimeError):
    """A firewall operation could not be completed."""


class FirewallDriver(ABC):
    @abstractmethod
    async def block(self, address: str) -> None:
        raise NotImplementedError

    @abstractmethod
    async def unblock(self, address: str) -> None:
        raise NotImplementedError


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
        process = await asyncio.create_subprocess_exec(
            self.executable, *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        _stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise FirewallError(stderr.decode(errors="replace").strip())

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
        return CommandFirewallDriver("true", (), (), False)
    candidates = {
        "nftables": ("nft", NftablesDriver),
        "iptables": ("iptables", IptablesDriver),
        "ufw": ("ufw", UfwDriver),
        "firewalld": ("firewall-cmd", FirewalldDriver),
    }
    if config.backend != "auto":
        executable, factory = candidates[config.backend]
        if not shutil.which(executable):
            raise FirewallError(f"configured firewall executable not found: {executable}")
        return factory(config.enabled)
    for executable, factory in candidates.values():
        if shutil.which(executable):
            return factory(config.enabled)
    LOGGER.warning("no firewall executable found; using dry-run driver")
    return CommandFirewallDriver("true", (), (), False)


class FirewallOrchestrator:
    """Enforces IP/CIDR safety policy before touching the operating system."""

    def __init__(self, config: FirewallConfig, driver: FirewallDriver | None = None) -> None:
        self.config = config
        self.driver = driver or detect_driver(config)
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
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        if network.version != 4:
            return False
        forbidden = (
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
        if any(network.subnet_of(item) or item.subnet_of(network) for item in forbidden):
            return False
        return not any(network.overlaps(ipaddress.ip_network(item, strict=False))
                       for item in self.config.whitelist)

    async def block(self, value: str, duration: int | None = None) -> bool:
        """Block a single public IPv4 address; return whether a new ban was added."""
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            LOGGER.warning("invalid block address", extra={"ip": value})
            return False
        if not self._allowed(address):
            LOGGER.warning("firewall safety policy rejected address", extra={"ip": address})
            return False
        async with self._lock:
            if address in self._blocked:
                return False
            await self.driver.block(address)
            expires = time.time() + (duration or self.config.ban_seconds)
            self._db.execute("INSERT OR REPLACE INTO bans VALUES (?, ?)", (address, expires))
            self._db.commit()
            self._blocked.add(address)
            return True

    async def unblock_expired(self) -> int:
        async with self._lock:
            now = time.time()
            rows = list(self._db.execute("SELECT address FROM bans WHERE expires_at <= ?", (now,)))
            for (address,) in rows:
                await self.driver.unblock(address)
                self._blocked.discard(address)
                self._db.execute("DELETE FROM bans WHERE address = ?", (address,))
            self._db.commit()
            return len(rows)

    async def cleanup_loop(self, stop: asyncio.Event, interval: float = 30.0) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                await self.unblock_expired()

    def close(self) -> None:
        self._db.close()
