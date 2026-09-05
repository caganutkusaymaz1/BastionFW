"""Deadman switch and auto-rollback for firewall enforcement.

Fail-safe design (fail-open for the operator):
- While the enforcement engine runs, a watchdog task renews a liveness file
  in short intervals. The file is refreshed only while the event loop is
  healthy.
- A tiny root shell script (run by cron or a systemd timer, outside this
  process) checks the file's mtime every minute. If the engine has crashed,
  hung, or been stopped for longer than the rollback window, the script
  removes all engine-owned nftables/iptables rules. It runs without Python
  and without any part of BastionFW being alive.
- ``FirewallOrchestrator`` also auto-rolls-back every ban at graceful
  shutdown, so a normal stop never leaves rules behind.

Every address recorded to the OS by ``CommandFirewallDriver`` has already
passed ``FirewallOrchestrator._allowed()`` vetting, so the rollback targets
a pre-approved universe of addresses: public IPv4 outside the configured
whitelist. No whitelisted operator address is ever touched.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .config import FirewallConfig
    from .firewall import FirewallOrchestrator

LOGGER = logging.getLogger(__name__)

DEFAULT_ROLLBACK_SECONDS = 120
LIVENESS_FILE_NAME = "deadman.liveness"
ROLLBACK_SCRIPT_NAME = "rollback-deadman.sh"
MIN_ROLLBACK_SECONDS = 10


def resolve_rollback_seconds(default: int = DEFAULT_ROLLBACK_SECONDS) -> int:
    """Read the rollback window from ED_BT_ADE_ROLLBACK_SECONDS safely."""
    raw = os.environ.get("ED_BT_ADE_ROLLBACK_SECONDS")
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < MIN_ROLLBACK_SECONDS:
        return default
    return value


def renewal_interval(rollback_seconds: int) -> float:
    """Renew at least six times inside the rollback window."""
    return max(1.0, rollback_seconds / 6.0)


def liveness_path(state_dir: Path) -> Path:
    return state_dir / LIVENESS_FILE_NAME


_FORBIDDEN_IN_STATE_DIR = ("\"", "$", "`", "\\", "\n", "\r", "\x00")


def validate_state_dir_for_script(state_dir: Path) -> str:
    """Reject paths that cannot be safely embedded in the POSIX-sh watchdog.

    The generated script interpolates the state directory inside
    double-quoted assignments. Characters that sh would expand or that
    terminate the quoting context would corrupt a script that runs as root,
    so they are refused at generation time instead of at detonation time.
    """
    text = str(state_dir)
    if any(character in text for character in _FORBIDDEN_IN_STATE_DIR):
        raise ValueError(
            'state_dir must not contain shell metacharacters (", $, `, \\, '
            "or newline); the deadman watchdog embeds it in a POSIX-sh script")
    return text


def rollback_script_path(path: Path) -> Path:
    return Path(path)


class DeadmanSwitch:
    """Renews a mtime-based liveness file while the event loop is healthy.

    The watchdog runs as an asyncio task: if the event loop wedges (blocking
    call, deadlock, resource exhaustion), renewals stop and the external
    root watchdog eventually trips and rolls back all engine bans.
    """

    def __init__(self, state_dir: Path,
                 rollback_seconds: int = DEFAULT_ROLLBACK_SECONDS) -> None:
        self.seconds = max(MIN_ROLLBACK_SECONDS, int(rollback_seconds))
        self.path = liveness_path(state_dir)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def _touch(self) -> None:
        with self.path.open("a"):
            os.utime(self.path, None)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - best effort hardening
            pass

    def renew(self) -> None:
        self._touch()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self.stop_event.clear()
            self._task = asyncio.get_running_loop().create_task(
                self._loop(), name="deadman-watchdog")
            self._touch()

    def request_stop(self) -> None:
        self.stop_event.set()

    async def _loop(self) -> None:
        interval = renewal_interval(self.seconds)
        while not self.stop_event.is_set():
            self._touch()
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def close(self) -> None:
        self.stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        try:
            self.path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best effort cleanup
            pass


def build_deadman_script(state_dir: Path, rollback_seconds: int) -> str:
    """Return a standalone POSIX-sh watchdog script for root deployment.

    The script removes only addresses that the engine itself recorded in
    ``firewall.sqlite3`` (or that are still present in the engine-owned
    nftables set). It never touches whitelisted or operator-managed rules.
    """
    state_dir_s = validate_state_dir_for_script(state_dir)
    liveness = state_dir_s + "/" + LIVENESS_FILE_NAME
    state_db = state_dir_s + "/firewall.sqlite3"
    return f"""#!/bin/sh
# BastionFW deadman rollback watchdog - generated by ed_bt_ade.rollback
# Deploy with a ROOT cron entry or systemd timer; see docs/OPERATIONS.md.
set -eu

STATE_DIR="{state_dir_s}"
LIVENESS_FILE="{liveness}"
STATE_DB="{state_db}"
ROLLBACK_SECONDS={int(rollback_seconds)}
LOCK_FILE="{state_dir_s}/rollback.lock"
LOG_FILE="{state_dir_s}/rollback.log"

log() {{
    printf '%s rollback: %s\\n' "$(date -u +%FT%TZ)" "$1" >> "$LOG_FILE" 2>/dev/null || :
}}

# Single-flight guard: overlapping cron runs must not double-execute.
if [ -e "$LOCK_FILE" ]; then
    exit 0
fi
trap 'rm -f "$LOCK_FILE"' EXIT
: > "$LOCK_FILE"

if [ ! -f "$LIVENESS_FILE" ]; then
    # No liveness file means the engine never started in this state dir:
    # nothing to guard, nothing to roll back.
    exit 0
fi

now=$(date +%s)
mtime=$(stat -c %Y "$LIVENESS_FILE" 2>/dev/null || true)
if [ -z "$mtime" ]; then
    log "cannot stat liveness file; skipping (fail-open: no destructive action)"
    exit 0
fi

age=$((now - mtime))
if [ "$age" -le "$ROLLBACK_SECONDS" ]; then
    exit 0
fi

log "deadman tripped (liveness age $age s > $ROLLBACK_SECONDS s); rolling back engine bans"

if command -v nft >/dev/null 2>&1; then
    nft list set inet ed_bt_ade blacklist 2>/dev/null \\
        | grep -oE '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' \\
        | sort -u \\
        | while IFS= read -r addr; do
            [ -n "$addr" ] || continue
            if nft delete element inet ed_bt_ade blacklist "{{ $addr }}" 2>/dev/null; then
                log "unblocked $addr (nftables)"
            else
                log "nftables unblock failed for $addr"
            fi
        done
fi

if command -v iptables >/dev/null 2>&1; then
    iptables -S INPUT 2>/dev/null \\
        | sed -n 's/^-A INPUT -s \\([0-9.]\\{{1,3}}\\(\\.[0-9]\\{{1,3}}\\)\\{{3}}\\) .*-j DROP$/\\1/p' \\
        | sort -u \\
        | while IFS= read -r addr; do
            [ -n "$addr" ] || continue
            if iptables -D INPUT -s "$addr" -j DROP 2>/dev/null; then
                log "unblocked $addr (iptables)"
            else
                log "iptables unblock failed for $addr"
            fi
        done
fi

rm -f "$LIVENESS_FILE"
log "rollback complete"
"""


def provision_rollback_script(path: Path, state_dir: Path,
                              rollback_seconds: int) -> Path:
    """Write the deadman script once and return its path.

    Written with 0700 permissions so only root can read or execute it. The
    liveness file itself is created by the engine at startup, never here.
    """
    destination = Path(path)
    if destination.exists():
        return destination
    document = build_deadman_script(state_dir, rollback_seconds)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(document)
        os.chmod(destination, 0o700)
    except OSError as exc:
        raise RuntimeError(f"cannot provision rollback script {destination}: {exc}") from exc
    return destination


class RollbackCoordinator:
    """Owns graceful-shutdown rollback of every engine-owned ban."""

    def __init__(self, firewall: FirewallOrchestrator) -> None:
        self.firewall = firewall

    async def rollback_all_bans(self) -> int:
        """Remove every engine-owned ban; return how many were removed."""
        removed = 0
        try:
            while True:
                count = await self.firewall.unblock_expired()
                if count == 0:
                    break
                removed += count
        except Exception:
            # Rollback is best-effort; a failing driver must not hang shutdown.
            LOGGER.exception("shutdown rollback hit an error; state may remain",
                             extra={"event": "rollback_error"})
        return removed
