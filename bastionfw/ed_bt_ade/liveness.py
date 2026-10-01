"""Python-native liveness watchdog and engine-domain rollback hook.

This module is the single source of truth for the liveness file that
independent watchdog processes inspect:

- The engine (``Sentinel``/``DeadmanSwitch``) refreshes the file while its
  event loop is healthy (see ``DeadmanSwitch``).
- The standalone command (``python -m ed_bt_ade.liveness --state-dir ...``),
  run from ``deploy/ed-bt-ade-liveness.{service,timer}``, checks the file's
  age and, on expiry, calls the real ``FirewallOrchestrator.purge_all()``
  through :func:`purge_engine_bans` and removes the liveness file.

How this differs from ``rollback.py``:
- ``rollback.py`` *generates a root POSIX-sh script* (``build_deadman_script``)
  whose only dependency is the ``nft``/``iptables`` binaries. That script is
  the deployment-independent default and also runs when Python is unavailable.
- ``liveness.py`` is the *Python-native* alternative: it reuses the engine's
  own ``purge_all()`` code path (same state DB and driver semantics), so it can
  run on hosts where Python is available and the sh script was never
  provisioned. Install **one** of the two watchdogs, not both.

The module avoids importing ``firewall``/``config`` at import time (the import
happens lazily inside :func:`purge_engine_bans`) so it can start in a minimal
root context.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import time

LOGGER = logging.getLogger("bastionfw.liveness")

LIVENESS_FILE_NAME = "deadman.liveness"
FIREWALL_DB_NAME = "firewall.sqlite3"


def liveness_file(state_dir: Path) -> Path:
    return state_dir / LIVENESS_FILE_NAME


def liveness_age_seconds(state_dir: Path) -> int | None:
    """Return the liveness file's age in seconds, or ``None`` if unreadable.

    ``None`` is also returned when the file does not exist; callers treat a
    missing file as "engine never ran in this state directory" and must stay
    fail-open (no destructive action).
    """
    path = liveness_file(state_dir)
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return None
    except OSError:
        return None
    return int(time.time() - mtime)


def refresh_liveness(state_dir: Path) -> None:
    """Create or refresh the liveness file (engine side)."""
    path = liveness_file(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a"):
        pass
    import os

    os.utime(path, None)


def purge_engine_bans(state_dir: Path, *, enabled: bool = True,
                      driver=None) -> int:
    """Remove every engine-owned ban via the engine's own purge path.

    Builds a :class:`FirewallOrchestrator` over the state DB in ``state_dir``
    and calls ``purge_all()`` — the same code path as the operator
    ``--purge-all-bans`` panic switch, including driver error handling. A
    missing state DB means the engine never recorded bans here, so this is a
    no-op returning ``0``. ``enabled`` defaults to true because this runs as a
    root watchdog; pass ``driver`` in tests to avoid touching the OS.
    """
    from .config import FirewallConfig
    from .firewall import FirewallOrchestrator

    state_db = Path(state_dir) / FIREWALL_DB_NAME
    if not state_db.exists():
        return 0
    config = FirewallConfig(enabled=enabled, backend="auto", state_db=state_db)
    firewall = FirewallOrchestrator(config, driver=driver)
    try:
        return asyncio.run(firewall.purge_all())
    finally:
        firewall.close()


def build_expiry_hook(state_dir: Path, *, enabled: bool = True, driver=None):
    """Return the real on-expiry callback used by the CLI watchdog.

    Unlike an empty callback, this purges all engine-owned bans and then
    removes the liveness file so a later timer pass does not re-fire.
    """
    state = Path(state_dir)

    def _on_expired() -> None:
        removed = purge_engine_bans(state, enabled=enabled, driver=driver)
        LOGGER.warning(
            "liveness watchdog purged %d engine-owned ban(s)",
            removed,
            extra={"event": "liveness_purge", "removed": removed})
        try:
            liveness_file(state).unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best effort cleanup
            pass

    return _on_expired


def run_watchdog(state_dir: Path, max_age_seconds: int,
                 on_expired=None) -> str:
    """One watchdog pass; returns a human-readable decision string.

    ``on_expired`` is an optional callable invoked exactly once when the
    liveness age exceeds ``max_age_seconds`` (the CLI wires
    :func:`build_expiry_hook` here).
    """
    age = liveness_age_seconds(state_dir)
    if age is None:
        return "missing"
    if age <= max_age_seconds:
        return "healthy"
    LOGGER.warning(
        "liveness expired: age %ds exceeds max %ds",
        age, max_age_seconds,
        extra={"event": "liveness_expired", "age_seconds": age})
    if on_expired is not None:
        on_expired()
    return "expired"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True,
                        help="engine state directory containing the liveness file")
    parser.add_argument("--max-age", type=int, default=120,
                        help="maximum tolerated liveness age in seconds")
    parser.add_argument("--no-purge", action="store_true",
                        help="report expiry only; do not purge engine bans")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    state_dir = Path(args.state_dir)
    # Wire the real rollback: on expiry, purge all engine-owned bans via the
    # engine's own code path (not an empty callback).
    hook = None if args.no_purge else build_expiry_hook(state_dir)
    decision = run_watchdog(state_dir, args.max_age, on_expired=hook)
    LOGGER.info("watchdog decision: %s", decision,
                extra={"event": "watchdog_decision"})
    # Exit 0 in every non-error case so timer/cron deployments do not email
    # on healthy and missing states; alerting happens through on_expired.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
