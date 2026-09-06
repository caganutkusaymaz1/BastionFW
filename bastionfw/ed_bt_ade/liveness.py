"""Liveness heartbeat shared by the engine and the external watchdog.

This module is the single source of truth for the liveness file that
independent watchdog processes inspect:

- The engine (``Sentinel``/``DeadmanSwitch``) refreshes the file while its
  event loop is healthy (see ``DeadmanSwitch``).
- The standalone watchdog command (``python -m ed_bt_ade.liveness``) or a
  cron/systemd timer checks the file's age and enforces operator policy
  (alert and/or run a rollback hook) when the engine stops renewing.

The watchdog deliberately has no BastionFW runtime dependencies beyond this
module so it can run in a minimal root context without the engine installed
as a package.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import time

LOGGER = logging.getLogger("bastionfw.liveness")

LIVENESS_FILE_NAME = "deadman.liveness"


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


def run_watchdog(state_dir: Path, max_age_seconds: int,
                 on_expired=None) -> str:
    """One watchdog pass; returns a human-readable decision string.

    ``on_expired`` is an optional callable invoked exactly once when the
    liveness age exceeds ``max_age_seconds`` (deployments wire their own
    rollback hook here — for example the generated deadman script).
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
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    decision = run_watchdog(Path(args.state_dir), args.max_age)
    LOGGER.info("watchdog decision: %s", decision,
                extra={"event": "watchdog_decision"})
    # Exit 0 in every non-error case so timer/cron deployments do not email
    # on healthy and missing states; alerting happens through on_expired.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
