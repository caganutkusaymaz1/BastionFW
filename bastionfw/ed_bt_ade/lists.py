"""Bulk ban-list import/export for operators (CSV / JSON).

Moves the engine's recorded ban list in and out of the host as a portable
document, so lists can be archived, migrated between hosts, or pre-seeded from
an external source:

    python -m ed_bt_ade.lists export --format csv  --output bans.csv
    python -m ed_bt_ade.lists export --format json --output bans.json
    python -m ed_bt_ade.lists import --format csv  --input bans.csv
    python -m ed_bt_ade.lists import --format json --input bans.json --duration 3600

Design notes:
- Everything routes through ``FirewallOrchestrator.block``, so the same safety
  policy applies as the live pipeline: only public, non-whitelisted IPv4
  addresses are imported; private/loopback/hostile entries are skipped and
  logged. Import never writes to the OS directly.
- Exports contain only engine-owned bans (the addresses the engine recorded).
- The active firewall backend from the loaded config is used as-is, so a
  dry-run config keeps imports dry-run.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import logging
from pathlib import Path
from typing import Iterable

from .config import load_config
from .firewall import FirewallOrchestrator

LOGGER = logging.getLogger("bastionfw.lists")

SUPPORTED_FORMATS = ("csv", "json")
CSV_HEADER = ("address", "expires_at")


def export_bans(firewall: FirewallOrchestrator, destination: Path,
                fmt: str = "csv") -> int:
    """Write every recorded ban to ``destination``; return the row count."""
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported format: {fmt}")
    rows = firewall.snapshot_bans()
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        document = {
            "version": 1,
            "bans": [{"address": address, "expires_at": expires_at}
                     for address, expires_at in rows],
        }
        target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    else:
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(CSV_HEADER)
            writer.writerows(rows)
    return len(rows)


def read_entries(source: Path, fmt: str = "csv") -> list[str]:
    """Parse addresses out of an exported CSV or JSON document."""
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported format: {fmt}")
    text = Path(source).read_text(encoding="utf-8")
    addresses: list[str] = []
    if fmt == "json":
        document = json.loads(text)
        items: Iterable = document.get("bans", []) if isinstance(document, dict) else document
        for item in items:
            if isinstance(item, dict):
                value = item.get("address")
            else:
                value = item
            if isinstance(value, str) and value.strip():
                addresses.append(value.strip())
    else:
        for row in csv.DictReader(io.StringIO(text)):
            value = (row.get("address") or "").strip()
            if value:
                addresses.append(value)
    return addresses


async def import_bans(firewall: FirewallOrchestrator, source: Path,
                      fmt: str = "csv", duration: int | None = None) -> int:
    """Block each address from ``source`` via the safety-checked path.

    Returns the number of *new* bans added. Addresses rejected by policy or
    already banned are skipped, never raising on a bad row.
    """
    imported = 0
    for value in read_entries(source, fmt):
        try:
            added = await firewall.block(value, duration=duration)
        except ValueError as exc:  # invalid duration or address shape
            LOGGER.warning("skipping import entry", extra={
                "event": "list_import_skipped", "ip": value, "reason": str(exc)})
            continue
        if added:
            imported += 1
        else:
            LOGGER.warning("import entry rejected by firewall policy", extra={
                "event": "list_import_rejected", "ip": value})
    return imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.example.json",
                        help="engine config used for firewall policy")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="write recorded bans to a file")
    export.add_argument("--format", choices=SUPPORTED_FORMATS, default="csv")
    export.add_argument("--output", required=True)

    load = sub.add_parser("import", help="block every address in a file")
    load.add_argument("--format", choices=SUPPORTED_FORMATS, default="csv")
    load.add_argument("--input", required=True)
    load.add_argument("--duration", type=int, default=None,
                      help="ban TTL in seconds (default: firewall.ban_seconds)")

    args = parser.parse_args(argv)
    config = load_config(Path(args.config))
    firewall = FirewallOrchestrator(config.firewall)
    try:
        if args.command == "export":
            count = export_bans(firewall, Path(args.output), args.format)
            print(f"exported {count} ban(s) to {args.output} ({args.format})")
        else:
            count = asyncio.run(import_bans(firewall, Path(args.input),
                                            args.format, args.duration))
            print(f"imported {count} new ban(s) from {args.input} ({args.format})")
    finally:
        firewall.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
