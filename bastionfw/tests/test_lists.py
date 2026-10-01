"""Tests for the bulk ban-list import/export CLI (ed_bt_ade.lists)."""

import asyncio
import csv
import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.lists import export_bans, import_bans, main, read_entries


class _RecordingDriver(FirewallDriver):
    def __init__(self) -> None:
        self.unblocked: list[str] = []

    async def block(self, address: str) -> None:
        return None

    async def unblock(self, address: str) -> None:
        self.unblocked.append(address)


def _orchestrator(directory: str) -> FirewallOrchestrator:
    return FirewallOrchestrator(
        FirewallConfig(state_db=Path(directory) / "firewall.sqlite3"),
        driver=_RecordingDriver())


class ListExportTests(unittest.TestCase):
    def test_csv_export_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            firewall = _orchestrator(directory)
            asyncio.run(firewall.block("8.8.8.8"))
            asyncio.run(firewall.block("9.9.9.9"))
            target = Path(directory) / "bans.csv"
            self.assertEqual(export_bans(firewall, target, "csv"), 2)
            with target.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], ["address", "expires_at"])
            self.assertEqual(sorted(row[0] for row in rows[1:]),
                             ["8.8.8.8", "9.9.9.9"])
            self.assertEqual(sorted(read_entries(target, "csv")),
                             ["8.8.8.8", "9.9.9.9"])
            firewall.close()

    def test_json_export_is_parseable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            firewall = _orchestrator(directory)
            asyncio.run(firewall.block("8.8.8.8"))
            target = Path(directory) / "bans.json"
            self.assertEqual(export_bans(firewall, target, "json"), 1)
            document = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(document["bans"][0]["address"], "8.8.8.8")
            self.assertEqual(read_entries(target, "json"), ["8.8.8.8"])
            firewall.close()


class ListImportTests(unittest.TestCase):
    def test_import_applies_policy_and_skips_bad_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "in.csv"
            source.write_text(
                "address,expires_at\n"
                "8.8.8.8,0\n"
                "10.0.0.1,0\n"          # private: rejected
                "127.0.0.1,0\n"         # loopback: rejected
                "8.8.8.8; rm -rf /,0\n"  # hostile: rejected
                "not-an-ip,0\n", encoding="utf-8")
            firewall = _orchestrator(directory)
            imported = asyncio.run(import_bans(firewall, source, "csv"))
            self.assertEqual(imported, 1)
            self.assertEqual([address for address, _ in firewall.snapshot_bans()],
                             ["8.8.8.8"])
            firewall.close()

    def test_cli_export_then_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_cfg = root / "source.json"
            source_cfg.write_text(json.dumps({
                "log_sources": [{"name": "t", "path": "/tmp/t.log"}],
                "firewall": {"backend": "dry-run",
                             "state_db": str(root / "source.db")},
            }), encoding="utf-8")
            # Seed a ban through the firewall, then export via the CLI.
            firewall = FirewallOrchestrator(
                FirewallConfig(backend="dry-run", state_db=root / "source.db"),
                driver=_RecordingDriver())
            asyncio.run(firewall.block("8.8.8.8"))
            firewall.close()
            exported = root / "bans.json"
            self.assertEqual(main(["-c", str(source_cfg), "export",
                                   "--format", "json", "--output", str(exported)]), 0)

            target_cfg = root / "target.json"
            target_cfg.write_text(json.dumps({
                "log_sources": [{"name": "t", "path": "/tmp/t.log"}],
                "firewall": {"backend": "dry-run",
                             "state_db": str(root / "target.db")},
            }), encoding="utf-8")
            self.assertEqual(main(["-c", str(target_cfg), "import",
                                   "--format", "json", "--input", str(exported)]), 0)
            target = FirewallOrchestrator(
                FirewallConfig(backend="dry-run", state_db=root / "target.db"),
                driver=_RecordingDriver())
            self.assertEqual([a for a, _ in target.snapshot_bans()], ["8.8.8.8"])
            target.close()


if __name__ == "__main__":
    unittest.main()
