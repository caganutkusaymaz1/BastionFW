"""Tests for scripts/provision-nftables.sh.

Runs the provisioning script against a stubbed ``nft`` so the object model
and idempotency can be verified without root or a live nftables subsystem.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bastionfw" / "scripts" / "provision-nftables.sh"

_FAKE_NFT = """#!/bin/sh
# Minimal nft stand-in: records calls and models table/set/chain/rule state.
STATE="${NFT_STATE:?}"
mkdir -p "$STATE"
printf '%s\\n' "$*" >> "$STATE/calls"
sub="$1"
case "$sub" in
  list)
    kind="$2"
    [ -f "$STATE/$kind" ] || exit 1
    if [ "$kind" = "chain" ] && [ -f "$STATE/rule" ]; then
      echo "ip saddr @blacklist drop"
    fi
    exit 0
    ;;
  add)
    kind="$2"
    : > "$STATE/$kind"
    exit 0
    ;;
esac
exit 0
"""

_FAKE_ID = """#!/bin/sh
echo 0
"""


@unittest.skipUnless(SCRIPT.is_file(), "provision-nftables.sh not present")
class ProvisionNftablesTests(unittest.TestCase):
    def _run(self, state: Path, stub_dir: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"
        env["NFT_STATE"] = str(state / "nft-state")
        return subprocess.run(
            ["sh", str(SCRIPT)], capture_output=True, text=True, env=env, check=False)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.state = root / "state"
        self.state.mkdir()
        self.stub_dir = root / "bin"
        self.stub_dir.mkdir()
        nft = self.stub_dir / "nft"
        nft.write_text(_FAKE_NFT, encoding="utf-8")
        nft.chmod(nft.stat().st_mode | stat.S_IEXEC)
        id_stub = self.stub_dir / "id"
        id_stub.write_text(_FAKE_ID, encoding="utf-8")
        id_stub.chmod(id_stub.stat().st_mode | stat.S_IEXEC)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_creates_table_set_chain_and_rule(self) -> None:
        result = self._run(self.state, self.stub_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.state / "nft-state" / "calls").read_text(encoding="utf-8")
        self.assertIn("add table inet ed_bt_ade", calls)
        self.assertIn("add set inet ed_bt_ade blacklist", calls)
        self.assertIn("add chain inet ed_bt_ade input", calls)
        self.assertIn("add rule inet ed_bt_ade input ip saddr @blacklist drop", calls)

    def test_second_run_is_idempotent(self) -> None:
        first = self._run(self.state, self.stub_dir)
        self.assertEqual(first.returncode, 0, first.stderr)
        calls_path = self.state / "nft-state" / "calls"
        calls_path.write_text("", encoding="utf-8")
        second = self._run(self.state, self.stub_dir)
        self.assertEqual(second.returncode, 0, second.stderr)
        calls = calls_path.read_text(encoding="utf-8")
        # No object may be re-created on the second pass.
        self.assertNotIn("add table", calls)
        self.assertNotIn("add set", calls)
        self.assertNotIn("add chain", calls)
        self.assertNotIn("add rule", calls)

    def test_requires_root(self) -> None:
        # Point PATH at a stub that reports a non-root uid.
        non_root = self.stub_dir.parent / "nonroot"
        non_root.mkdir()
        shutil.copy(self.stub_dir / "nft", non_root / "nft")
        (non_root / "id").write_text("#!/bin/sh\necho 1000\n", encoding="utf-8")
        (non_root / "id").chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = f"{non_root}:{env.get('PATH', '')}"
        env["NFT_STATE"] = str(self.state / "nft-state")
        result = subprocess.run(
            ["sh", str(SCRIPT)], capture_output=True, text=True, env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stderr)


if __name__ == "__main__":
    unittest.main()
