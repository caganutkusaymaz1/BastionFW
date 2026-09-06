#!/bin/sh
# End-to-end WAF integration smoke test.
#
# Validates the full L7 pipeline without Docker: a realistic Coraza audit
# line is parsed, evaluated through the ban loop, mirrored into the WAF
# deny-list, and finally removed by purge. Run from the repository root or
# the bastionfw/ directory:
#
#   bash tests/integration/test_waf_smoke.sh
#
set -eu

cd "$(dirname "$0")/../.."

echo "[waf-smoke] 1/4 parsing Coraza audit line"
python3 - <<'PY'
import json
from ed_bt_ade.parsing import parse_coraza_audit_line

line = json.dumps({
    "transaction": {"client_ip": "8.8.4.4", "uri": "/?q=1 UNION SELECT"},
    "messages": [{"rule_ids": ["942100"]}],
    "anomaly_score": 7,
})
detection = parse_coraza_audit_line(line)
assert detection is not None, "parser returned None for a valid audit line"
assert detection.ip == "8.8.4.4", detection.ip
assert detection.source == "coraza_audit"
print("parsed:", detection.rule, detection.ip, detection.severity)
PY

echo "[waf-smoke] 2/4 enforcing through the ban loop (mock driver)"
python3 - <<'PY'
import asyncio
import json
import tempfile
from pathlib import Path

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.parsing import parse_coraza_audit_line
from ed_bt_ade.waf_reputation import (
    DENYLIST_FILE_NAME,
    FileWafReputationDriver,
    MockWafReputationDriver,
)


class _NoopDriver(FirewallDriver):
    async def block(self, address: str) -> None:
        return None

    async def unblock(self, address: str) -> None:
        return None


async def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        waf = MockWafReputationDriver()
        file_waf = FileWafReputationDriver(root)
        fw = FirewallOrchestrator(
            FirewallConfig(state_db=root / "fw.db"),
            driver=_NoopDriver(), waf_driver=file_waf)
        detection = parse_coraza_audit_line(json.dumps({
            "client_ip": "8.8.4.4", "anomaly_score": 9}))
        assert detection is not None
        blocked = await fw.block(detection.ip)
        assert blocked, "orchestrator refused a public test address"
        assert file_waf.snapshot() == ("8.8.4.4",), file_waf.snapshot()
        document = json.loads((root / DENYLIST_FILE_NAME).read_text())
        assert document["addresses"] == ["8.8.4.4"]
        fw._db.execute("UPDATE bans SET expires_at = 1")
        fw._db.commit()
        removed = await fw.unblock_expired()
        assert removed == 1, removed
        assert file_waf.snapshot() == (), "deny-list not drained on expiry"
        fw.close()
        print("enforced L3/L4 + L7 deny-list, expiry drained both layers")


asyncio.run(main())
PY

echo "[waf-smoke] 3/4 hostile input stays inert"
python3 - <<'PY'
from ed_bt_ade.parsing import parse_coraza_audit_line

assert parse_coraza_audit_line("not json at all") is None
assert parse_coraza_audit_line(
    '{"client_ip": "8.8.8.8; rm -rf /", "anomaly_score": 9}') is None
print("hostile audit lines rejected without side effects")
PY

echo "[waf-smoke] 4/4 deadman fail-open monitor"
python3 - <<'PY'
import asyncio

from ed_bt_ade.waf_reputation import MockWafReputationDriver, WafDeadmanSwitch


async def main() -> None:
    waf = MockWafReputationDriver()
    await waf.add("8.8.4.4")
    deadman = WafDeadmanSwitch(waf, max_unhealthy_seconds=1)
    assert not deadman.report_health(False, now=0)
    assert deadman.report_health(False, now=1)
    await deadman.trip()
    assert waf.cleared == 1
    print("WAF deadman tripped and cleared the deny-list (fail-open)")


asyncio.run(main())
PY

echo "[waf-smoke] PASS"
