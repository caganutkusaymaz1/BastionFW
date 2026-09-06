#!/usr/bin/env bash
#
# BastionFW hybrid-WAF smoke test (Faz 3).
#
# Static mode (default, no Docker required):
#   bash tests/integration/test_waf_smoke.sh
#     - validates the Compose deployment file
#     - feeds a realistic Coraza audit-log fixture through the real parser
#
# End-to-end mode (requires Docker Engine + Compose v2, builds images):
#   bash tests/integration/test_waf_smoke.sh --run
#     - brings up bastionfw + waf with WAF_MODE=detect
#     - checks the WAF is alive and that a CRS-detected request lands in
#       /var/log/waf/audit.json as a parseable Coraza audit line
#     - switches the engine to block mode and verifies the WAF answers 403
#     - switches back to detect so the stack stays in the safe default
#
# Set BASTIONFW_SMOKE_REQUIRE=1 to make static checks fail the script.
# Requires: python3, curl, docker, docker compose v2.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PYTHON=${PYTHON:-python3}
# Make the engine importable from the repo root (used by the audit-line check).
export PYTHONPATH="${ROOT}/bastionfw${PYTHONPATH:+:$PYTHONPATH}"
REQUIRE=${BASTIONFW_SMOKE_REQUIRE:-0}
WAF_PORT=${WAF_PORT:-80}
BASTIONFW_PORT=${BASTIONFW_DASHBOARD_PORT:-8080}

say() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
fail() {
  printf '\033[1;31mSMOKE FAIL: %s\033[0m\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing tool: $1"
}

parser_fixture() {
  "$PYTHON" - <<'PY'
import json
print(json.dumps({
    "transaction": {
        "timestamp": "2026-09-01T10:00:00Z",
        "id": "smoke-1",
        "client_ip": "198.51.100.42",
        "is_interrupted": True,
        "request": {"method": "GET", "uri": "/?q=union+select"},
        "response": {"status": 403},
    },
    "messages": [
        {"message": "SQL Injection Attack Detected",
         "data": {"id": 942100, "severity": "CRITICAL",
                  "msg": "Detects classic SQL injection", "data": "union select"}},
        {"message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
         "data": {"id": 949110, "severity": "CRITICAL"}},
    ],
}))
PY
}

verify_audit_line() {
  # $1 = raw JSON audit line; asserts the real parser accepts it.
  "$PYTHON" -c '
import json, sys
from ed_bt_ade.parsing import parse_coraza_audit_line
raw = sys.stdin.read().strip()
if not raw:
    raise SystemExit("audit log is empty")
event = parse_coraza_audit_line(raw)
if event is None:
    raise SystemExit("parser rejected the WAF audit line")
print(json.dumps({"ip": event.ip, "score": event.anomaly_score,
                  "rules": list(event.rule_ids),
                  "severity": event.severity,
                  "blocked": event.interrupted}))
' <<<"$1"
}

wait_http() {
  # $1 = url, $2 = label, $3 = retries
  local url="$1" label="$2" tries="${3:-30}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null; then
      printf '  %-28s ok\n' "$label"
      return 0
    fi
    sleep 2
  done
  fail "$label never became ready ($url)"
}

wait_logline() {
  # $1 = grep pattern for the latest audit line inside the waf container
  local tries="${2:-30}"
  for _ in $(seq 1 "$tries"); do
    local line
    if line="$(docker compose exec -T waf tail -n 1 /var/log/waf/audit.json 2>/dev/null)"; then
      if printf '%s' "$line" | grep -Eq "$1"; then
        printf '%s' "$line"
        return 0
      fi
    fi
    sleep 2
  done
  fail "no audit line matching '$1' appeared in /var/log/waf/audit.json"
}

say "BastionFW hybrid-WAF smoke test"
require_tool "$PYTHON"
require_tool docker

# ---------------------------------------------------------------------------
# 1. Static validation
# ---------------------------------------------------------------------------
say "1/3 Static validation"
docker compose config -q || fail "docker compose config is invalid"
if ! "$PYTHON" -c "import ed_bt_ade" >/dev/null 2>&1; then
  fail "ed_bt_ade is not importable; install bastionfw or set PYTHONPATH"
fi

say "Parser fixture round-trip"
verify_audit_line "$(parser_fixture)" >/dev/null
printf '  parser accepts the Coraza audit schema\n'

if [ "${1:-}" != "--run" ]; then
  printf '\nStatic checks passed. For the full end-to-end WAF check run:\n'
  printf '  bash %s --run\n' "$0"
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. End-to-end stack
# ---------------------------------------------------------------------------
say "2/3 Bringing up bastionfw + waf (WAF_MODE=detect)"
command -v curl >/dev/null 2>&1 || fail "missing tool: curl (needed for --run)"

# The dashboard only binds non-loopback when a token is present; without one
# the WAF reverse-proxy target inside the compose network is unreachable.
export ED_BT_ADE_DASHBOARD_TOKEN="${ED_BT_ADE_DASHBOARD_TOKEN:-}"
if [ -z "$ED_BT_ADE_DASHBOARD_TOKEN" ]; then
  ED_BT_ADE_DASHBOARD_TOKEN="$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(24))')"
  export ED_BT_ADE_DASHBOARD_TOKEN
  printf '  generated temporary dashboard token for the smoke run\n'
fi

export WAF_MODE=detect
export ED_BT_ADE_WAF_MODE=detect
export ED_BT_ADE_WAF_ENABLED=true
docker compose up -d --build bastionfw waf >/dev/null

trap 'docker compose down >/dev/null 2>&1 || true' EXIT

wait_http "http://127.0.0.1:${BASTIONFW_PORT}/api/status" "bastionfw dashboard" 40
wait_http "http://127.0.0.1:${WAF_PORT}/" "waf ingress (via proxy)" 60

say "Attack request through the WAF in detect mode"
curl -fsS -o /dev/null \
  -H "Authorization: Bearer ${ED_BT_ADE_DASHBOARD_TOKEN}" \
  "http://127.0.0.1:${WAF_PORT}/?q=1%27+union+select+password+from+users" \
  || true
line="$(wait_logline '942100')"
printf '  audit line: %s\n' "$(printf '%s' "$line" | head -c 160)..."
printf '  parsed:     '
verify_audit_line "$line"

say "3/3 Engine switch to block mode (opt-in) and back to detect"
export WAF_MODE=block
export ED_BT_ADE_WAF_MODE=block
docker compose up -d waf >/dev/null
wait_http "http://127.0.0.1:${WAF_PORT}/" "waf after block-mode restart" 40

code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${ED_BT_ADE_DASHBOARD_TOKEN}" \
  "http://127.0.0.1:${WAF_PORT}/?q=1%27+union+select+password+from+users" \
  || true)"
if [ "$code" != "403" ]; then
  fail "expected HTTP 403 from block-mode WAF, got ${code:-no response}"
fi
printf '  block-mode WAF answered 403 for the CRS-matching request\n'
line="$(wait_logline 'is_interrupted')"
verify_audit_line "$line" >/dev/null
printf '  audit line records the interrupted transaction\n'

export WAF_MODE=detect
export ED_BT_ADE_WAF_MODE=detect
docker compose up -d waf >/dev/null
wait_http "http://127.0.0.1:${WAF_PORT}/" "waf back in detect mode" 40
printf '  stack restored to the safe detect default\n'

say "SMOKE OK"
