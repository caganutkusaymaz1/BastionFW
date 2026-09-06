# BastionFW Operations Guide

**Developer:** Cagan Utku Saymaz

## 1. Installation

Python 3.11 or newer is required on a Linux host. There are no package dependencies.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m unittest discover -s tests -v
```

The service account must be able to read the configured log files. The state
directory must be writable only by the service account.

## 2. First Run: Staging/Dry-Run

```bash
mkdir -p staging-logs state
: > staging-logs/auth.log
python -m ed_bt_ade.sentinel --config config.staging.json
```

Generate test events from another terminal:

```bash
for n in 1 2 3; do
  echo "Failed password for root from 203.0.113.10" >> staging-logs/auth.log
done
curl -fsS http://127.0.0.1:19109/healthz
curl -fsS http://127.0.0.1:19109/metrics
```

`203.0.113.0/24` is reserved for documentation and should be used for staging
tests instead of simulating traffic from real attackers.

## 3. Production Firewall Enablement

1. Observe dry-run metrics and detection rates for at least 24 hours.
2. Add management IP addresses and CIDRs to the whitelist.
3. Pin `backend` to a driver actually available on the host.
4. Manually verify the firewall's existing ruleset or set structure.
5. Run a limited staging test with a short `ban_seconds` value.
6. Only then set `firewall.enabled=true`.

Loopback, RFC1918, link-local, reserved, and whitelisted addresses are rejected
at the code level. The whitelist is not a replacement for network access policy;
host firewall rules and out-of-band access must also be verified.

## 4. Threat Intelligence and Webhooks

Threat intelligence is disabled by default. Configure the provider URL through
`threat_intel.abuseipdb_url`. Do not write API keys to configuration files.
Use a secret manager for provider credentials in production.

Webhook URLs are grouped by severity under `alerting.webhooks`. The dispatcher
sends batches, applies rate limiting, and keeps external-service failures out of
the main ingestion pipeline.

## 5. systemd

Adapt `deploy/ed-bt-ade.service` to the host paths. Review the service account,
log read permissions, state directory, and required firewall capabilities
individually. Because `NoNewPrivileges` is used with `CAP_NET_ADMIN`, one of
these settings may need to change according to the deployment policy.

## 6. Monitoring and Rollback

- `/healthz`: returns HTTP 200 when the service is ready.
- `/metrics`: exposes processed logs, detections, blocks, errors, and latest
  pipeline latency in Prometheus text format.
- JSON logs are written to stdout and can be routed to journald or a central
  log collector.
- For false positives, first disable enforcement with `firewall.enabled=false`,
  then adjust rule thresholds and the whitelist.

## 7. Distributed Architecture Boundary

This package is a host-local agent. For hundreds of hosts, use one agent per
host with a central event bus, centralized policy/configuration distribution,
mTLS identities, centralized deduplication, and fleet-level auditing. SQLite is
only for host-local ban and reputation-cache state; it must not be used for
central coordination.

## 8. Hybrid WAF Orientation

The full stack lives in the repository root `docker-compose.yml`:

- `waf` — Caddy + Coraza + OWASP CRS ingress (built from `deploy/waf/`).
  Client traffic enters here and is reverse-proxied to `UPSTREAM_URL`.
- `bastionfw` — engine, dashboard, and metrics. It tails the WAF's JSON audit
  log, mirrors bans onto the dynamic deny-list, and runs the deadman switch.

Shared volumes:

- `bastionfw-waf` → `/var/lib/bastionfw/waf` — `denylist.json` (state),
  `deny.caddy` (403 matcher include), `engine-mode.conf`, `fail-open.flag`.
- `bastionfw-waf-audit` → `/var/log/waf` — Coraza JSON audit log
  (`audit.json`); read-only inside the engine, written by the WAF.

Relevant metrics (`/metrics` or the dashboard `/api/status`):

- `waf_requests_blocked_total`, `waf_rule_matches_total{rule_id=...}`,
  `waf_fail_open_active`, `sentinel_ips_blocked_total`.

## 9. Safely Switching the WAF from Detect to Block

The engine and the WAF container each read their own variable — keep them in
sync (`ED_BT_ADE_WAF_MODE` for the engine, `WAF_MODE` for the container).

1. Observe the stack in `detect` for at least 24 hours. Watch the dashboard's
   WAF panel: rule-match counts, the top OWASP rule IDs, and the deny-list
   size. Confirm your application produces no legitimate traffic that matches
   CRS rules.
2. Validate enforcement in a low-risk window with a short ban window
   (`detection.coraza_block_score`, `firewall.ban_seconds`) and documentation
   IPs (`198.51.100.0/24`, `203.0.113.0/24`).
3. Add management networks to `firewall.whitelist` before enabling
   enforcement so operators can never be locked out.
4. Only after staging validation set `ED_BT_ADE_DRY_RUN=false` **and** opt the
   WAF into block mode:

   ```bash
   # .env
   ED_BT_ADE_DRY_RUN=false
   ED_BT_ADE_WAF_ENABLED=true
   ED_BT_ADE_WAF_MODE=block
   WAF_MODE=block
   ```

   ```bash
   docker compose up -d bastionfw waf
   ```

5. Verify: a CRS-matching request now returns HTTP 403 through the WAF and
   appears as an interrupted transaction in `audit.json`; the engine's
   dashboard shows `mode=ENFORCING` and `engine_mode=block`.

To revert, set both variables back to `detect` (or `ED_BT_ADE_DRY_RUN=true`)
and restart the two services.

## 10. Dynamic Deny-List Operations

When `ED_BT_ADE_WAF_ENABLED=true`, every ban is enforced twice: kernel rules
and the WAF deny-list. BastionFW rewrites `deny.caddy` and reloads Caddy
through its admin API (`waf.admin_url`, default `http://waf:2019`) — no
restart, no dropped traffic.

- Inspect the current deny-list:

  ```bash
  docker compose exec bastionfw sh -c \
    'python -c "import json,sys; d=json.load(open(\"/var/lib/bastionfw/waf/denylist.json\")); print(d)"' 2>/dev/null || \
  cat /var/lib/bastionfw/waf/denylist.json   # host path when bind-mounted
  ```

- Remove a single address (both layers):

  ```bash
  TOKEN="$(grep ED_BT_ADE_DASHBOARD_TOKEN .env | cut -d= -f2)"
  curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"action":"unban","ip":"198.51.100.10"}' \
    http://127.0.0.1:8080/api/bans
  ```

- Clear every active and expired ban instantly:

  ```bash
  docker compose exec bastionfw python -m ed_bt_ade.sentinel \
    --config /app/config.container.json --purge-all-bans
  ```

The Caddy admin API is unauthenticated by design and listens only inside the
Compose network; do not publish port 2019 to a host interface.

## 11. Deadman Switch and Fail-Open

The deadman switch (`rollback.py`) polls `waf.health_url` (the WAF's own HTTP
endpoint) every `waf.health_interval_seconds`. After
`waf.failure_threshold` consecutive failures it:

1. rewrites `engine-mode.conf` to `SecRuleEngine DetectionOnly` and reloads
   Caddy, so CRS stops blocking while the application stays reachable;
2. writes `fail-open.flag` for supervisors and flips `waf_fail_open_active`;
3. optionally runs `waf.rollback_command` (operator-provided).

Fail-open is sticky by design: after the WAF recovers, the engine *stays* in
detect mode and logs a warning. Restore block mode explicitly by reasserting
`ED_BT_ADE_WAF_MODE=block` / `WAF_MODE=block` and restarting `waf` — the
engine reasserts the configured mode at startup.

## 12. End-to-End Smoke Test

Static validation plus a full Compose-based end-to-end run:

```bash
bash tests/integration/test_waf_smoke.sh
bash tests/integration/test_waf_smoke.sh --run
```

The `--run` path builds the images, starts `bastionfw` + `waf` in detect mode,
sends a CRS-matching request, and asserts the audit line parses through
`parsing.parse_coraza_audit_line`; it then restarts the WAF in block mode and
asserts HTTP 403 before restoring the safe detect default.