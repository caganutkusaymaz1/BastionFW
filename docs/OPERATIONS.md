# Operations Guide

This guide covers day-to-day operation of BastionFW with the Coraza WAF,
including the detect → block promotion procedure.

## Components

```
Client → Coraza WAF (Caddy) → application (UPSTREAM_URL)
              │ audit JSON
              ▼
        BastionFW engine (tailer → detection → reputation → enforcement)
              │                    │
              ▼                    ▼
     nftables/iptables ban    waf-denylist.json (L7)
              ▲                    ▲
              └── deadman watchdog ┘ (fail-open + rollback)
```

## Daily operations

- **Health:** `http://<host>:9109/healthz` (engine), WAF container health in
  `docker compose ps`.
- **Dashboard:** `http://<host>:8080`, authenticate via
  `POST /api/login` (bearer token → session cookie) or use
  `Authorization: Bearer $ED_BT_ADE_DASHBOARD_TOKEN` directly.
- **Metrics:** `http://<host>:9109/metrics` (Prometheus text format).
- **State:** all engine state lives in the `bastionfw-state` volume
  (`firewall.sqlite3`, `threat-intel.sqlite3`, `deadman.liveness`,
  `waf-denylist.json`).
- **Panic switch:** `python -m ed_bt_ade.sentinel --purge-all-bans` removes
  every active and expired ban from both enforcement layers immediately.

## Promoting the WAF from detect to block (safe procedure)

Default is `WAF_MODE=detect`: Coraza logs attacks but does not block.
Follow every step in order; do not skip the soak period.

1. **Prerequisites verified in staging:**
   - `ED_BT_ADE_DASHBOARD_TOKEN` set (dashboard authenticated);
   - rollback timer installed and observed firing
     (`deploy/ed-bt-ade-rollback.timer`, verify `rollback.log` in the state
     volume shows successful no-op or real passes);
   - whitelists reviewed: `firewall.whitelist` covers every operator IP,
     VPN concentrator, and monitoring probe.

2. **Detect-mode soak (≥ 1 week of representative traffic):**
   - Watch `waf.top_rule_ids` and engine alerts; tune CRS false positives
     against your application before enforcement is possible.
   - Confirm `parse_coraza_audit_line` sees your real traffic (engine log:
     `coraza_audit` source events).

3. **Enable the fail-open guard (always):** keep the engine running so
   `WafDeadmanSwitch` can clear the deny-list if the WAF goes unhealthy.
   The L3/L4 deadman watchdog must remain installed regardless of WAF mode.

4. **Switch to block:** in `.env` set `WAF_MODE=block`, then
   `docker compose up -d waf`. Roll out to one low-risk vhost first if your
   setup supports per-host configuration.

5. **Watch the first hour:** engine `pipeline_errors` metric, WAF
   `denied_requests_total`, and your application's error budget. Expect
   some residual false positives; tune rules rather than disabling the WAF.

6. **Rollback path (any time):** set `WAF_MODE=detect` and
   `docker compose up -d waf`. For the engine,
   `--purge-all-bans` clears L3/L4 and deny-list state without stopping
   ingestion.

## Deadman switch verification (quarterly drill)

1. Start the engine with `ED_BT_ADE_DRY_RUN=false` and one test ban.
2. Stop the engine with `docker compose stop bastionfw` (do **not** stop the
   timer).
3. Within `ED_BT_ADE_ROLLBACK_SECONDS` (default 120 s) the root watchdog
   must remove the test ban; verify in `rollback.log` and with
   `nft list set inet ed_bt_ade blacklist`.
4. Restart the engine (`docker compose start bastionfw`).

## WAF smoke test

```bash
bash tests/integration/test_waf_smoke.sh
```

Exercises parser-level end-to-end flow (valid audit line → detection →
deny-list update → expiry removal) without requiring a running WAF
container.

## Env var reference (security-relevant)

| Variable | Purpose |
|---|---|
| `ED_BT_ADE_DASHBOARD_TOKEN` | dashboard bearer token; unset ⇒ loopback-only bind |
| `ED_BT_ADE_ROLLBACK_SECONDS` | deadman rollback window (min 10, default 120) |
| `ED_BT_ADE_DRY_RUN` | `true` forces dry-run firewall mode |
| `WAF_MODE` | `detect` (default) or `block` (operator opt-in) |
| `UPSTREAM_URL` | application behind the WAF |
| `BASTIONFW_API_URL` / `BASTIONFW_API_TOKEN` | console proxy → engine dashboard |
| `ED_BT_ADE_ABUSEIPDB_KEY` | threat-intel API key (server-side only) |

Generate tokens with `openssl rand -hex 32`. Never commit `.env`.
