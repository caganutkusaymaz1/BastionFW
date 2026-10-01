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

## Dashboard session cookie (`Secure` flag)

`POST /api/login` sets the `bastionfw_session` cookie with
`HttpOnly; Secure; SameSite=Strict`. `Secure` means a conforming browser only
stores and resends the cookie over HTTPS. On a plain-HTTP dashboard (for
example a loopback-only `http://127.0.0.1:8080`) the browser therefore **drops
the cookie after login**, and the next request arrives unauthenticated. This
is deliberate fail-safe behavior; do not remove the flag to work around it.

Supported options:

1. **Terminate TLS in front of the dashboard** (recommended for any
   network-exposed deployment). The cookie then travels over HTTPS as intended.
2. **On a trusted loopback-only host**, skip the cookie flow and authenticate
   every request with `Authorization: Bearer $ED_BT_ADE_DASHBOARD_TOKEN`.

Verify the flag is present:

```bash
curl -si -X POST http://127.0.0.1:8080/api/login \
  -H "Authorization: Bearer $ED_BT_ADE_DASHBOARD_TOKEN" | grep -i set-cookie
# Set-Cookie: bastionfw_session=...; HttpOnly; Secure; Max-Age=...; Path=/; SameSite=Strict
```

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
```Exercises parser-level end-to-end flow (valid audit line → detection →
  deny-list update → expiry removal) plus the `WAF_MODE` detect/block
  contract, without requiring a running WAF container.

## WAF image verification (why `waf` is built, not `image:`)

**The image the repository previously referenced does not exist.**
`corazawaf/coraza-caddy:v2` is not published on Docker Hub — the registry API
returns `object not found` for that repository, and `docker build` fails with
`pull access denied for corazawaf/coraza-caddy`. The Composer `waf` service
using `image: corazawaf/coraza-caddy:v2` could therefore never have started.

Upstream reality: the OWASP Coraza Caddy module
(`github.com/corazawaf/coraza-caddy/v2`) is distributed **as a Go plugin**, not
as a published image. Its only bundled Dockerfile
(`example/Dockerfile`) builds a local image from an xcaddy-compiled binary and
bakes a **static** example Caddyfile that exposes **no** `UPSTREAM_URL` or
`WAF_MODE` handling; the example hardcodes `:8080`, `SecRuleEngine On`, and an
audit path under `/home/coraza/logs`.

BastionFW therefore builds Caddy with the Coraza plugin from source using
Caddy's official builder image, and the `waf` Compose service is built from
`deploy/waf/` (`build: context: ./deploy/waf`, image tag `bastionfw-waf:local`)
instead of a non-existent stock image. Our layer:

- maps `WAF_MODE=detect` → `SecRuleEngine DetectionOnly` and
  `WAF_MODE=block` → `SecRuleEngine On`; any other value aborts startup
  (`deploy/waf/entrypoint.sh`);
- reverse-proxies `UPSTREAM_URL` (default `http://app:3000`);
- loads OWASP CRS with `load_owasp_crs` (rules are compiled into the binary);
- writes Coraza JSON audit events to `/var/log/waf/audit.json`, the shared
  `waf-audit` volume the engine reads **read-only**.

Evidence: <https://github.com/corazawaf/coraza-caddy> — plugin syntax is a
`coraza_waf { ... }` block inside a Caddyfile, with `load_owasp_crs` required
for the bundled `@`-prefixed CRS paths. There is no environment-variable
configuration path in the module.

### Block-mode verification

With `WAF_MODE=block` the WAF must return **403** for an obvious SQLi probe:

```bash
docker compose up -d --build waf
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:${WAF_PORT:-8081}/?id=1' OR '1'='1"
```

In `WAF_MODE=detect` the same request returns the upstream status (200) and a
`coraza` entry appears in `/var/log/waf/audit.json` instead.

A self-contained script that builds the image, deploys it against a throwaway
upstream, and asserts both modes (then tears everything down) is available:

```bash
sh ./deploy/waf/verify-block-mode.sh
# [waf-verify] block  benign=200  sqli=403
# [waf-verify] detect sqli=200 (expected upstream 200)
# [waf-verify] PASS: block=403, detect=200
```

Last verified on 2026-10-01 against Caddy 2.11.4 + OWASP CRS 4.25.0: the SQLi
probe returned `403` (with `X-Blocked: true`) in block mode and `200` in detect
mode, and the real audit entry (CRS rule 949110, `Inbound Anomaly Score
Exceeded`) was written to `/var/log/waf/audit.json`.

### WAF audit → engine feedback loop

The engine ingests Coraza audit JSON (`log_sources[].source_type =
"coraza_audit"`) and a confirmed OWASP CRS match drives the L3/L4 ban loop:

| Audit record | Parsed as | Bans? |
|---|---|---|
| CRS rule ids + anomaly score ≥ 5 | `coraza_waf_match`, severity `high` | yes |
| CRS rule ids, anomaly score 1–4 | `coraza_waf_match`, severity `medium` | no — alert only |
| no rule ids parsed | `coraza_audit`, severity `low` | no — alert only |

Native CRS audit JSON carries no structured `rule_id` / `anomaly_score` fields;
both are extracted from the bounded `messages[].error_message` audit text (CRS
threshold of 5 is the "critical" boundary). Request content (uri, headers,
body) is **never** scanned for this, so a crafted request cannot inject a fake
rule id or inflate the score that drives the ban decision.

> **Operator caveat — client address fidelity.** The banned address comes from
> `transaction.client_ip`. If the WAF sits behind another reverse proxy or CDN,
> that field can be the *proxy's* address. BastionFW's safety policy still
> refuses private/loopback/reserved addresses, but a **public** front-end proxy
> or CDN egress address would be ban-able. Add every front-end proxy/CDN egress
> address to `firewall.whitelist` before setting `firewall.enabled=true`.

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
