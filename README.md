# BastionFW Security Platform

**Developer:** Cagan Utku Saymaz

BastionFW is a defensive Linux security platform that fuses a **Coraza WAF**
(Go, OWASP CRS) with an **IPS/active-defense engine**. Instead of only watching
logs, it closes a bidirectional feedback loop: L7 detections from the WAF feed
IP reputation scoring, which drives enforcement on two layers at once —
L3/L4 kernel rules (nftables/iptables) **and** an L7 dynamic deny-list applied
by the WAF itself — with a deadman switch that fails open if the WAF goes
unhealthy.

```
                    BI-DIRECTIONAL FEEDBACK LOOP
                        (hybrid WAF + IPS)
                                                                        
     [ Client traffic ]                                                  
            │                                                            
            ▼                                                            
   ┌────────────────────┐   (L7 detection / JSON audit log)   ┌─────────────────────────────┐
   │  Coraza WAF (Caddy) │ ──────────────────────────────────> │ BastionFW Tailer Engine     │
   │    (OWASP CRS)      │                                     └─────────────┬───────────────┘
   └─────────▲───────────┘                                                 │
             │                                                              ▼
             │  (L7 dynamic deny-list)                    ┌─────────────────────────────┐
             └──────────────────────────────────────────── │ BastionFW Orchestrator      │
                                                           │ (score & IP reputation)     │
   ┌──────────────────────────────────────────────────────┐ └─────────────┬───────────────┘
   │  (L3/L4 nftables/iptables ban)                       │               │
   │                                                      ▼               ▼
   │   ┌────────────────────┐             ┌─────────────────────────────┐
   │   │  Linux OS Kernel   │             │   Deadman Switch Loop       │
   │   │ (Netfilter engine) │             │   (auto-rollback safety)    │
   │   └────────────────────┘             └─────────────────────────────┘
   └──────────────────────────────────────────────────────────────────────┘
```

**The loop**

1. **Detect (L7)** — Coraza filters every HTTP request with OWASP CRS and
   appends one JSON line per matched transaction to `/var/log/waf/audit.json`.
2. **Correlate & score** — the BastionFW tailer reads the line immediately,
   validates the client IP (`validation.parse_ip`), and updates the threat
   score with the transaction's anomaly score and rule IDs.
3. **Enforce (both layers)** — when the score clears the configured threshold,
   BastionFW bans the IP simultaneously at L3/L4 (kernel firewall) and writes
   it into the Coraza dynamic deny-list file (403 at the HTTP layer even
   through proxies/CDNs).
4. **Safety & rollback** — when a ban expires, or the engine/WAF crashes, the
   deadman switch (`rollback.py`) clears rules from both layers safely and
   drops the WAF engine to detect mode (fail-open) so the application stays
   reachable.

## Quick start

Requirements:

- Docker Engine and Docker Compose v2
- A copy of `.env.example` saved as `.env`

```bash
cp .env.example .env
# 1) Generate a strong token and put it in .env:
#    python3 -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up --build
```

The default deployment is dry-run mode (the engine never changes the host
firewall) and the WAF runs in `WAF_MODE=detect` (audit-only). With
`ED_BT_ADE_DASHBOARD_TOKEN` set, the dashboard is available at
`http://127.0.0.1:8080` (token via `Authorization: Bearer` or a one-time
`/?token=...` cookie bootstrap) and readiness at `http://127.0.0.1:9109/healthz`.
Client traffic enters through the WAF at `http://127.0.0.1` (port from
`WAF_PORT`, default 80) and is reverse-proxied to `UPSTREAM_URL`.

```bash
docker compose down
```

## Configuration

The root Compose deployment uses `bastionfw/config.container.json` and
persists local state in the `bastionfw-state` volume. Host logs are mounted
read-only from `BASTIONFW_LOG_ROOT` (default: `/var/log`).

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `ED_BT_ADE_DRY_RUN` | `true` | Firewall enforcement off; set `false` only after staging validation. |
| `ED_BT_ADE_DASHBOARD_TOKEN` | *(empty)* | Dashboard/API bearer token. Empty ⇒ loopback-only bind (fail-safe). |
| `WAF_MODE` / `ED_BT_ADE_WAF_MODE` | `detect` | Coraza engine mode (`detect` audit-only, `block` opt-in). Keep both equal. |
| `ED_BT_ADE_WAF_ENABLED` | `false` | Enables the L7 dynamic deny-list + deadman switch. |
| `UPSTREAM_URL` | `http://bastionfw:8080` | Application behind the WAF (reverse-proxy target). |
| `WAF_PORT` | `80` | Published ingress port of the WAF. |

The WAF image is built in-repo from `deploy/waf/Dockerfile` (pinned
coraza-caddy v2.6.0 with embedded CRS) because no official
`corazawaf/coraza-caddy` image is published to Docker Hub. The engine never
touches the host firewall while `ED_BT_ADE_DRY_RUN=true`; the WAF stays in
detect mode until you explicitly opt into `WAF_MODE=block` (see
`docs/OPERATIONS.md` for the safe transition).

Never commit `.env` or place API keys in JSON configuration. Use a secret
manager or runtime environment injection for production credentials.

## Development

Python tests (engine):

```bash
cd bastionfw
python3 -m unittest discover -s tests -v
```

Hybrid-WAF smoke test (static checks, then optional full end-to-end):

```bash
bash tests/integration/test_waf_smoke.sh            # static + parser
bash tests/integration/test_waf_smoke.sh --run      # full compose stack
```

Workspace typechecking and builds require pnpm:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run build
```

CI (`ci.yml`) additionally runs `bandit -r ed_bt_ade -ll -q`,
`pnpm audit --audit-level=high`, and `gitleaks`; any finding turns the
pipeline red.

## Repository layout

- `bastionfw/`: Python engine — tailer, detector, firewall abstraction,
  WAF reputation driver, rollback/deadman, dashboard, configuration, tests.
- `deploy/waf/`: Coraza + OWASP CRS ingress (Dockerfile, Caddyfile,
  entrypoint).
- `artifacts/api-server/`: authenticated Express service that proxies the real
  engine data (no mocks).
- `artifacts/bastionfw-console/`: React/Vite operations console.
- `lib/`: API schema, generated clients, and database packages.
- `tests/integration/`: end-to-end WAF smoke test.
- `.github/workflows/ci.yml`: Python + TypeScript validation and security
  scans.

## Security boundary

The platform is host-local by design. Production enforcement requires a
reviewed firewall ruleset, explicit host capabilities, protected management
access, secret management, and environment-specific acceptance tests. See
`SECURITY.md` for the hardening guide, the fail-open/rollback contract, and
how to report vulnerabilities.
