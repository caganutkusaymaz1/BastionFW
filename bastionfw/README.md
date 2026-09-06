# BastionFW v3.0

**Developer:** Cagan Utku Saymaz

BastionFW is a defensive, modular log analyzer and active-defense
orchestrator for Linux hosts. The first implementation is intentionally
dependency-light and safe by default:

- asynchronous inode-aware log tailing with rotation/truncation handling;
- bounded queue backpressure and isolated source tasks;
- pluggable SSH, web-attack, and privilege-anomaly detection rules;
- TTL LRU + SQLite threat-intelligence cache;
- token bucket rate limiting, retries, and a circuit breaker;
- persistent temporary bans with strict public-IPv4 safety checks;
- dry-run firewall behavior by default;
- JSON logs, Prometheus text metrics, `/healthz`, and graceful shutdown;
- Coraza WAF JSON audit-log parsing (`source_type: "coraza_audit"`) that
  binds CRS anomaly scores and rule IDs into native detections;
- bidirectional enforcement: every L3/L4 ban is mirrored to the Coraza dynamic
  deny-list (`waf_reputation.py`) and removed from both layers on expiry;
- a WAF deadman switch (`rollback.py`) that fails open to detect mode when the
  WAF goes unhealthy;
- authenticated dashboard/API (`ED_BT_ADE_DASHBOARD_TOKEN`) with loopback-only
  fail-safe binding.

## Hybrid WAF + IPS architecture

BastionFW closes a bidirectional feedback loop with the Coraza WAF ingress:

```
[Client traffic] --> Coraza WAF (Caddy + OWASP CRS)
                        |  (JSON audit log, L7 detection)
                        v
                   BastionFW tailer --> score & IP reputation
                        |
     +------------------+------------------+
     |                                     |
     v                                     v
  L7 dynamic deny-list               L3/L4 kernel ban
  (403 at the HTTP layer)            (nftables/iptables)
     |                                     |
     +--------------+----------------------+
                    v
        Deadman switch / rollback
        (fail-open to detect, expiry cleanup)
```

- The WAF service definition, Caddyfile, and pinned Dockerfile live in the
  repository-root `deploy/waf/`; the root `docker-compose.yml` runs the full
  stack. `WAF_MODE=detect` (default) is audit-only; `WAF_MODE=block` is an
  explicit opt-in.
- Coraza audit lines are validated with `validation.parse_ip()` and turned
  into native `Detection` records (`parsing.parse_coraza_audit_line` +
  `detector.CorazaAuditRule`); see the smoke test fixture in
  `tests/integration/test_waf_smoke.sh` for the exact schema.
- The WAF section of the configuration (`waf.*`) controls the deny-list
  driver and the deadman switch. It stays disabled until the stack has been
  validated in staging.

## Run

```bash
python -m unittest discover -s tests -v
python -m ed_bt_ade.sentinel --config config.example.json
```

Safe first-run steps for new operators are in `KULLANIM-KILAVUZU.md`. The
quickest demo is:

```bash
bash run_dashboard.sh
```

Generate sample events from another terminal:

```bash
bash demo-events.sh
```

Copy `config.example.json` to a host-specific file before deployment, or use
`config.production.example.json` with the provided systemd unit. Set
`firewall.enabled` to `true` only after validating the driver and whitelist in
a staging environment. `ED_BT_ADE_DRY_RUN=true` always forces dry-run mode.
`deploy/ed-bt-ade.service` is a hardened starting point for a Linux systemd
deployment; review filesystem permissions, capabilities, and log paths with
the host administrator before installing it.

The internal Python package and environment variable prefix retain the
`ed_bt_ade`/`ED_BT_ADE` names for compatibility with the v3 implementation.

## Design boundaries

This package does not claim that one process on one host is itself a
distributed control plane. For a multi-host deployment, run one local agent
per server and place a durable event bus, centrally managed policy, identity
and certificate rotation, and fleet-level deduplication around it. The local
agent keeps ingestion independent from threat-intelligence outages and uses
SQLite only for local durable state.

The command argument shapes in `firewall.py` are intentionally conservative
and should be validated against the organization's existing firewall ruleset
before enabling enforcement. In particular, use dedicated nftables/iptables
sets in production rather than changing a default chain ad hoc.

## Extension points

Implement `DetectionRule` for additional rules, `FirewallDriver` for a
site-specific set-based firewall integration, or replace the HTTP threat
intelligence request with a provider adapter. Keep external calls out of the
ingestion loop and preserve the `None`/degraded behavior on provider failure.