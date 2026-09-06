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
- JSON logs, Prometheus text metrics, `/healthz`, and graceful shutdown.

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

The Coraza WAF hybrid (audit-log ingestion, dynamic deny-list,
`WafDeadmanSwitch` fail-open) is documented in the repository root
(`THREAT_MODEL.md`, `docs/OPERATIONS.md`). Operations procedure for the
detect → block promotion lives in `docs/OPERATIONS.md`. This package has
not been independently audited; see the root README "Security Posture"
section for exactly what is and is not verified.

The command argument shapes in `firewall.py` are intentionally conservative
and should be validated against the organization's existing firewall ruleset
before enabling enforcement. In particular, use dedicated nftables/iptables
sets in production rather than changing a default chain ad hoc.

## Extension points

Implement `DetectionRule` for additional rules, `FirewallDriver` for a
site-specific set-based firewall integration, or replace the HTTP threat
intelligence request with a provider adapter. Keep external calls out of the
ingestion loop and preserve the `None`/degraded behavior on provider failure.