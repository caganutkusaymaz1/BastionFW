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
4. Provision the nftables objects (see below) and verify the firewall's
   existing ruleset or set structure.
5. Run a limited staging test with a short `ban_seconds` value.
6. Only then set `firewall.enabled=true`.

### 3.1 Provisioning the nftables table/set/chain (nftables backend)

The `nftables` backend writes only into the engine-owned objects
`inet ed_bt_ade blacklist` (IP ban set) and `inet ed_bt_ade input` (drop
rule). Create them once with the idempotent helper before enabling
enforcement. It is safe to re-run:

```bash
sudo bash bastionfw/scripts/provision-nftables.sh
sudo nft list table inet ed_bt_ade    # shows table, set, chain and rule
```

Equivalent manual commands (what the script runs):

```bash
nft add table inet ed_bt_ade
nft add set inet ed_bt_ade blacklist '{ type ipv4_addr; flags interval; }'
nft add chain inet ed_bt_ade input '{ type filter hook input priority 0; }'
nft add rule inet ed_bt_ade input ip saddr @blacklist drop
```

These match `ed_bt_ade/firewall.py::NftablesDriver`, which issues
`nft add element inet ed_bt_ade blacklist { <ip> }` and
`nft delete element inet ed_bt_ade blacklist { <ip> }`. Only IPv4 addresses
are ever placed in `blacklist` (see § 8 on the IPv6 decision).

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

### 6.1 Deadman Switch (SSH lock-out protection) — REQUIRED for enforcing mode

Before setting `firewall.enabled=true`, install the deadman watchdog. It is an
independent root-level fail-safe: if the BastionFW process crashes, hangs, or
stops renewing its liveness file while bans are active, the watchdog removes
all engine-owned nftables/iptables rules so you can never be locked out of
your own server.

```bash
# 1. Provision the standalone watchdog script (idempotent, 0700, root-only):
sudo python3 -c "
from pathlib import Path
from ed_bt_ade.rollback import provision_rollback_script
provision_rollback_script(
    Path('/var/lib/bastionfw/rollback-deadman.sh'),
    Path('/var/lib/bastionfw'),
    120,
)
"

# 2. Install the systemd timer (every minute, as root):
sudo cp deploy/ed-bt-ade-rollback.service /etc/systemd/system/
sudo cp deploy/ed-bt-ade-rollback.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ed-bt-ade-rollback.timer
```

Behavior:

- The engine renews `/var/lib/bastionfw/deadman.liveness` six times inside
  the rollback window (default 120 s; override with
  `ED_BT_ADE_ROLLBACK_SECONDS`, minimum 10 s).
- If the file's age exceeds the window, the watchdog removes only addresses
  recorded by the engine (engine-owned nftables set entries and engine-added
  iptables DROP rules). Whitelisted and operator-managed rules are untouched.
- Every action is appended to `/var/lib/bastionfw/rollback.log`.
- A graceful `systemctl stop` also rolls back every active ban from inside
  the engine (`RollbackCoordinator`), and a dry-run deployment never arms the
  deadman liveness file with active bans because no bans are ever recorded.
- If the state database is deleted, the watchdog takes no action — the
  liveness file is only armed while the engine actually runs.

Test the watchdog in staging by stopping the engine with a manually inserted
ban row, then confirming `rollback.log` shows the unblock and your SSH session
stays connected.

#### 6.1.1 Python-native alternative (`ed_bt_ade.liveness`)

Two watchdogs exist. Install **exactly one**:

| Watchdog | Artifact | Dependency | Rollback mechanism |
|---|---|---|---|
| POSIX-sh (default) | `rollback-deadman.sh` + `ed-bt-ade-rollback.{service,timer}` | `nft`/`iptables` binaries only | deletes recorded set elements/rules from sh |
| Python-native (alternative) | `ed_bt_ade.liveness` + `ed-bt-ade-liveness.{service,timer}` | Python + installed package | engine's own `FirewallOrchestrator.purge_all()` |

```bash
sudo cp deploy/ed-bt-ade-liveness.service /etc/systemd/system/
sudo cp deploy/ed-bt-ade-liveness.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ed-bt-ade-liveness.timer
```

The CLI runs one pass: healthy → exit 0 (no-op); missing liveness file →
exit 0 (fail-open); expired → it purges every engine-owned ban through
`purge_all()` (the same code path as `--purge-all-bans`) and removes the
liveness file so a later timer pass does not re-fire. Use `--no-purge` to
report only. Because both watchdogs roll back the same objects, running both
would be redundant but not harmful — still, install only one to keep the
audit trail clear.

### 6.2 Observability: Grafana dashboard

The engine exposes Prometheus text metrics at `/metrics` (see §6).
`deploy/grafana-dashboard.json` is a ready-to-import Grafana dashboard that
visualizes logs processed, threats by rule, IPs blocked, pipeline errors, and
pipeline latency. Import it in Grafana → Dashboards → Import, then pick your
Prometheus data source when prompted (the dashboard declares a
`DS_PROMETHEUS` variable).

### 6.3 Bulk ban-list import / export

Move the engine's recorded ban list in and out as CSV or JSON. All imports go
through the same safety policy as the live pipeline (public, non-whitelisted
IPv4 only); rejected rows are logged and skipped, never fatal:

```bash
python -m ed_bt_ade.lists export --format csv  --output bans.csv
python -m ed_bt_ade.lists export --format json --output bans.json
python -m ed_bt_ade.lists import --format csv  --input bans.csv
python -m ed_bt_ade.lists import --format json --input bans.json --duration 3600
```

The installed console script `bastionfw-lists` is equivalent. `--config`
selects the policy/state file; the configured backend is used as-is, so a
dry-run config keeps imports dry-run.

## 7. Distributed Architecture Boundary

This package is a host-local agent. For hundreds of hosts, use one agent per
host with a central event bus, centralized policy/configuration distribution,
mTLS identities, centralized deduplication, and fleet-level auditing. SQLite is
only for host-local ban and reputation-cache state; it must not be used for
central coordination.

## 8. IPv6 policy (deliberate decision: IPv4-only enforcement)

BastionFW detects and parses IPv6 addresses safely, but it **does not ban
them**. This is a deliberate, documented scope decision, not an oversight:

- `validation.parse_ip` / `parse_network` take an `ipv6_enabled` flag; the
generic parsers accept IPv6 (so IPv6 attackers are still observed), but the
firewall passes `firewall.ipv6_enabled` (default **false**).
- `FirewallConfig.ipv6_enabled` defaults to `false`. `FirewallOrchestrator`
then **explicitly rejects** an IPv6 ban and logs
`firewall_ipv6_rejected` — it never hands the address to a driver that only
has an IPv4 set.
- The deadman rollback script and the provisioning script therefore manage
only the IPv4 `inet ed_bt_ade blacklist` set. There is no `blacklist6` set.
- `firewall.ipv6_enabled=true` currently has no enforcement effect: the
orchestrator logs `firewall_ipv6_unsupported` and refuses, so a misconfigured
operator cannot accidentally send IPv6 into the IPv4 set.

Consequence: an attacker coming only over IPv6 is detected and alerted on, but
not blocked until IPv6 enforcement (dual-set nftables support) is implemented.
If your exposure is primarily IPv6, plan for that before relying on
BastionFW's L3/L4 layer.