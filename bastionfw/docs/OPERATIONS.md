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

## 7. Distributed Architecture Boundary

This package is a host-local agent. For hundreds of hosts, use one agent per
host with a central event bus, centralized policy/configuration distribution,
mTLS identities, centralized deduplication, and fleet-level auditing. SQLite is
only for host-local ban and reputation-cache state; it must not be used for
central coordination.