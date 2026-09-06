# Threat Model

**Scope:** BastionFW engine (`bastionfw/ed_bt_ade`), its dashboard, the
console proxy (`artifacts/api-server`), and the Coraza WAF sidecar declared
in `docker-compose.yml`. This document describes **verified current
behavior** — every claim below was checked against the listed code during
the hardening round. No claim is made about anything not in the code.

## What BastionFW protects

| Asset | Protection | Evidence |
|---|---|---|
| SSH service | Brute-force detection per source IP (threshold + sliding window), optional L3/L4 ban | `detector.py::SSHBruteForceRule` |
| Web applications (behind Coraza) | L7 detection from audit logs (SQLi/XSS/LFI/RFI/web-shell/command-injection/smuggling patterns), anomaly-score-driven severity | `parsing.py::parse_coraza_audit_line`, `detector.py::WebAttackRule` |
| Linux host network plane | nftables/iptables/ufw/firewalld DROP rules for engine-recorded addresses only | `firewall.py::CommandFirewallDriver` subclasses |
| CDN/proxied traffic | Dynamic WAF deny-list (L7) mirroring engine bans | `waf_reputation.py` |
| Availability during engine failure | Three-layer rollback (see below) | `rollback.py`, `liveness.py` |

## Trust boundaries and who can access what

1. **Engine process** — runs unprivileged (non-root, `USER bastionfw` in the
   Dockerfile; privilege drop in `privilege.py` when started as root
   outside containers). Needs write access only to its state directory and
   read access to log files; firewall changes happen through CAP_NET_ADMIN
   or a setcap wrapper, not full root.
2. **Dashboard** — `dashboard.py` binds to `0.0.0.0` **only** when
   `ED_BT_ADE_DASHBOARD_TOKEN` is set; otherwise it fail-safely binds to
   `127.0.0.1` and logs a warning (`resolve_bind_host`). With a token,
   every protected path requires `Authorization: Bearer` or the HttpOnly
   session cookie obtained from `POST /api/login`. Login is rate-limited
   (5 failures / 5 min → 60 s lockout, `429`) and every attempt is
   audit-logged; the token value is never logged.
3. **Console proxy** (`artifacts/api-server`) — sits behind Clerk
   authentication (`requireAuth`); it proxies the engine dashboard with a
   server-side token (`BASTIONFW_API_TOKEN`) that is never exposed to
   clients. It performs no enforcement of its own.
4. **Root deadman watchdog** — the generated rollback script runs as root
   from cron/systemd (`deploy/ed-bt-ade-rollback.{service,timer}`). It
   removes only addresses the engine itself recorded; whitelisted and
   operator-managed rules are never touched.
5. **Coraza container** — reverse-proxies `UPSTREAM_URL`; writes audit JSON
   to the shared `waf-audit` volume, which the engine mounts **read-only**.

## Security invariants (verified)

- **Command execution:** exactly one subprocess site
  (`asyncio.create_subprocess_exec`, argv list, no `shell=True`,
  no `os.system`/`eval`/`exec`).
- **Ban universe:** every address recorded to the OS passed
  `FirewallOrchestrator._allowed()` — canonical `ipaddress` parsing,
  IPv4-only, `is_global`, not loopback/private/link-local, not whitelisted.
  Non-canonical input is rejected before it can reach argv.
- **Rollback window:** liveness file renewed ≥6×/window while the event loop
  is healthy; external watchdog rolls back if renewals stop. Window is
  operator-tunable via `ED_BT_ADE_ROLLBACK_SECONDS`.
- **WAF fail-open:** if the WAF stays unhealthy beyond
  `WafDeadmanSwitch.max_unhealthy_seconds`, the dynamic deny-list is cleared
  so the application behind a broken WAF stays reachable. L3/L4 protection
  and the root watchdog are independent of this switch.
- **Bounded parsing:** log lines capped at 1 MiB buffered, detection input
  at 64 KiB, Coraza JSON depth ≤ 64, rule IDs ≤ 32; all with defined
  rejection behavior (no crashes).
- **SSRF:** operator-configured outbound URLs (threat-intel, webhooks) must
  be HTTP(S), credential-free, and non-private unless the host is listed in
  `waf.trusted_internal_hosts`.

## What BastionFW does NOT protect

- **L7 application-logic vulnerabilities.** Coraza/CRS catches generic web
  attack patterns; business-logic flaws, broken authorization in *your*
  application, or zero-day exploits that do not match CRS rules are out of
  scope for this project.
- **Encrypted traffic inspection.** BastionFW analyzes audit logs, not TLS
  streams.
- **Host malware / insider threats.** An operator with root on the host can
  disable the engine, edit configs, and read state. BastionFW is a
  defense-in-depth layer, not tamper-proof.
- **IPv6 banning.** Enforcement accepts IPv4 addresses only
  (`firewall.py`: `network.version != 4 → reject`); IPv6 is parsed
  safely but never banned.
- **Email/pager alerting.** Alerting is webhook-based only
  (`AlertingConfig.webhooks`); there is no built-in email/SMS path.
- **Multi-host coordination.** Each engine instance protects its own host;
  there is no cluster-wide state sync.

## Known limitations (disclosed honestly)

- The login rate limiter is in-memory: a dashboard restart clears failure
  history, and attackers rotating across source IPs behind an unconfigured
  `trusted_proxies` list will appear as distinct clients.
- The console proxy's ban/unban/service endpoints validate input and
  authenticate the requester but do not themselves enforce changes —
  enforcement is performed on the engine host (documented in
  `artifacts/api-server/src/routes/security.ts`).
- No independent third-party security audit has been performed on this
  codebase. CI runs bandit, gitleaks, Trivy, pnpm audit, and fuzz tests
  (see README "Security Posture"); these reduce but do not eliminate risk.
