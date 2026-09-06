# Security Policy

**BastionFW** is a defensive, host-local log analysis and active-defense
platform. It can change host firewall state and, in the hybrid deployment, an
L7 WAF deny-list. Treat it as security tooling: misconfiguration can disrupt
the very traffic it is meant to protect.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 3.x (hybrid Coraza WAF) | Yes |
| < 3.0 (log-only engine) | No |

## Safe defaults

- Firewall enforcement is **off** (`ED_BT_ADE_DRY_RUN=true`) unless explicitly
  enabled after staging validation.
- The Coraza WAF runs in **detect** mode (`WAF_MODE=detect`). Block mode is an
  explicit opt-in and must be validated in staging first.
- The L7 deny-list driver and the WAF deadman switch are disabled
  (`waf.enabled=false`) until the WAF stack is deployed and validated.
- The dashboard binds to **127.0.0.1 only** whenever
  `ED_BT_ADE_DASHBOARD_TOKEN` is unset — even when `0.0.0.0` is requested.
- All dashboard/API token comparisons use `hmac.compare_digest`.
- Loopback, RFC1918, link-local, reserved, and whitelisted addresses are never
  banned at the code level.
- CI runs `bandit`, `pnpm audit --audit-level=high`, and `gitleaks`; findings
  fail the pipeline (`continue-on-error: false`).

## Deployment hardening

1. Generate a long random dashboard token and pass it only through the
   environment (never commit it):
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
2. Keep `.env` out of version control and out of logs. API keys belong in a
   secret manager, never in JSON configuration.
3. Validate the firewall backend and whitelist in staging for 24+ hours before
   setting `ED_BT_ADE_DRY_RUN=false`.
4. Add management networks to `firewall.whitelist` before enabling
   enforcement so operators can never lock themselves out.
5. When enabling the WAF deny-list integration
   (`ED_BT_ADE_WAF_ENABLED=true`), keep `ED_BT_ADE_WAF_MODE` and the WAF
   container's `WAF_MODE` in sync (both `detect`, then both `block`).
6. The engine is host-local. For fleets, run one agent per host and place a
   central policy/event plane around it; SQLite is host-local state only.

## Fail-open and rollback

BastionFW favors availability: if the WAF becomes unhealthy for a sustained
period, the deadman switch drops the Coraza engine to `DetectionOnly`
(fail-open) so the protected application stays reachable. It never silently
re-enables block mode after a trip — restoring enforcement requires an
operator to reassert `waf.mode=block` (restart the engine).

Instantly clear every active/expired ban from all enforcement layers with:

```bash
python -m ed_bt_ade.sentinel --config <config> --purge-all-bans
```

or inside the container deployment:

```bash
docker compose exec bastionfw python -m ed_bt_ade.sentinel \
  --config /app/config.container.json --purge-all-bans
```

## Reporting a vulnerability

Do **not** open a public issue for security defects. Report them privately to
the repository owner (Cagan Utku Saymaz) with:

- affected version and deployment shape (host or container, WAF enabled?),
- a minimal reproducer,
- impact assessment.

Do not include real attacker IPs, credentials, or production log excerpts in
reports. Use documentation-range IPs (`203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`) in any shared material.
