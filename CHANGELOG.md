# Changelog

All notable changes to BastionFW are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — hardening round (95 → 99)

- **Supply chain:** hash-pinned Python lock (`bastionfw/requirements.lock`
  via `pip-compile --generate-hashes`), digest-pinned Docker base image
  (`python:3.13-slim@sha256:9d2e5553…`), Syft CycloneDX SBOMs for both
  container images, and Trivy HIGH/CRITICAL image scanning in CI.
- **Fuzz testing:** hypothesis property-based tests for `parse_ip`,
  `parse_network`, and the Coraza audit parser (bounded example counts,
  integrated into the normal pytest pipeline).
- **Dashboard brute-force protection:** sliding-window rate limiter on
  `POST /api/login` (5 failures / 5 min → 60 s lockout with `429`),
  audit logging of every attempt (token never logged), and brute-force
  alerts routed through the existing webhook dispatcher.
- **Coverage gate:** `pytest --cov-fail-under=80` enforced in CI; coverage
  raised from 61% to 80%+ with new pipeline/lifecycle/privilege tests.
- **Enterprise documentation:** `THREAT_MODEL.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`, and a Security Posture section in the README.

## [3.1.0] — Coraza WAF hybrid hardening

### Added

- Coraza WAF + OWASP CRS sidecar in `docker-compose.yml`
  (`WAF_MODE=detect` default; `block` is an explicit operator opt-in),
  with audit logs shared via the `waf-audit` volume.
- `parsing.py::parse_coraza_audit_line` — JSON audit parser with
  canonical-IP validation, size/depth/rule-id caps.
- `source_type: "coraza_audit"` log sources wired into the normal ban loop.
- `waf_reputation.py` — bi-directional enforcement: engine bans are
  mirrored into the WAF dynamic deny-list; expiry/purge removes from both
  layers; `WafDeadmanSwitch` clears the deny-list when the WAF stays
  unhealthy (fail-open) so the application stays reachable.
- `POST /api/login` — cookie-based dashboard bootstrap (HttpOnly,
  SameSite=Strict); token never appears in URLs or JavaScript.
- Standalone liveness watchdog (`ed_bt_ade/liveness.py`) usable without the
  engine installed.
- `docs/OPERATIONS.md` — detect→block promotion guide;
  `tests/integration/test_waf_smoke.sh` end-to-end check.

### Changed

- `security.ts` console API proxies the real Python dashboard with a
  server-side token; all mock/dummy data removed; unused
  `src/security/detector.ts` deleted.

## [3.0.x] — production baseline

### Added

- Bearer-token dashboard authentication with `hmac.compare_digest` and
  fail-safe loopback binding when no token is configured.
- SSRF-hardened `_validated_url` (private/loopback/link-local/metadata
  rejection with `waf.trusted_internal_hosts` allowlist for compose-internal
  service names).
- 1 MiB tailer buffer cap (`MAX_BUFFER_BYTES`) against newline-less
  producer memory exhaustion.
- `FirewallOrchestrator.purge_all()` and `--purge-all-bans` panic switch.
- Deadman switch with `ED_BT_ADE_ROLLBACK_SECONDS` env override honored at
  runtime; POSIX-sh watchdog script refuses shell-hostile `state_dir`
  values; root systemd timer deployment units.
- Async inode-aware tailing, bounded queues, token-bucket rate limiting,
  circuit breaker, SQLite TTL/LRU threat-intel cache, JSON audit logging,
  Prometheus metrics, privilege drop, and the initial 23-test suite.

### Security

- Command injection review: single subprocess site, argv-list only,
  `shell=True` absent repo-wide.
- Threat-intel URL encoding hardening (canonical IP re-validation before
  any outbound request).

[Unreleased]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.1.0...HEAD
[3.1.0]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.0.0...v3.1.0
[3.0.x]: https://github.com/caganutkusaymaz1/BastionFW/releases/tag/v3.0.0
