# Changelog

All notable changes to BastionFW are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.2] — CI supply-chain hardening, non-root WAF, beginner README

### Security

- **GitHub Actions mutable tag'leri SHA'ya sabitlendi (A1).** `ci.yml` içindeki
  her `uses:` ifadesi artık 40 karakterlik commit SHA'sı kullanıyor (`@v4`
  yerine `@11d5960…` gibi), yanına da hangi tag'e karşılık geldiği yorum olarak
  yazıldı. 10 farklı action doğrulandı: `actions/checkout`,
  `actions/setup-python`, `actions/setup-node`, `actions/upload-artifact`,
  `pnpm/action-setup`, `gitleaks/gitleaks-action`,
  `docker/setup-buildx-action`, `docker/build-push-action`,
  `anchore/sbom-action` (ve `download-syft` alt dizini) ve
  `aquasecurity/trivy-action`. Bir action sahibinin hesabı ele geçirilirse ya da
  tag sessizce başka bir commit'e taşınırsa (trivy-action ve
  kics-github-action için gerçek örnekler), CI runner'ında keyfi kod çalışması
  artık mümkün değil.
- **`curl | sh` kurulum deseni kaldırıldı (A2).** Trivy daha önce
  `raw.githubusercontent.com/.../install.sh` betiğini doğrulamadan `sh` ile
  çalıştırıyordu. Aynı iş artık dosyada zaten kullanılan, SHA'ya sabitlenmiş
  resmi `aquasecurity/trivy-action` ile yapılıyor: aynı `trivy config` alt komutu,
  aynı `HIGH,CRITICAL` eşiği, aynı `exit-code: 1` davranışı — Dockerfile ve
  docker-compose.yml için ayrı adımlar hâlinde.
- **WAF container'ı artık root olarak çalışmıyor (A3).**
  `deploy/waf/Dockerfile` içine `USER waf` eklendi. Base `caddy:2.11.4` imajı
  `caddy` kullanıcısı içermediği için `addgroup`/`adduser -S -D -H` ile uid
  10001'li ayrı bir sistem kullanıcısı oluşturuluyor. `entrypoint.sh`'in
  yazma ihtiyacı olan dizinler (`/tmp/caddy/*` tmpfs ve `/var/log/waf` audit
  volume'ü) kullanıcıya veriliyor; compose'un `read_only` + `tmpfs`
  ayarlarıyla çakışma yok — container gerçek compose koşullarıyla
  doğrulandı (`mode=detect engine=DetectionOnly`, audit dosyası yazılabilir,
  Coraza/OWASP CRS kuralları çalışır).
- **npm/pnpm tedarik-zinciri sertleştirmesi (A4).** `.npmrc`'ye
  `min-release-age=7`, `pnpm-workspace.yaml`'a `minimumReleaseAge: 10080`
  (24 saatten 7 güne), `blockExoticSubdeps: true` ve
  `trustPolicy: no-downgrade` eklendi. Ayrıca build-script beyaz listesi
  `@clerk/shared` içerecek şekilde tamamlandı; hem pnpm 10
  (`onlyBuiltDependencies`) hem pnpm 11+ (`allowBuilds`) sözdizimi birlikte
  bildirildi, böylece iki ana sürümde de `ERR_PNPM_IGNORED_BUILDS` oluşmuyor.
- **`Dockerfile` dashboard varlığını kopyalamıyordu.** `bastionfw/web/`
  dizini imaja hiç girmiyordu; `dashboard.py` `WEB_ROOT`'u `<paket>/web`
  olarak çözdüğü için container'da panel arayüzü **hiç yoktu** ve
  `GET /` `500 dashboard asset unavailable` döndürüyordu (`/api/status` ise
  çalışıyordu, yani hata sessizce geçiyordu). `COPY bastionfw/web ./web`
  eklendi; yeni imajda `/` 200 ile HTML döndürüyor.

### Documentation

- **README sıfırdan yazıldı.** 125 → 900+ satır: projenin ne işe yaradığı,
  hangi durumlarda kullanılmadığı, 5 dakikalık zihinsel model (ASCII şema),
  terimler sözlüğü, iki ayrı kurulum yolu (Docker / elle), "ilk 10 dakika"
  anlatımı, her yapılandırma alanının tablo hâlinde açıklaması, panel ve API
  uçları, dry-run → gerçek engelleme için 6 aşamalı güvenli geçiş, WAF
  bölümü ve 11 senaryolu sorun giderme rehberi. Kurulum komutlarının tamamı
  çalıştırılarak doğrulandı.
- **Yanlış pozitifler gerekçelendirildi.** `rollback.py`'deki `0o700`
  (root'a ait deadman-watchdog betiği) ve `dispatcher.py` /
  `threat_intel.py` içindeki `urlopen` çağrıları (giriş `parse_ip()` veya
  `_validated_url()` ile doğrulanmış, şema `http`/`https` ile sınırlı)
  değiştirilmedi; her birine kodu referans alan teknik gerekçe yazıldı.

### Changed

- Semgrep'in `nosemgrep` bastırma yorumları `try`/`except` blokları içinde
  etkili olmadığı için, üç konumda da işaretçi ilgili kod satırının sonuna
  taşındı. Yanlış yerde bırakılmış bir bastırma, hiç bulgu yokmuş gibi
  göründüğü için sessizce yanıltıcıydı.

## [3.2.1] — SSRF hostname-resolution fix

### Security

- **`_validated_url()` skipped its range checks for hostnames (SSRF).** When
  a configured URL host was a *name* rather than a literal IP (`localhost`,
  `internal-api.corp`, or any domain — including an attacker-controlled one —
  resolving to `169.254.169.254` or a private range), `ipaddress.ip_address()`
  raised `ValueError`, the address stayed `None`, and the private/loopback/
  link-local/reserved/multicast rejection was skipped entirely, so the URL was
  accepted. Hosts used by `threat_intel.abuseipdb_url` and
  `alerting.webhooks.*` are now resolved with `socket.getaddrinfo()` (stdlib,
  no new dependency) and **every** returned IPv4/IPv6 address is run through
  the same range checks; any private/loopback/link-local/reserved result is
  rejected. Resolution failures (`socket.gaierror`) are rejected with a clear
  `ConfigError` rather than silently accepted (a name could resolve to an
  internal address later, at request time). The `waf.trusted_internal_hosts`
  allowlist is still checked first, so explicitly trusted internal service
  names need no DNS lookup and offline/air-gapped configs keep working. DNS
  now runs at config-load time, which is infrequent and acceptable. Covered by
  `tests/test_security.py` (`SecurityRegressionTests.test_ssrf_*`).

## [3.2.0] — WAF enforcement hardening & operator tooling

### Security

- **The WAF image could never build (A1).** `corazawaf/coraza-caddy:v2` does
  not exist on Docker Hub (the registry returns *object not found*), so the
  Compose `waf` service was guaranteed to fail to pull. The image is now built
  from source on Caddy's official builder image (`caddy:2.11.4-builder` with
  `xcaddy build --with github.com/corazawaf/coraza-caddy/v2`, which embeds
  OWASP CRS); CI builds and scans this image.
- **WAF env contract is honoured (A1).** `deploy/waf/{Caddyfile,entrypoint.sh}`
  map `WAF_MODE=detect` → `SecRuleEngine DetectionOnly` and
  `WAF_MODE=block` → `SecRuleEngine On` (an unknown mode aborts startup),
  reverse-proxy `UPSTREAM_URL`, and write Coraza JSON audit events to
  `/var/log/waf/audit.json` on the shared `waf-audit` volume.
- **nftables provisioning automated (A2).**
  `bastionfw/scripts/provision-nftables.sh` idempotently creates `inet ed_bt_ade`
  (table, IPv4 `blacklist` set, `input` chain, drop rule) exactly matching the
  objects `firewall.NftablesDriver` writes into.
- **IPv6 policy made explicit (A3).** IPv6 bans are rejected and logged
  (`firewall.ipv6_enabled`, default `false`) instead of being passed to an
  IPv4-only driver; documented in `docs/OPERATIONS.md` §8 and `THREAT_MODEL.md`.
- **Dashboard session cookie hardened (A7).** `Set-Cookie` now includes
  `Secure` alongside `HttpOnly` / `SameSite=Strict`, with the plain-HTTP
  loopback behaviour documented.
- **WAF audit records can now drive enforcement.** Native Coraza/CRS audit
  JSON carries no structured `rule_id` / `anomaly_score`; both are now
  extracted from bounded `messages[].error_message` audit text. Attacker-
  controlled request content (uri, headers, body) is never scanned, so it
  cannot forge a rule id or inflate the score that gates a ban. A confirmed
  CRS match (rule ids + score ≥ 5) is a blocking signal; bare `coraza_audit`
  events and text web rules stay alert-only to avoid self-inflicted DoS on
  CRS false positives.

### Fixed

- `rollback.py` docstrings corrected to state real behaviour: graceful
  shutdown drains *expired* bans only, active bans survive a restart, and
  only the external root watchdog clears all bans after a crash (A4).
- `ed_bt_ade/liveness.py` completed — the CLI `on_expired` hook now performs a
  real `FirewallOrchestrator.purge_all()` and removes the liveness file, with
  systemd units and a documented difference from the POSIX-sh watchdog (A5).
- `artifacts/mockup-sandbox` is documented in the repository layout instead of
  being silently removed (A6).

### Added

- Bulk ban-list import/export CLI: `python -m ed_bt_ade.lists` /
  `bastionfw-lists`, CSV and JSON, routing every import through the same
  safety-vetted ban path as the live pipeline (B4).
- Ready-to-import Grafana dashboard for the Prometheus `/metrics` endpoint:
  `bastionfw/deploy/grafana-dashboard.json` (B8).
- `deploy/waf/verify-block-mode.sh` — builds and deploys the WAF against a
  throwaway upstream, asserts `block → 403` and `detect → 200` for a SQLi
  probe, then tears everything down.
- IPv6/ban-policy, WAF-deploy, nftables-provisioning, list-IO, Grafana and
  native-audit test suites (104 → 137 tests; coverage 82.9% → 83.7%).

### Supply chain & testing (hardening round, 95 → 99)

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

[Unreleased]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.2.2...HEAD
[3.2.2]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.2.1...v3.2.2
[3.2.1]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/caganutkusaymaz1/BastionFW/compare/v3.0.0...v3.1.0
[3.0.x]: https://github.com/caganutkusaymaz1/BastionFW/releases/tag/v3.0.0
