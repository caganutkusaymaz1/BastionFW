# BastionFW Security Platform

BastionFW is a defensive Linux security platform that tails security logs,
detects SSH and web attack signals, stages temporary firewall bans, and
exposes an operational dashboard and Prometheus metrics.

## Quick start

Requirements:

- Docker Engine and Docker Compose v2
- A copy of `.env.example` saved as `.env`

```bash
cp .env.example .env
docker compose up --build
```

The default deployment is dry-run mode and does not modify the host firewall.
Open the dashboard at `http://127.0.0.1:8080` and check readiness at
`http://127.0.0.1:9109/healthz`.

Stop the stack with:

```bash
docker compose down
```

## Configuration

The root Compose deployment uses `bastionfw/config.container.json` and persists
local state in the `bastionfw-state` volume. Host logs are mounted read-only
from `BASTIONFW_LOG_ROOT` (default: `/var/log`). Set
`ED_BT_ADE_DRY_RUN=false` only after validating the configured backend,
whitelist, capabilities, and rollback procedure in staging.

The image automatically falls back to the mock firewall driver when the
configured executable is unavailable or the container lacks privileges.

Never commit `.env` or place API keys in JSON configuration. Use a secret
manager or runtime environment injection for production credentials.

## Development

Python tests:

```bash
cd bastionfw
python3 -m unittest discover -s tests -v
```

Workspace typechecking and builds require pnpm:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run build
```

The TypeScript workspace contains the API server, React console, generated API
clients, and database package. The Python agent remains independently
installable through `bastionfw/pyproject.toml`.

## Repository layout

- `bastionfw/`: Python log analyzer, detector, firewall abstraction, dashboard,
  configuration, and tests.
- `artifacts/api-server/`: authenticated Express API service.
- `artifacts/bastionfw-console/`: React/Vite operations console.
- `lib/`: API schema, generated clients, and database packages.
- `.github/workflows/ci.yml`: automated Python and TypeScript validation.

## Security boundary

The platform is host-local by design. Production enforcement requires a
reviewed firewall ruleset, explicit host capabilities, protected management
access, secret management, and environment-specific acceptance tests.

## Security posture

**Automated security testing** (defined in `.github/workflows/ci.yml`, all
blocking — `continue-on-error: false`):

| Check | Scope |
|---|---|
| `bandit -r ed_bt_ade -ll -q` | Python static security analysis |
| `pytest --cov-fail-under=80` | full suite incl. hypothesis fuzz tests, 80% coverage gate |
| `gitleaks` | secret-leak scan of the whole repository history |
| `pnpm audit --audit-level=high --prod` | npm dependency vulnerabilities |
| Trivy `HIGH,CRITICAL` (exit 1) | container images `bastionfw` and `waf`, OS packages included |
| Syft CycloneDX SBOM | both images, uploaded as CI artifacts |
| `pnpm install --frozen-lockfile` | npm supply-chain lock enforcement |
| hash-pinned Python install (`--require-hashes`) | every Python artifact verified against its sha256 |
| digest-pinned base image (`python:3.13-slim@sha256:9d2e…`) | upstream tag mutation impossible |

**Test coverage:** 81% (`ed_bt_ade`, 95 tests, including 7 property-based
hypothesis tests). The CI gate is 80% — coverage may not decrease.

**Independent audit:** no independent third-party security audit or
penetration test has been performed on this codebase. The checks above are
automated only. See `THREAT_MODEL.md` ("Known limitations") for the honest
gap list before relying on BastionFW in a high-risk deployment.

**Further reading:** [`THREAT_MODEL.md`](THREAT_MODEL.md),
[`SECURITY.md`](SECURITY.md), [`CHANGELOG.md`](CHANGELOG.md),
[`CONTRIBUTING.md`](CONTRIBUTING.md), [`docs/OPERATIONS.md`](docs/OPERATIONS.md).
