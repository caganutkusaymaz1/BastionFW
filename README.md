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
