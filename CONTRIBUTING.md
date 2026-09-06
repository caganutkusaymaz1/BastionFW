# Contributing to BastionFW

Thank you for improving BastionFW. This project holds a security-sensitive
bar: every change must keep the defensive guarantees documented in
[`THREAT_MODEL.md`](THREAT_MODEL.md) and [`SECURITY.md`](SECURITY.md).

## Development setup

```bash
# Python engine + tests (from the repo root)
cd bastionfw
python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install --no-deps .
python3 -m pip install pytest pytest-cov hypothesis bandit[toml]

# TypeScript workspace (repo root)
pnpm install --frozen-lockfile
```

## Test and coverage requirements (mandatory)

Every pull request must pass the full CI pipeline locally before review:

```bash
# 1. Full test suite with the 80% coverage gate (from bastionfw/)
python3 -m pytest --cov=ed_bt_ade --cov-report=term-missing --cov-fail-under=80
python3 -m unittest discover -s tests -q

# 2. Static security analysis
bandit -r ed_bt_ade -ll -q

# 3. TypeScript (from repo root)
pnpm run typecheck && pnpm run build
```

Rules:

- New behavior requires new tests. Bug fixes require a regression test that
  fails without the fix.
- Coverage may not decrease below 80% (CI enforces `--cov-fail-under=80`).
- Existing tests may never be deleted, skipped, or weakened. If a test must
  change because the contract legitimately changed, state the reason in the
  commit message and reference the task or issue that changed the contract.
- Property-based (hypothesis) tests belong in `tests/test_fuzz_properties.py`
  and run inside the normal pytest pipeline with bounded example counts.

## Commit message format

```
<type>(<scope>): <imperative summary in 72 chars or less>

<optional body: motivation, design notes, and for security changes the
threat/attack scenario addressed>

🤖 Generated with Codebuff
Co-Authored-By: Codebuff <noreply@codebuff.com>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `chore`.
Scopes seen in this repo: `security`, `waf`, `dashboard`, `ops`, `safety`,
`console`, `supply-chain`, `fuzz`, `coverage`.

Each logical unit of work gets its own commit (the project follows a
code → tests → run → verify → commit loop per item).

## Security-sensitive changes

Changes touching any of the following need explicit reasoning in the commit
message:

- `firewall.py` (address policy, driver commands)
- `rollback.py` / `liveness.py` (deadman/rollback semantics)
- `validation.py` / `parsing.py` (input handling)
- `dashboard.py` (authentication, rate limiting)
- `config.py::_validated_url` (SSRF policy)
- `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`

Follow the public-API rule: signatures, CLI flags, config fields, and
endpoints are **additive only**; never remove or narrow existing behavior
without a deprecation cycle (old behavior keeps working with a warning for
at least one release, noted in `CHANGELOG.md`).

## Supply-chain rules

- Python dependency changes go through `requirements.in`, then regenerate
  `requirements.lock` with `pip-compile --generate-hashes` — never edit the
  lock by hand.
- npm changes must keep `pnpm-lock.yaml` frozen (`pnpm install
  --frozen-lockfile` must pass in CI).
- Docker base images are pinned by digest; bumping a digest requires
  re-running the Trivy scan (`--severity HIGH,CRITICAL --exit-code 1`).

## Reporting vulnerabilities

Do not open public issues for security problems. Follow
[`SECURITY.md`](SECURITY.md).
