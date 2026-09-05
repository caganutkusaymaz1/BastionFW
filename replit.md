# BastionFW Security Platform

BastionFW is a dry-run-first security operations console for reviewing detections and staging policy-aware defensive actions.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/bastionfw-console` — authenticated React/Vite SOC dashboard.
- `artifacts/api-server/src/routes/security.ts` — protected overview, events, and staged SOC actions.
- `artifacts/api-server/src/security/detector.ts` — reusable payload normalization, threat signatures, and rate limit primitives.
- `lib/api-spec/openapi.yaml` — source of truth for the generated client and Zod contracts.
- `artifacts/api-server/src/middlewares/requireAuth.ts` — Clerk-backed API guard.

## Architecture decisions

- Enforcement remains dry-run by default; service and address controls stage state changes rather than executing host shell commands.
- Dashboard data is contract-first through OpenAPI-generated hooks and refreshes telemetry on a finite interval.
- Clerk provides browser session auth; protected API routes rely on the same-origin session cookie rather than custom bearer-token handling.
- Threat detection normalizes repeated URL encoding before matching and keeps IP/UA/URI rate limiting primitives bounded in memory.

## Product

The console gives analysts a live protection posture, event stream, traffic and attack breakdowns, manual ban/unban controls, threat-intelligence refresh, and staged service controls.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Use `pnpm --filter @workspace/api-spec run codegen` after changing `lib/api-spec/openapi.yaml`.
- Protected SOC endpoints intentionally return `401` until a Clerk session is established.
- Build the web artifact with workflow-provided `PORT` and `BASE_PATH` values.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
