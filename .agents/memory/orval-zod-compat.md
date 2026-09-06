---
name: OpenAPI integer compatibility
description: Orval's Zod client currently targets zod.int(), which is unavailable in this workspace's Zod 3 runtime.
---

Use numeric OpenAPI schemas for generated dashboard counters unless the workspace upgrades the Zod runtime and generator together.

**Why:** Code generation succeeds, but the workspace typecheck fails when Orval emits `zod.int()` against the installed Zod 3 package.

**How to apply:** After changing `lib/api-spec/openapi.yaml`, run codegen and the full typecheck before adding integer-specific generated response schemas.