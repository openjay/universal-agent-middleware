# UAM Delivery Plan V2

## P0 — identity and architecture freeze — DONE

- Standalone project: Universal Agent Middleware.
- Vendor/model/client/executor neutral core.
- Target project sovereignty preserved.
- Ports/adapters architecture frozen.
- Current effect profile remains read-only observation + separate `repository-change-v1` handoff.

Exit: no core dependency on a named AI vendor or executor.

## P1 — universal core MVP — IMPLEMENTED, LOCAL TESTS PASS

- versioned workspace registry with kind/capability profile;
- physical separation between UAM control state and target workspaces;
- canonical path confinement + secret denylist;
- bounded tree/read/search;
- hardened read-only Git observation;
- Bearer-authenticated loopback HTTP;
- immutable profiled Execution Contract bound to clean exact Git snapshot;
- immutable Executor Result + machine reviewer;
- hash-chained audit.

Exit: fresh local E2E, boundary, packaging, and adapter smoke PASS after v0.2 migration.

## P2 — protocol interoperability — IMPLEMENTED AT MVP SCOPE, LOCAL TESTS PASS

- generic OpenAPI 3.1 adapter;
- MCP 2026-07-28 stateless `server/discover` / `tools/list` / `tools/call`;
- HTTP MCP Origin/header/auth fail-closed checks;
- MCP stdio entry point;
- same `MiddlewareGateway` for HTTP and MCP.

Exit: protocol conformance tests prove no capability difference between adapters.

## P3 — portable package interoperability — IMPLEMENTED STRUCTURALLY, LIVE CLIENT TEST PENDING

- Agent Plugins 1.0.0 `plugin.json`;
- portable Agent Skill;
- `mcp.json` with no embedded credentials;
- package structural tests;
- explicit Working Draft dependency note.

Exit: at least two independent compatible clients load the package or equivalent components without changing UAM core.

## P4 — multi-project first deployment — NOT_STARTED

Register real workspaces independently, beginning with examples such as `my-app` and `api-service`. No project code change is required to register a read-only workspace.

Acceptance:

- workspace roots isolated;
- contract IDs/state do not collide;
- exact revisions bind handoffs;
- no cross-project context leakage;
- each project SSOT remains authoritative.

## P5 — real executor round trip — NOT_STARTED

Choose executors based on task fit and available resources, not a hard-coded vendor default.

Acceptance:

- READY contract -> executor adapter -> actual patch/effect -> result evidence -> UAM review;
- no duplicated full research conversation required;
- no silent scope expansion;
- executor-specific quota/cost data recorded as adapter telemetry only.

## P6 — production security — NOT_STARTED

- dedicated unprivileged service account / OS sandbox;
- per-client/per-workspace scoped credentials;
- OAuth or identity-aware proxy for remote MCP/HTTP;
- rate limiting and bounded concurrency;
- external audit anchoring/signing;
- structured telemetry without workspace-content logging;
- signed/versioned policy bundles;
- encrypted control state where required.

## P7 — additional profiles/workspace kinds — HOLD UNTIL REAL NEED

Do not generalize speculatively. Add a profile only when a real use case cannot be represented safely by `repository-change-v1`.

Each new profile requires schema + authority/effect model + reviewer + negative tests.

## Success metrics

Primary universal metrics:

- execution cost per accepted result;
- first-pass acceptance rate;
- rework rate;
- handoff bytes/tokens relative to research context;
- policy rejection rate;
- cross-adapter semantic parity;
- evidence completeness.

Adapter-specific metrics such as Codex credits, Claude usage, API spend, latency, or local GPU time are secondary dimensions, not core product identity.
