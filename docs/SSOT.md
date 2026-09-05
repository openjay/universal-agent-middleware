# Universal Agent Middleware — Product SSOT V3

Status: `PUBLIC_PREVIEW`
Version: `0.5.1rc1`

## 1. Product identity

Universal Agent Middleware (UAM) is a **vendor-neutral middleware layer** that separates:

1. reasoning/observation clients;
2. target-project truth and resources;
3. bounded execution handoffs;
4. executors and their effects;
5. evidence-based result review.

UAM is independent of any specific target project, OpenAI, Anthropic, Google, Cursor, GitHub, Microsoft, any individual model, and any single agent protocol.

## 2. Product objective

Provide a stable interoperability and control boundary where AI reasoning clients can **autonomously discover, observe, and analyze** local project reality within authorized trust zones — without prior registration — while preserving project sovereignty, least privilege, and read-only enforcement.

Core capability progression:
- v0.2: inspect explicitly registered workspaces
- v0.3: project-level reality coverage + observation diagnostics
- v0.4: autonomous reality discovery within standing trust zones
- v0.5: operational hardening + Public Preview read-only MCP profile (current)

## 3. Authority law

- UAM owns only UAM configuration, state, adapter behavior, and contract/review semantics.
- A target workspace owns its own SSOT, policies, branch protection, runtime truth, deployment authority, and product decisions.
- A client adapter cannot grant target-project authority.
- An executor adapter cannot silently broaden a contract.
- A protocol or packaging standard is transport/interoperability infrastructure, not authority.
- Conversation history is context, never execution authority.
- RootScope defines standing read-only trust zones — it grants discovery/observation, never mutation authority.
- Capability enforcement in v0.4: `discover`, `content_read`, `text_search`, `git_observe`, `auto_admit` are enforced; `metadata_read` is declared/informational only (independent enforcement deferred to v0.5); override enforcement is reserved for v0.5.

## 4. Frozen invariants

1. **VENDOR_NEUTRAL_CORE** — core behavior contains no required vendor-specific API, model, plan, or identity.
2. **CLIENTS_ARE_ADAPTERS** — ChatGPT, Claude, Gemini, Cursor, Copilot, or future clients are northbound adapters/consumers.
3. **EXECUTORS_ARE_ADAPTERS** — Codex, Claude Code, Cursor, native workers, local models, CI agents, or future executors are southbound capability providers.
4. **PROJECT_SOVEREIGNTY** — target-project authority always outranks UAM observations or model claims about that project.
5. **TARGET_WORKSPACE_READ_ONLY_BY_DEFAULT** — all observation surfaces have no target-workspace write endpoint.
6. **NO_ARBITRARY_EXEC** — no caller-supplied shell command reaches subprocess through UAM observation APIs.
7. **EXPLICIT_WORKSPACE_CAPABILITIES** — every workspace (static or derived) has explicit capability bounds.
8. **CANONICAL_PATH_CONFINEMENT** — resolved paths must remain inside the registered/derived root; traversal and symlink escape fail closed.
9. **SECRET_DENYLIST** — credential/key locations are inaccessible even inside a registered root or auto-admitted scope.
10. **CONTROL_STATE_SEPARATE** — UAM state is physically disjoint from every target workspace.
11. **SNAPSHOT_BOUND_HANDOFF** — `repository-change-v1` creation requires a clean observed worktree, exact current Git `HEAD`, safe allowed paths, and authoritative files tracked by the bound repository snapshot.
12. **IMMUTABLE_HANDOFF** — a contract ID cannot be overwritten.
13. **PROFILED_CONTRACTS** — contract semantics are versioned profiles. Unsupported profiles fail closed.
14. **EVIDENCE_OVER_CLAIMS** — completion requires Executor Result evidence bound to the exact contract/base/scope/verification surface.
15. **STANDARDS_ARE_REPLACEABLE_ADAPTERS** — MCP, Agent Skills, Agent Plugins, OpenAPI, tunnels, and future standards never become the core authority model.
16. **NO_FALSE_UNIVERSALITY** — UAM may be architecturally extensible without claiming workspace kinds, effects, or client integrations that have not passed conformance tests.
17. **HERMETIC_GIT** — all Git operations on untrusted repositories disable fsmonitor, external diff, pagers, global/system config, and terminal prompts.
18. **OBSERVATION_NOT_AUTHORITY** — UAM coverage completeness does not equal project authority grant. `UAM_COVERAGE_COMPLETE ≠ PROJECT_AUTHORITY_GRANTED`.

## 5. Implemented capability surface

### v0.4 — Autonomous Reality Discovery

- **RootScope**: standing trust zones with capability inheritance (discover, metadata_read, content_read, text_search, git_observe, auto_admit)
- **DiscoveryEngine**: deterministic Git repository scanning, remote identity resolution, worktree grouping, activity classification
- **Auto-admission**: on-demand repository admission inside authorized `auto_admit=true` scopes; requires .git marker and scope authority, not prior inventory membership
- **ExplorationEngine**: coverage gap analysis, project ranking, "what am I missing?" inference
- **Cross-project search**: ripgrep-based text search with project attribution

### Workspace profile: `git-repository`

Capabilities: `filesystem.read`, `git.observe`

Operations:
- list workspaces and scopes;
- autonomous project discovery;
- cross-project search;
- bounded tree / text read / text search;
- hardened Git status/diff/log;
- coverage gap analysis;
- audit-chain verification;
- immutable contract create/read;
- immutable executor-result record/read + machine review.

### MCP tool surface: 19 read-only tools

All tools: `readOnlyHint=true, destructiveHint=false, openWorldHint=false`.

## 6. Adapter classes

Northbound:
- MCP 2026-07-28 stateless tools adapter — 19 tools via official SDK (READ_ONLY_SESSION_PROFILE_V2).
- Secure MCP Tunnel — outbound-only, via `tunnel-client`.
- Generic HTTP/OpenAPI 3.1 — implemented.

Southbound:
- Generic contract export/result ingestion — implemented.
- Forge/Runtime observation adapters — deferred to v0.5.

## 7. Explicitly absent

- target repository write/apply patch;
- arbitrary command execution;
- git commit/push/merge;
- deploy/runtime/database/external financial effects;
- credential reading;
- vendor-owned identity or billing logic in core;
- forge CI observation (v0.5);
- runtime identity observation (v0.5);
- autonomous execution (v0.5).

## 8. Current release acceptance

UAM v0.4.0 terminal acceptance requires:

1. 19-tool parity: source = local MCP = tunneled MCP = ChatGPT Web;
2. docs/README/CHANGELOG/MANIFEST all reflect v0.4.0;
3. hermetic Git in all code paths (discovery included);
4. RootScope capability enforcement (git_observe=false blocks git calls);
5. auto-admission: discovered repos usable via existing tools;
6. secret firewall holds for derived workspaces;
7. cross-project search includes project attribution;
8. fresh ChatGPT session can discover/read/explore without prior registration;
9. all regression tests pass;
10. release receipt produced.
