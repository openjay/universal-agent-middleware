# Universal Agent Middleware — Product SSOT V3

Status: `PUBLIC_PREVIEW`
Version: `0.6.3`

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
- v0.5: operational hardening + Public Preview read-only MCP profile
- v0.6: unified resolver, bounded discovery cache, cross-process SQLite reality index (current)

## 3. Authority law

- UAM owns only UAM configuration, state, adapter behavior, and contract/review semantics.
- A target workspace owns its own SSOT, policies, branch protection, runtime truth, deployment authority, and product decisions.
- A client adapter cannot grant target-project authority.
- An executor adapter cannot silently broaden a contract.
- A protocol or packaging standard is transport/interoperability infrastructure, not authority.
- Conversation history is context, never execution authority.
- RootScope defines standing read-only trust zones — it grants discovery/observation, never mutation authority.
- Capability enforcement in v0.4: `discover`, `content_read`, `text_search`, `git_observe`, `auto_admit` are enforced; `metadata_read` is declared/informational only (independent enforcement deferred to v0.5); override enforcement is reserved for v0.5.
- Added after v0.6.0: `directory_admit` (default `false`) is enforced at on-demand admission of non-Git directories as `filesystem-directory` workspaces. It never implies discovery, indexing or Git access.

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

### v0.6 — Cross-Process Reality Index

- **RealityIndex**: SQLite WAL database in UAM private state; scope snapshots, instance records, inverted alias columns
- **Fast identity resolution**: bare project names resolved from index in sub-milliseconds when warm
- **Cross-process sharing**: multiple MCP processes share one index; single writer with busy timeout
- **Policy generation invalidation**: index entries tied to RootScope policy digest; stale on revoke/reload
- **Corruption recovery**: integrity_check failure triggers rebuild; live scan repopulates index
- **CLI indexing**: `uam index` for bounded warm-up; `--background` spawns detached worker process (`start_new_session=True`) that survives caller exit
- **Doctor integration**: index health with machine-readable `failure_class`, schema version, freshness, policy alignment, scope obligation (required vs orphaned)
- **Supervisor refresh**: detached worker processes with 600s cooldown; targets only `required` scopes (stale, missing, or policy_mismatch)
- **`authority.index`**: enforced at `index_scope`; scopes with `index=false` cannot be indexed

### v0.4 — Autonomous Reality Discovery

- **RootScope**: standing trust zones with capability inheritance (discover, metadata_read, content_read, text_search, git_observe, auto_admit; plus `directory_admit` after v0.6.0)
- **DiscoveryEngine**: deterministic Git repository scanning, remote identity resolution, worktree grouping, activity classification
- **Auto-admission**: on-demand repository admission inside authorized `auto_admit=true` scopes; requires .git marker and scope authority, not prior inventory membership. A directory without `.git` is never admitted as a repository; it can only become a `filesystem-directory` workspace (profile below), and discovery never lists it
- **ExplorationEngine**: coverage gap analysis, project ranking, "what am I missing?" inference
- **Cross-project search**: ripgrep-based text search with project attribution. Authority is decided before anything is read: the server enumerates the scope, asks the current `text_search` authority about each directory and file, and hands ripgrep only the open, verified files; a budget or ripgrep failure ends a search as explicitly incomplete and never falls back to a wider search

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

### Workspace profile: `filesystem-directory`

Capabilities: `filesystem.read` only. A directory is not a repository, so `git.observe` can never be granted to this kind: registry load rejects it, and Git tools and `repository-change-v1` contracts are refused with `diagnostic.status = UNSUPPORTED_CAPABILITY`.

Two explicit routes, both read-only, neither one discovery:

- **Static registration** — `"kind": "filesystem-directory"` in `workspaces.json`. The owner's explicit grant, served without any RootScope (like static Git workspaces). `repository_identity` and `discovery` are Git-only registry fields and are rejected for this kind.
- **Derived admission** — an explicit `derived:<scope_id>:<rel>` or absolute-path selector inside a scope whose most specific authority sets `directory_admit=true` together with `content_read`.

A `uam_search_scope` hit names where it can be read: each result carries `locator {workspace_id, path, kind}` — the derived workspace that contains the hit (the nearest Git repository at or below the scope root, else the hit's top-level directory, else the scope root) and the path inside it. The locator is a pointer, not a permission: it carries no host path and is resolved against live authority when used, exactly like a handle typed by hand.

Controls (all inherited or added, none relaxed): RootScope authority is re-verified on every request, so revocation is immediate; canonical-path confinement, symlink-escape denial, the secret denylist (case-insensitive), file-size and search limits and the audit chain apply unchanged; authority is checked before the filesystem, so a path outside every authorized scope is refused identically whether or not it exists; a derived directory may not equal, contain or sit inside UAM's own control plane (state, config, credentials, logs, release root), may not have a protected name (for example `.ssh`) in its path below the scope root, and may not span a nested scope, so a more specific scope is never bypassed by admitting one of its ancestors (derived workspaces of both kinds also apply a nested scope per path).

Not provided by design: auto-discovery or indexing of non-Git directories (a separate, held extension); Git observation of directory instances at project level (reported as `observable: false`, "not applicable").

Coverage honesty: `coverage.complete` and `uam_list_workspaces` describe **registered workspaces only** (`basis: registered_workspaces`, `unregistered_root_scope_paths: not_assessed`); discovery coverage states `discovers: git-repositories` and `non_git_directories: not_discovered`. Absence from a scan or listing says nothing about readability.

### MCP tool surface: 20 read-only tools (19 in the published v0.5.1rc1 profile contract)

All tools: `readOnlyHint=true, destructiveHint=false, openWorldHint=false`.

`READ_ONLY_SESSION_PROFILE_V3` (V2's 19 tools plus `uam_file_digest`) is declared in `docs/oss/profile-v3-declaration.json`, which binds the complete tool set, the input/output/safety/description fingerprints and the full metadata difference against V2 (one tool added, seven descriptions changed, nothing removed), and is described by the successor contract `docs/oss/public-profile-contract-v3.md`. `uam_file_digest` is served by the MCP SDK adapter only; `directory_admit` is off by default; static registrations stay independent of RootScopes. V3 is adopted locally (the maintainer's own supervised runtime) and published in 0.6.3. The 19-tool contract of the published v0.5.1rc1 (`docs/oss/public-profile-contract.md`) and its receipts are historical and unchanged.

## 6. Adapter classes

Northbound:
- MCP 2026-07-28 stateless tools adapter — 20 tools via official SDK (READ_ONLY_SESSION_PROFILE_V3 = V2 plus `uam_file_digest`).
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

UAM v0.6.3 release acceptance requires:

1. 20-tool parity under `READ_ONLY_SESSION_PROFILE_V3` (V2's 19 tools plus `uam_file_digest`, bound by `docs/oss/profile-v3-declaration.json` and `docs/oss/public-profile-contract-v3.md`): source = local MCP = tunneled MCP = ChatGPT Web once the connector has been refreshed (seven tool descriptions differ from V2); the 19-tool contract of the published v0.5.1rc1 stays the historical baseline;
2. docs/README/CHANGELOG/MANIFEST all reflect v0.6.3;
3. hermetic Git in all code paths (discovery included);
4. RootScope capability enforcement (git_observe=false blocks git calls, including project-level observation of each instance under its current `git.observe`; index=false blocks indexing);
5. auto-admission: discovered repos usable via existing tools;
6. secret firewall holds for derived workspaces;
7. cross-project search includes project attribution and decides authority before it reads (scope-search enumeration under the current `text_search` authority; a failure or exhausted budget is explicitly incomplete);
8. fresh ChatGPT session can discover/read/explore without prior registration;
9. all regression tests pass against exact release commit;
10. Doctor phase timing present in all health reports;
11. Supervisor incident classification uses specific failure_class from health_report;
12. Index refresh owned by Supervisor detached workers (not Doctor daemon threads);
13. Orphaned/revoked scope rows do not block READY for required scopes;
14. release receipt produced.
