# Changelog

## v0.5.1rc1 — Public Preview RC1

- OSS convergence: 111-file export allowlist with SHA256 verification, 100% pinned GitHub Action SHAs, 8-cell CI matrix qualified.
- OSS-SEC-001 pre-read boundary enforcement with rg exclusion globs and disjoint sub-roots.
- `public-profile-contract.md` ACCEPTED — 19 read-only MCP tools, session-read Preview surface.
- Path 1 clean public genesis procedure documented; private repo retained as provenance.

## v0.5.0 — operational hardening

- POSIX audit v2 with process locking, durable writes, structured verification and explicit legacy migration.
- Shared runtime manifest, semantic Doctor, persistent P0 freeze and transactional recovery budget.
- Clean archived source, immutable release identity, verified staging and explicit macOS activation.
- Isolated test state and explicit search dependency/timeout failures. No new MCP tools or workspace authorization.
- Production migration and canonical landing remain pending; see the hardening program document.

All notable changes to Universal Agent Middleware are documented here.

## [0.4.0] — 2026-08-09 — Autonomous Reality Discovery

### Added
- RootScopeV1 authority model: standing trust zones with capability inheritance
- DiscoveryEngine: deterministic Git repository scanning and project identification
- Remote identity resolution: groups worktrees into logical projects
- Activity classification: active/recent/dormant/archived
- Cross-project search via ripgrep across entire authorized scope
- CoverageGapV1: referenced-but-unobserved surface inference
- ExplorationEngine: "what am I missing?" aggregation
- Project-specific observation profiles (`config/project-observation-profiles/`)
- 6 new MCP tools: `uam_list_scopes`, `uam_discover_projects`, `uam_scope_inventory`, `uam_search_scope`, `uam_explain_coverage`, `uam_what_am_i_missing`
- `uam_explore`: intent-driven autonomous exploration with RealityGraphV1, retrieval planning
- `config/root_scopes.json`: machine discovery + code root read authority
- Program SSOT archived in `docs/programs/`

### Changed
- Tool surface: 10 → 19 read-only tools
- Architecture: passive registration → autonomous discovery within trust zones
- Version numbering: v0.4 = Reality Discovery (Autonomous Execution deferred to v0.5)

### Security
- Secret firewall preserved under broad scope authority
- All new tools remain `readOnlyHint=true, destructiveHint=false`
- Discovery reuses hermetic ReadOnlyGit (fsmonitor/pager/external disabled)
- RootScope capability enforcement: `git_observe=false` blocks all git probing
- Auto-admitted derived workspaces inherit secret firewall and path containment
- Broad discovery operations recorded in hash-chained audit log

## [0.3.2] — 2026-08-08 — Semantic Correctness Hardening

### Added
- `lifecycle` field: orthogonal to `role` (active/landed/stale/superseded)
- `not_applicable` coverage state: absent candidate is healthy
- `observation_requirements`: renamed from `decision_requirements`
- `authority_evaluation`: explicit `{mode: PROJECT_DEFINED, evaluated_by_uam: false}`
- Project observation profiles: `config/project-observation-profiles/`
- 20 acceptance tests (T1-T6)

### Changed
- Schema version: `project-reality-snapshot-v2`
- Machine invariant: `UAM_COVERAGE_COMPLETE ≠ PROJECT_AUTHORITY_GRANTED`

## [0.3.1] — 2026-08-08 — Project Reality Coverage

### Added
- `ProjectRegistry`: multi-instance project model
- `WorkspaceInstance`: role + project grouping
- Git worktree discovery: auto-detect worktrees for registered repos
- `ProjectRealitySnapshotV1`: coverage diagnostics (COMPLETE/PARTIAL/UNKNOWN)
- 2 new MCP tools: `uam_project_reality`, `uam_list_project_instances`
- `session-context-pack-v2`: project-aware bootstrap

## [0.3.0] — 2026-08-08 — Live Human Reasoning Bridge

### Added
- Official MCP Python SDK adapter (`src/universal_agent_middleware/adapters/mcp_sdk.py`)
- Read-only ChatGPT session profile (`READ_ONLY_SESSION_PROFILE_V1`)
- Secure MCP Tunnel integration via `tunnel-client` v0.0.11
- ChatGPT Developer Mode plugin: 10 read-only observation tools
- `WorkspaceSnapshotV1` — lightweight workspace state in one call
- `SessionContextPackV1` — full reasoning bootstrap in one call
- Workspace context profiles (`config/workspace-contexts/*.json`)
- `head_state` field: explicit `attached`/`detached` disambiguation
- Freshness test workspace for live-data proof
- Prompt injection test fixture

### Security
- No mutation tools exposed to remote clients
- Direct `.git/` reads denied at adapter level
- Secret/dotfile path denial (`.env`, credentials)
- Path traversal containment (`../` cross-workspace)
- Prompt-injection containment: security is middleware-enforced, not model-dependent
- Absolute paths omitted in remote responses
- No credentials committed to repository

### Verified (E2E)
- 78 regression tests (all pass)
- Local MCP interoperability (stdio, annotations)
- Secure tunnel connectivity and health
- ChatGPT Web live invocation (Gate E1)
- Ground-truth parity: HEAD, branch, dirty state (Gate E2)
- Security negatives: .env, .git, traversal all denied (Gate E3)
- Runtime freshness: HEAD/content change without reconnect (Gate E4)
- Fresh-clone reproducibility from tag (Gate F): 78/78 tests, MCP 10/10, zero mutations
- Source/runtime skew detection and resolution: serving process reload verified
- Session continuity across UAM runtime reload: existing ChatGPT session consumed new `head_state` semantics without Refresh or reconnect
- Secret provenance scan: 0 credentials in tree or full git history

### Operational Properties Proven
- Workspace data freshness: live per-invocation (no caching)
- Middleware runtime upgrade: existing sessions survive backend restart
- Session disposability: conversation history ≠ project state
- Tunnel health continuity: readyz/healthz maintained across process cycles

### Known Non-blocking
- `tunnel-client` "harpoon" channel warning: does not affect MCP data path
- Large dirty worktree in example workspace: workspace-level, not UAM issue; bootstrap truncation in backlog
- Tunnel is runtime-live, not yet 24/7 durable service (launchd hardening in backlog)

### Not Yet Included
- Write-capable northbound MCP tools
- Goal/WorkItem continuation engine
- Persistent external executor (24h autonomous)
- Mobile MCP support (web only)
- Production OAuth / service-account hardening
- Multi-executor routing (Claude Code / Codex)

## [0.2.0] — 2026-08-08

### Established
- UAM v0.2.0 baseline: 50/50 tests, manifest-verified source
- Independent standalone repository
- Example workspace registration with synthetic and local fixtures
- Observation E2E: tree/read/search/git against real repos
- Security controls: traversal, secret, cross-workspace denial
- First `repository-change-v1` Execution Contract
- Local executor adapter with scope checking and verification
- Full closed-loop: Contract → Execute → Result → Review

### Architecture
- Vendor-neutral core with no required vendor dependency
- Physical state/workspace isolation enforced
- Hash-chained audit log
- Immutable contracts and executor results
- Bounded execution with explicit path allowlists
