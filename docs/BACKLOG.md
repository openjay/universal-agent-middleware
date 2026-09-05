# UAM Hardening & Next-Phase Backlog

> v0.5.1rc1 = Public Preview RC1 (operational hardening + read-only MCP observation).
> v0.6+ = Forge/Runtime Observation + Autonomous Execution (planned).

## v0.5.1rc1 — Public Preview RC1 (CURRENT)

### Completed
1. **RootScopeV1** — standing trust zones with capability inheritance
2. **DiscoveryEngine** — deterministic Git repo scanning, remote identity resolution, worktree grouping
3. **ExplorationEngine** — CoverageGap analysis, "what am I missing?"
4. **Cross-project search** — ripgrep-based, scope-bounded (OSS-SEC-001 enforced)
5. **19-tool MCP surface** — all read-only, all audited
6. **Hermetic Git in discovery** — reuses ReadOnlyGit security model
7. **Auto-admission** — derived workspaces from discovered repos
8. **Freshness/coverage metadata** — cache_hit, cache_age_ms, bounded depth disclosure
9. **Audit v2** — POSIX hash chain with process locking and verification
10. **Synthetic portable test suite** — 199 tests (1 skipped), no machine-specific fixtures

### Remaining for GA
- Full negative security suite publication
- Artifact-first install path for all supported platforms
- External onboarding feedback cycle

---

## v0.4.0 — Autonomous Reality Discovery (DONE)

Completed: RootScope, DiscoveryEngine, 19-tool surface, CoverageGap MVP.

---

## v0.3.2 — Semantic Correctness Hardening (DONE)

Completed:
1. **Lifecycle semantics** — split `role` × `lifecycle` (candidate/landed/stale)
2. **observation_requirements** — renamed from `decision_requirements`
3. **NOT_APPLICABLE coverage state** — absent candidate is healthy
4. **Project observation profiles** — project-specific mapping isolated from core

---

## v0.4.x — Hardening (only if real-world usage generates friction)

### P1: Tunnel Durability
Convert `tunnel-client run` to supervised service (launchd, health checks).

### P2: Bootstrap Token/Context Control
Truncate large `git status` in bootstrap to summary + on-demand detail.

### P3: Output Schema Stabilization
Formalize response shapes as versioned JSON schemas.

### P4: Structured Observability
Per-request telemetry (local only, no content/secrets).

### P5: Mount Policy
Enforce `local_fixed/network/removable` classification for machine-wide scopes.
Currently `/` scope is safe-by-default (depth-4 bounded, noise exclusions).

### P6: RealityGraphV1
Full relationship extraction, intent-driven ranking, bounded retrieval plans.
Current: activity ranking + CoverageGap MVP.

---

## v0.6+ — Forge/Runtime Observation + Autonomous Execution (BACKLOG)

### ForgeObservationAdapter
Native GitHub/GitLab CI status readback (PR state, checks, merge status).
Currently handled by `externally_verified` from external tools.

### RuntimeObservationAdapter
Service identity, artifact hash, fleet membership.

### Autonomous Execution Engine
```text
GoalContractV1 → WorkItemV1 → Lease/Heartbeat → Checkpoint
→ Continuation Engine → Executor Router → Attention Inbox
```

---

## Known Non-blocking Anomalies (track, don't fix)

| Item | Status | Action |
|------|--------|--------|
| `harpoon` channel warning in tunnel-client | Non-blocking | Monitor |
| Large dirty worktree in example workspace | Workspace-level | P2 handles context cost |
| Sparkle updaters sensitive to syspolicyd | OS-level | Schedule in watchdog health window |
