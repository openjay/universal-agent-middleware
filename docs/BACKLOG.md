# UAM Hardening & Next-Phase Backlog

> v0.5.1rc1 = Public Preview RC1 (operational hardening + read-only MCP observation).
> v0.6+ = Forge/Runtime Observation + Autonomous Execution (planned).

## Release pipeline follow-ups (found in a pre-production review)

### Build the release from the locked commit, not from the working tree — RESOLVED in 0.6.1 (F-REL-1)
`release._stage_candidate` checked that HEAD was the intended commit and the tree clean, but
`release._build_release` then built the wheel from the mutable working tree, and
`release._verify_artifacts` compared the installed package files with that same working tree. Anything
that changed between the clean check and the build yielded an artifact that matched the working tree and was
recorded under the old commit, and the artifact check could not see it.

Resolved: `release_build.py` exports the commit with `git archive` into a private directory (proved equal
to the commit's tree object by object), builds the wheel from that export only, and `verify_build` proves
before the manifest is written that the wheel holds exactly the commit's package files plus its own
`dist-info` and that the installed package equals the commit's Git blobs. `artifact_verify` and
`uam release-seal` apply the same inventory check. Remaining, by design of this fix: bytecode is not part
of the compared set, the build backend and the interpreter that runs it are not pinned (a reproducible
wheel digest across hosts is not claimed), and `installer stage` still builds from a `git archive`
extraction with `python -m build` without the wheel and installed-package comparison that `uam release`
performs.

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

## `filesystem-directory` follow-ups (opened with the directory-workspace fix)

The directory workspace kind itself is implemented (see `CHANGELOG.md`, `docs/SSOT.md`). What stays open, none of it blocking:

### HOLD: automatic discovery of non-Git directories
Deliberately not done. Discovery, indexing and bare-name resolution see Git repositories only, and a directory is admitted only by an explicit path. Admitting every ordinary folder by default would make `directory_admit` on a broad scope a blanket read grant over everything not protected by name. An independent compatibility extension, not part of Task Coordination: it needs its own bounds (depth, count, size), a per-folder opt-in marker or allowlist, index schema support, and the same conformance tests as the kind itself.

### P2: directory-aware `uam_session_bootstrap` / `uam_workspace_snapshot`
Both need `git status`, so on a directory workspace they refuse with the `UNSUPPORTED_CAPABILITY` diagnostic. A bootstrap that returns the tree and the readable top-level files without Git changes those tools' output shape, which is a contract change (`tool_contract.json`).

### P2: `deny_paths` for a directory workspace (considered, not built)
A per-workspace deny list looks like a cheap way to exclude `evidence/` inside an admitted folder, but as a control it would be partial: it must be case-folded on case-insensitive filesystems, must resolve to the same inode (not just the same spelling), and `uam_search_scope` reads the tree without going through a workspace. A narrow RootScope around the folder to read, or a nested scope with `text_search=false` around the part to hide, already covers it with existing, enforced semantics.

### P2: RootScope authority at file level — done for derived workspaces, two things open
Derived workspaces of either kind now apply the most specific scope per path (see `CHANGELOG.md`, path-level authority). Open: a static registration is still the owner's explicit grant and ignores nested denials; changing that is an authorization-semantics decision that needs a compatibility policy of its own. Also open and optional: directory admission still refuses to span a nested scope, which the per-path rule would now make unnecessary.

### Done: capability gate for project-level Git tools
Project-level Git observation now follows each instance's current capability (`CHANGELOG.md`, `docs/SECURITY_MODEL.md`): a static instance needs `git.observe` in the live registry entry, a derived one the live resolver and its effective RootScope, directory instances are never handed to Git, and an instance that is not asked is reported `observable: false`, never as clean or complete. What stays open, none of it blocking: the instances of a project are built when the gateway is constructed, so a changed project definition needs a restart; and the derived branch has no production caller (a project definition holds registered workspaces only), so tests reach it by injection.

### P3: `uam_search_scope` path membership
`uam_search_scope` is governed by the scope's `text_search` bit and is not limited to repositories or admitted workspaces: it can reveal that a file in a non-admitted directory contains a query. Hits now carry a `locator` so a hit can be followed to a read; that is a pointer, not a permission, and does not change the membership question. Scope Search v2 decides authority before it reads (a denied directory is never listed and a denied file never opened; see `docs/SECURITY_MODEL.md`), which closes the read-before-filter window but not this question: inside a `text_search=true` scope the answer still reveals which allowed files contain a query. Options: restrict it to discovered repositories and admitted workspaces, or require `directory_admit` for non-Git paths. Both change what existing scopes can search.

---

## Boundaries registered by the integration audit

Named by the independent audit of the 2026-10-12 integration candidate, plus one (advertised descriptions) that the candidate's own clean-room run on Python 3.11 exposed. They are recorded so that they are tracked, not because the candidate reproduced them as defects, and none was changed by it. Each needs its own decision, evidence or compatibility policy before it is built.

### P2: per-workspace `allowed_paths` / `denied_paths`
Not implemented: no workspace registration carries such lists (the only allow-list in the code base is the change-contract field `allowed_change_paths`). Considered and not built as a partial control (see the `deny_paths` entry above); a narrow RootScope, or a nested scope with `text_search=false`, is the enforced mechanism.

### P2: static registrations stay independent of RootScopes
Unchanged by design (see the file-level authority entry above). Registered again because project-level Git and scope search were both changed around it, and tests now state the independence explicitly.

### P3: `uam_file_digest` change detection is cooperative
A digest is claimed only when the open descriptor and the path keep the same device, inode, size and modification time from before the first byte to after the last (`file_digest.py`). A file rewritten in place with the same size and modification time is indistinguishable from an unchanged one, and a read blocked on a stalled device is not interrupted. A refused digest (`byte_limit`, `os_permission_denied`) still reports the `size_bytes` and `mtime_ns` of a file that the read authority already covers, before any limit is applied.

### P3: per-workspace `uam_search_text` is path-based and has its own text domain
It walks the workspace by path and reopens each file by path after the check (Scope Search v2 closed that window for `uam_search_scope` only). Its domain (a NUL probe of the first 8 KiB, `max_file_bytes`, `max_search_files`, no ignore files) is reported through counters, not through a declared `search_domain`.

### P3: advertised tool descriptions depend on the interpreter's docstring handling
A tool's MCP description is its docstring. Python 3.13 and later strip docstring indentation at compile time and 3.11 and 3.12 do not, so one source tree advertises the same wording with different indentation (measured, 3.11.15 against 3.14.6: 16 of 20 descriptions, nothing else). The adapter does not normalise them: doing so would touch every tool registration and would have to leave the 3.14 text byte-identical so that no connector needs a Refresh. `tool_contract.json` excludes descriptions; the V3 declaration binds the 3.13+ text and its tests say so. Not verified: a deployment on Python 3.12 (expected to behave like 3.11) and a connector's Refresh after such a change.

### P3: `uam_tree` reports file sizes without the hard-link rule
`uam_tree` checks enumeration authority per path and reports a regular file's size without the other-names rule that read, digest and search apply, so the size of a file that also has a name inside a nested scope that denies reading is visible through its allowed name.

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
| Loopback HTTP tests with 3–5 s client timeouts (`test_workspace_unavailable.py::StatusEndpointTests`, `test_mcp_http.py`, `test_api_e2e.py`, `test_filesystem_directory_adapters.py`) fail intermittently on a heavily loaded macOS host | Host-level; present on the unchanged baseline too | Measured on 2026-10-12 with `StatusEndpointTests` repeated in-process: baseline 1/150 (Python 3.11) and 5/150 (3.14), integration candidate 10/150 (3.11, one burst) and 3/150 (3.14). Stacks captured 2 s into a stalled request show the server's handler thread idle in `readinto` (waiting for the request line) and the client in `getresponse`: the request bytes had not arrived, no product code was running. The host load average was 90–165 with `fseventsd` above 150% CPU. Rerun before reading one red run of these as a regression; raising the timeouts was deliberately not done as part of the integration |
