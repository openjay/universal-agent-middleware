# Roadmap

**Current release:** v0.5.1rc1 Public Preview RC1  
**Contract:** SDK stdio session-read profile, 19 read-only MCP tools

## Public Preview (now)

- [x] Scope search authorization enforcement (OSS-SEC-001)
- [x] Synthetic portable test suite (199 tests, 1 skipped)
- [x] Audit v2 hash chain with verification
- [x] Python 3.11–3.14 × Linux/macOS CI matrix
- [x] Wheel/sdist packaging with clean install smoke
- [ ] External onboarding feedback (post-public)
- [ ] MCP Registry metadata publish (O10, separate from core gates)

## GA Direction

- Full negative security suite published and CI-gated
- Artifact-first install/upgrade on all supported platforms
- Consistent authorization semantics across discovery, search, and read paths
- Third-party reproduction from empty environment without operator fixtures

## Explicitly Deferred

| Area | Notes |
|------|-------|
| Write-capable remote tools | LocalExecutor remains experimental/legacy |
| HTTP/OpenAPI as supported Preview surface | Legacy; stdio is canonical |
| Streamable HTTP MCP | Requires independent protocol acceptance |
| Windows / network FS | Separate portability gates |
| Multi-tenant / OAuth / hosted service | Not in Preview scope |
| Forge/runtime observation adapters | v0.6+ backlog |
| Autonomous execution engine | v0.6+ backlog |

See `docs/BACKLOG.md` for detailed engineering items.
