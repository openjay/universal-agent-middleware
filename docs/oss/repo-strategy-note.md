# Repository Strategy Decision Note

**Date:** 2026-09-05  
**Decision:** **Path 1 — Clean Public Genesis**  
**Alternative considered:** Modified Path 2 — direct private→public visibility flip on existing history

## Chosen strategy

**Path 1 — Clean Public Genesis:** retain the private repository as provenance and export a clean single-commit release for the public repository.

Rationale:

1. Private repo preserves full development history and internal evidence for operator use.
2. Public repo receives a sanitized, single-commit genesis without personal-path history exposure.
3. Aligns with O0 privacy gate (history scrub not required on public export).
4. `docs/oss/approved-export-allowlist.json` defines the exact public file set with SHA256 verification.

## Evidence summary

| Factor | Finding |
|--------|---------|
| Commit count (private) | 40+ local commits — retained in private repo |
| Real secrets in history | **None found** — only placeholder API key strings |
| Personal paths in private history | **Present** — not exported to public genesis |
| Personal paths in current `src/` + `tests/` | **Clean** |
| Tracked public candidate files | Verified via allowlist manifest |
| IP sensitivity (user assessment) | Low — path references are not secrets |

## Public export procedure

1. Generate `docs/oss/approved-export-allowlist.json` at candidate commit with SHA256 for every tracked file.
2. Export allowlisted files into a clean public repository (single initial commit).
3. Keep private repo private; do not flip visibility on history-bearing tree.
4. Tag public release `0.5.1rc1` after CI qualification on private remote.

## Namespace note

Public repository: `openjay/universal-agent-middleware` (clean genesis).  
Private provenance repository: retained separately; not made public.
