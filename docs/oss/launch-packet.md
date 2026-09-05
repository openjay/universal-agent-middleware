# OSS Public Preview Launch Packet

**Prepared:** 2026-09-05  
**Target:** Public Preview RC1 (`0.5.1rc1`)  
**Candidate commit:** see `approved-export-allowlist.json` → `baseline_commit` (qualified at export time)  
**Repository strategy:** Path 1 — Clean Public Genesis (private repo retained as provenance)

## Executive Summary

Final convergence (Steps 1–4) completes on the private remote after push and CI qualification. The public candidate has **111 tracked files** (allowlist-verified with SHA256), **zero personal-path hits in tracked content**, **199 passing tests** (1 skipped), **100% pinned GitHub Action SHAs**, and requires **8/8 CI matrix cells green** on the candidate commit at export time. Public visibility flip and PyPI distribution remain blocked pending explicit GO-PUBLIC-CODE and GO-DISTRIBUTION authorization.

## Gate Readiness (O0–O9)

| Gate | Status | Evidence |
|------|--------|----------|
| **O0 Privacy** | **PASS (tree)** / Path 1 genesis | 39 PRIVATE_RETAIN untracked; allowlist manifest (111 files) |
| **O1 Truth** | **PASS** | README/SSOT aligned to v0.5.1rc1, 19 tools; `public-profile-contract.md` **ACCEPTED** |
| **O2 Reproducibility** | **PASS (local + CI)** | `pytest -q`: 199 passed, 1 skipped; sdist collect-only: 200 tests, 0 errors |
| **O3 Portability** | **PASS (private CI)** | 8/8 matrix green — R1 qualified (ubuntu + macos × 3.11–3.14) |
| **O4 Security** | **PASS (R2 qualified)** | OSS-SEC-001 pre-exclusion globs + disjoint sub-roots + post-filter |
| **O5 Packaging** | **PASS (local)** | MANIFEST.in includes tests/fixtures; sdist + wheel built |
| **O6 Supply Chain** | **READY (pre-config)** | Split build/publish jobs; 100% pinned 40-char action SHAs; PyPI OIDC pending GO-DISTRIBUTION |
| **O7 Community** | **PASS** | SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, GOVERNANCE.md, ROADMAP.md |
| **O8 Runtime Honesty** | **PASS** | public-profile-contract.md ACCEPTED; legacy HTTP/LocalExecutor marked experimental |
| **O9 Release Baseline** | **PENDING (post-public)** | Requires clean genesis export + tagged release after GO-PUBLIC-CODE |

## CI Qualification (private remote)

| Cell | Result |
|------|--------|
| ubuntu-latest × Python 3.11 | PASS |
| ubuntu-latest × Python 3.12 | PASS |
| ubuntu-latest × Python 3.13 | PASS |
| ubuntu-latest × Python 3.14 | PASS |
| macos-latest × Python 3.11 | PASS |
| macos-latest × Python 3.12 | PASS |
| macos-latest × Python 3.13 | PASS |
| macos-latest × Python 3.14 | PASS |

**Workflow run:** see `private-scan-coverage.json` `ci_qualification.run_id` for latest qualified run.

## Artifacts (local build, 0.5.1rc1)

| Artifact | Notes |
|----------|-------|
| `universal_agent_middleware-0.5.1rc1-py3-none-any.whl` | Built locally; hash recorded at release time |
| `universal_agent_middleware-0.5.1rc1.tar.gz` | Includes tests/ via MANIFEST.in; 200 tests collected |

## Allowlist manifest

- **File:** `docs/oss/approved-export-allowlist.json`
- **Files covered:** 111 / 111 (100% of `git ls-files`)
- **Generated:** see `generated_at` in manifest
- **Baseline commit:** see `baseline_commit` in manifest

## Decision Points

| Point | Status |
|-------|--------|
| GO-PREP | **COMPLETE** — OSS-4.5 repair slice |
| GO-PUSH-PRIVATE | **IN PROGRESS** — convergence commit push + CI 8/8 qualification |
| GO-PUBLIC-CODE | **HOLD** — owner authorization required |
| GO-DISTRIBUTION | **HOLD** — PyPI OIDC + post-public verification |

## Unresolved / Known Limitations

- Private repo history contains personal paths (not exported under Path 1)
- Production service on operator Mac is independent of public Preview
- Attestation verification deferred until public repo + release tag exist
- Windows/NFS/multi-tenant explicitly out of Preview scope

## Path 1 — Clean Public Genesis (ready on GO-PUBLIC-CODE)

Once owner authorization is given, export the exact 111-file candidate in a single step:

```bash
# From private provenance repo at the qualified candidate (HEAD or tagged baseline):
BASELINE="$(git rev-parse HEAD)"
# Optional cross-check: should match docs/oss/approved-export-allowlist.json baseline_commit ± allowlist pin commit
git archive --format=tar "$BASELINE" | tar -x -C /tmp/uam-public-genesis

# Verify every allowlisted file hash (0 mismatches required):
python3 - <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path("/tmp/uam-public-genesis")
doc = json.loads((root / "docs/oss/approved-export-allowlist.json").read_text())
placeholder = "0" * 64
bad = []
for e in doc["files"]:
    p = root / e["path"]
    if e["path"] == "docs/oss/approved-export-allowlist.json":
        t = p.read_text().replace(e["sha256"], placeholder, 1)
        h = hashlib.sha256(t.encode()).hexdigest()
    else:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != e["sha256"]:
        bad.append(e["path"])
print(f"mismatches: {len(bad)}")
sys.exit(1 if bad else 0)
PY

# Initialize clean public repo (no history from private remote):
cd /tmp/uam-public-genesis
git init -b main
git add -A
git commit -m "Public Preview RC1 genesis (0.5.1rc1)"
git remote add origin git@github.com:openjay/universal-agent-middleware.git
git push -u origin main --force  # empty public repo only; never force-push private provenance
git tag -a v0.5.1rc1 -m "Public Preview RC1"
git push origin v0.5.1rc1
```

Do **not** flip private repo visibility. Retain private repo as provenance; public repo receives genesis commit only.
