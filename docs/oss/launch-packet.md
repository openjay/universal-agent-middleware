# OSS Public Preview Launch Packet

**Prepared:** 2026-09-05  
**Target:** Public Preview RC1 (`0.5.1rc1`)  
**Genesis commit:** `cd6e50ba865fc98e70e41c6742a863b8f2bf89e9` (openjay/universal-agent-middleware `main`)  
**Repository strategy:** Path 1 — Clean Public Genesis (private repo retained as provenance)

## Executive Summary

GO-PUBLIC-CODE is **COMPLETE**. The public candidate has **111 tracked files** (allowlist-verified with SHA256), **zero personal-path hits in tracked content**, **199 passing tests** (1 skipped), **100% pinned GitHub Action SHAs**, and **8/8 CI matrix cells green** on public CI run `33954828455`. GO-DISTRIBUTION (tag, GitHub Release, PyPI OIDC) proceeds under explicit authorization.

## Gate Readiness (O0–O9)

| Gate | Status | Evidence |
|------|--------|----------|
| **O0 Privacy** | **PASS** | Path 1 genesis; 39 PRIVATE_RETAIN untracked; allowlist manifest (111 files) |
| **O1 Truth** | **PASS** | README/SSOT aligned to v0.5.1rc1, 19 tools; `public-profile-contract.md` **ACCEPTED** |
| **O2 Reproducibility** | **PASS (local + public CI)** | `pytest -q`: 199 passed, 1 skipped; sdist collect-only: 200 tests, 0 errors |
| **O3 Portability** | **PASS (public CI)** | 8/8 matrix green — run `33954828455` (ubuntu + macos × 3.11–3.14) |
| **O4 Security** | **PASS** | OSS-SEC-001 pre-exclusion globs + disjoint sub-roots + post-filter; PVR enabled |
| **O5 Packaging** | **PASS** | MANIFEST.in includes tests/fixtures; sdist + wheel built |
| **O6 Supply Chain** | **PASS (pre-release)** | Split build/publish jobs; 100% pinned 40-char action SHAs; attestation in release.yml |
| **O7 Community** | **PASS** | SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, GOVERNANCE.md, ROADMAP.md |
| **O8 Runtime Honesty** | **PASS** | public-profile-contract.md ACCEPTED; legacy HTTP/LocalExecutor marked experimental |
| **O9 Release Baseline** | **IN PROGRESS** | Genesis `cd6e50b` exported; tag `v0.5.1rc1` + PyPI under GO-DISTRIBUTION |

## CI Qualification (public remote)

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

**Workflow run:** `33954828455` on `openjay/universal-agent-middleware` — 8/8 PASS (2026-09-05T08:18:27Z).

## Artifacts (0.5.1rc1)

| Artifact | Notes |
|----------|-------|
| `universal_agent_middleware-0.5.1rc1-py3-none-any.whl` | Built via release workflow + local smoke verification |
| `universal_agent_middleware-0.5.1rc1.tar.gz` | Includes tests/ via MANIFEST.in; 200 tests collected |

## Allowlist manifest

- **File:** `docs/oss/approved-export-allowlist.json`
- **Files covered:** 111 / 111 (100% of public candidate tree)
- **Generated:** see `generated_at` in manifest
- **Baseline commit:** `cd6e50ba865fc98e70e41c6742a863b8f2bf89e9` (genesis)

## Decision Points

| Point | Status |
|-------|--------|
| GO-PREP | **COMPLETE** — OSS-4.5 repair slice |
| GO-PUSH-PRIVATE | **COMPLETE** — convergence commit push + private CI 8/8 |
| GO-PUBLIC-CODE | **COMPLETE** — genesis `cd6e50b`, public CI `33954828455` 8/8 |
| GO-DISTRIBUTION | **IN PROGRESS** — tag `v0.5.1rc1`, GitHub Release, PyPI OIDC |

## Unresolved / Known Limitations

- Private repo history contains personal paths (not exported under Path 1)
- Production service on operator Mac is independent of public Preview
- PyPI Trusted Publisher OIDC must be configured on pypi.org for automated publish
- Windows/NFS/multi-tenant explicitly out of Preview scope

## Path 1 — Clean Public Genesis (executed)

Genesis export completed 2026-09-05:

- **Public repo:** `openjay/universal-agent-middleware`
- **Genesis commit:** `cd6e50ba865fc98e70e41c6742a863b8f2bf89e9`
- **Public CI qualification:** run `33954828455` (8/8 PASS)
- **Provenance retained:** `openjay/uam-provenance` (private)

Verification command (0 mismatches required):

```bash
python3 - <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(".")
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
```

Do **not** flip private repo visibility. Retain private repo as provenance; public repo receives genesis commit only.
