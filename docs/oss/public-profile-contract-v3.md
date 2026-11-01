# UAM Session-Read Profile V3 — Successor Contract

**Status:** ADOPTED LOCALLY — the maintainer's own supervised runtime serves it (2026-10-31); published with the 0.6.3 package, see [Adoption and publication](#adoption-and-publication)  
**Profile:** `READ_ONLY_SESSION_PROFILE_V3` — 20 read-only tools: the 19 of `READ_ONLY_SESSION_PROFILE_V2` plus `uam_file_digest`  
**Extends:** `READ_ONLY_SESSION_PROFILE_V2` (19 tools) as served by source commit `e75fe4c88e438a88e52dc56886894930b536ad23` (package `0.6.0`)  
**Predecessor, historical and unchanged:** [`public-profile-contract.md`](public-profile-contract.md) — Public Preview `v0.5.1rc1`, 19 tools. That contract, its receipts and `private-scan-coverage.json` describe a published release and are not rewritten by this document.  
**Machine-readable declaration:** [`profile-v3-declaration.json`](profile-v3-declaration.json), kept honest by `tests/test_profile_v3_declaration.py`

## What this document is, and is not

It is the versioned successor to the V2 inventory for the session-read profile of this source tree, and it makes the 20-tool surface a checked contract instead of a count in prose. It is **not** a release and **not** a GA claim. The profile has been adopted locally, in the maintainer's own supervised runtime, and ships in the 0.6.3 package as part of the Public Preview. The V2 contract remains what the earlier published pre-release (`0.5.1rc1`) promises and is unchanged: a client that stays on that release sees the same 19 tools as before.

## What V3 changes against V2

| Change | Tools | Effect for a connected client |
|--------|-------|-------------------------------|
| **Added** | `uam_file_digest` | A new tool: connectors must Refresh before it appears |
| **Description only** | `uam_git_log`, `uam_git_status`, `uam_list_project_instances`, `uam_list_workspaces`, `uam_project_reality`, `uam_search_scope`, `uam_session_bootstrap` | Same input, output and safety fingerprints; the text a model reads differs, which a release reports as `client_refresh_needed`. (`uam_list_project_instances` and `uam_project_reality` joined the four in v0.6.1: their answers name a discovered worktree by `worktree_id` and, inside a scope, `scope_id` + `relative_path`, and never by an absolute host path. `uam_session_bootstrap` joined in v0.6.3: its description now says that it needs `git.observe` and which tools a `filesystem-directory` workspace uses instead; the server `instructions` route by capability the same way. Its answer, its refusals and every fingerprint other than the description are unchanged.) |
| **Removed** | none | — |
| **Input, output or safety fingerprint changed** | none | No `tool_contract.json` digest of a V2 tool changed |

The complete difference is `metadata_diff_vs_baseline` in the declaration; it is recomputed from the two listings by the test, so this table cannot drift from it unnoticed.

## What the declaration binds

For each of the 20 tools, `candidate.fingerprints` holds the `tool_contract.json` digest and the digest of every top-level field of the tool listing the server advertises. The declaration names which field is which role:

| Role | Listing field |
|------|---------------|
| input | `inputSchema` |
| output | `outputSchema` |
| safety | `annotations` |
| description | `description` |

It also binds the exact tool set (names, count and the digest of the whole contract), the V2 baseline in the same form, and the read-only safety values every tool carries: `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`. The candidate side is produced by running the release pipeline's own probe (`release_probe.PROBE_SOURCE`) unchanged, so the digests are those a release computes and compares; a count that merely matches proves nothing.

**The description digest belongs to a kind of interpreter.** A tool's description is its docstring. Python 3.13 and later strip the common indentation of a docstring when they compile it; earlier interpreters keep it, so one source tree advertises the same wording with different indentation. Measured on this candidate with Python 3.11.15 against 3.14.6 (the service interpreter): 16 of the 20 descriptions differ, and no other field of any tool does. The declared description digests are those of the 3.13+ text, which the declaration records as `description_digest_basis`. The tests compare them only on such an interpreter and compare every other digest on every interpreter; the builder refuses to run on one that keeps the indentation. `tool_contract.json`, and so the release pipeline's contract check, excludes descriptions and is not affected.

## Tool inventory (20)

All tools expose `readOnlyHint=true, destructiveHint=false, openWorldHint=false`.

1. `uam_list_workspaces`
2. `uam_workspace_snapshot`
3. `uam_session_bootstrap`
4. `uam_tree`
5. `uam_read_file`
6. `uam_file_digest` *(new in V3)*
7. `uam_search_text`
8. `uam_git_status`
9. `uam_git_diff`
10. `uam_git_log`
11. `uam_verify_audit`
12. `uam_project_reality`
13. `uam_list_project_instances`
14. `uam_list_scopes`
15. `uam_discover_projects`
16. `uam_scope_inventory`
17. `uam_search_scope`
18. `uam_explain_coverage`
19. `uam_what_am_i_missing`
20. `uam_explore`

## Serving: `uam_file_digest` is served by the SDK adapter only

`uam_file_digest` (SHA-256, size and modification time of a file's raw bytes, never its content) exists only in the MCP SDK adapter (`uam mcp-sdk-stdio --profile session-read`). The legacy HTTP/OpenAPI adapter and the custom stdio MCP adapter do not serve it, and the profile does not claim parity for them: those adapters are outside the Public Preview contract (see the predecessor). The test checks that none of them mentions the tool.

## Defaults and independence

- **Directory admission is off by default.** `directory_admit` is `false` unless a RootScope sets it, and a scope that does not set it keeps its exact `policy_generation`. Reading a folder that is not a Git repository needs an explicit registration or a narrow scope with `directory_admit`; nothing is discovered or indexed by default.
- **Static registration authorization stays independent.** A statically registered workspace is the owner's explicit grant: RootScopes do not narrow it, and a RootScope does not grant it. This is unchanged from V2 and is pinned by tests; changing it is an authorization-semantics decision that needs its own compatibility policy.
- **Authority is decided before anything is read, and observation follows the capability it holds now.** `uam_search_scope` opens only what the current `text_search` authority allows, and project-level Git runs only for an instance whose current registration grants `git.observe`. Neither changes a tool schema; both change what a caller can observe (see `CHANGELOG.md`).

## Supported surface

| Surface | Status |
|---------|--------|
| MCP SDK stdio, `session-read` profile, 20 tools | Adopted locally; published in 0.6.3 |
| `uam_file_digest` outside the SDK adapter | Not served |
| Legacy HTTP/OpenAPI adapter, LocalExecutor | Out of scope, as in the predecessor |
| Streamable HTTP MCP, Windows, NFS, multi-tenant | Not supported (separate gates) |

## Unverified

This document states a contract, not test results. Verification of the adopted profile is kept outside this repository, bound to the adopted commit; here, what is **not** established:

- Python 3.12, Linux, and the public repository's CI matrix (ubuntu and macOS × Python 3.11–3.14) as evidence for this document: that evidence is the GitHub Actions run of the tagged commit, not this text, and the checks behind the adoption ran on local macOS volumes. A local run on the interpreters it names says nothing about the others. Python 3.12 is expected to advertise indented descriptions like 3.11 (the compile-time dedent is a Python 3.13 change); that expectation has not been run.
- A deployment on a Python that keeps docstring indentation (3.11, 3.12): it would advertise the same 20 tools and the same input, output and safety fingerprints with differently indented descriptions, which a release reports as a description change. Whether a connector's Refresh handles that has not been exercised.
- Connector behaviour after the description changes: a client such as ChatGPT Web must Refresh, and that refresh has not been exercised.
- Any run longer than a test: the adoption is one operator's supervised runtime, there is no soak, no third-party deployment is claimed and no GA gate is claimed.
- Behaviour on platforms and filesystems other than the local macOS volumes the checks ran on.

## Adoption and publication

**Adopted locally.** On 2026-10-31 the maintainer activated a sealed release (`uam release --expect-seal`) that carries this profile in the maintainer's own supervised runtime; the release receipt and the Doctor verdict were `READY`, and the receipt records the V3 contract digest (`candidate.contract_sha256`) and the metadata difference above. That release was built from a private development commit. It is an adoption by one operator on one host and is not evidence about any other environment. There are two different ways back, and they do not serve the same surface. As of this adoption the sealed release the maintainer keeps as the fallback is `0.6.2`, a development version that was never published; it also serves 20 tools, so rolling back to it does not return a client to 19. Only an explicit return to the published `0.5.1rc1` (the V2 profile) serves the 19 tools of V2.

**Published.** `0.6.3` is the first release that carries the profile. Its 57 package files (55 modules plus `tool_contract.json` and `task_tool_contract.json`) are byte-identical to the ones in the adopted release, and [`release-0.6.3-product-files.json`](release-0.6.3-product-files.json) lists their SHA-256. The published wheel as a whole is not byte-identical to the adopted one: its metadata, README and project URLs were changed for publication, so it has a hash of its own, recorded in the `SHA256SUMS` of the GitHub release. What shows that the profile is published is the tagged commit, the files PyPI serves and those release assets, not this document.

A connector that already listed the tools of an earlier release must Refresh to see `uam_file_digest` and the changed descriptions; that refresh has not been exercised (see Unverified).
