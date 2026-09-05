# UAM Public Preview Profile Contract

**Status:** ACCEPTED — R1 8-cell CI matrix and R2 pre-read physical boundary tests fully qualified  
**Baseline:** v0.5.1rc1 source tree (Public Preview RC1)  
**License:** MIT (see `license-decision.md`)

## Product promise

Universal Agent Middleware gives AI agents a live, scoped view of local codebases through a **read-only MCP observation profile**.

Public Preview is **not** Production GA. It establishes a reproducible, safe baseline for external verification of permission boundaries and audit behavior.

## Supported surface (Preview)

| Surface | Status | Entry point |
|---------|--------|-------------|
| MCP SDK stdio | **Supported** | `uam mcp-sdk-stdio --profile session-read` |
| 19 read-only tools | **Supported** | Derived from `tool_contract.json`; no hand-counted runbooks |
| Workspace registry | **Supported** | `config/workspaces.example.json` → user-local `config/workspaces.json` |
| Root scope registry | **Supported** | `examples/root_scopes.example.json` → user-local config |
| Audit hash chain | **Supported** | POSIX local FS; cooperating-writer model |
| Git / rg observation | **Supported** | External tools; missing rg returns explicit error |

## Explicitly excluded or experimental

| Surface | Status | Notes |
|---------|--------|-------|
| LocalExecutor | **Experimental / legacy** | Write-capable; not part of session-read Preview |
| HTTP/OpenAPI adapter | **Legacy** | Different surface; not qualified for Preview claims |
| Streamable HTTP MCP | **Not supported** | No independent protocol acceptance |
| macOS launchd service | **Optional adapter** | Not required for core stdio quickstart |
| Secure tunnel / platform keys | **Optional** | Core stdio quickstart does not require provider accounts |
| Windows / NFS / multi-tenant | **Not supported** | Separate gates required |

## Read-only definition

- Session-read MCP grants **no** write, shell, commit, push, merge, or deploy tools to the caller.
- UAM writes its own audit/state internally; internal Git/rg subprocesses are **not** shell access for the caller.
- Returned file content is **untrusted data**; middleware enforces path containment and secret firewall, but does not eliminate prompt injection risk.

## Default configuration contract

- Empty authority or explicit placeholder examples only.
- No automatic inheritance of operator HOME or personal code roots.
- `config/workspaces.json` and `config/root_scopes.json` are **local-only** (gitignored); examples ship in-repo.

## Tool inventory (19)

All tools expose `readOnlyHint=true, destructiveHint=false`:

1. `uam_list_workspaces`
2. `uam_workspace_snapshot`
3. `uam_session_bootstrap`
4. `uam_tree`
5. `uam_read_file`
6. `uam_search_text`
7. `uam_git_status`
8. `uam_git_diff`
9. `uam_git_log`
10. `uam_verify_audit`
11. `uam_project_reality`
12. `uam_list_project_instances`
13. `uam_list_scopes`
14. `uam_discover_projects`
15. `uam_scope_inventory`
16. `uam_search_scope`
17. `uam_explain_coverage`
18. `uam_what_am_i_missing`
19. `uam_explore`

## Python / platform matrix (target)

| OS | Python | CI status |
|----|--------|-----------|
| Linux | 3.11–3.14 | **PASS** — 8/8 public CI (run `33954828455`) |
| macOS | 3.11–3.14 | **PASS** — 8/8 public CI (run `33954828455`) |

Full 8-cell matrix qualification (gate O3 / R1) is complete on the live public repository `openjay/universal-agent-middleware` at genesis commit `cd6e50b`.

## Security negatives (R2 qualified for Preview)

Scope precedence, content-read authorization before file access, secret-parent exclusion, symlink traversal, path encoding, error redaction, default-deny, audit tampering detection, and restart-storm behavior pass dedicated negative tests (gate O4 / R2 pre-read physical boundary). GA may require additional surfaces beyond session-read Preview.
