# Universal Agent Middleware (UAM) v0.5.1rc1

**Public Preview RC1** — read-only MCP observation for local codebases

UAM is a vendor-neutral, local-first middleware that lets any reasoning client (ChatGPT, Claude, Cursor, future agents) observe your local project workspaces in real time through a secure read-only interface — with project-level reality coverage, lifecycle tracking, and observation-based diagnostics.

## What it does

```text
Reasoning client (new session, no history needed)
       │
       ▼
  UAM MCP App (19 read-only tools)
       │
       ▼
  Optional secure MCP tunnel (outbound-only)
       │
       ▼
  Your local machine
       │
       ▼
  Registered workspaces + project reality
  (my-app, api-service, etc.)
```

A new conversation can read live repository state — HEAD, branch, files, diffs, search, project reality coverage — without copy-paste and without granting write access.

## Quick start

### 1. Install from PyPI

```bash
python -m venv .venv && source .venv/bin/activate
pip install universal-agent-middleware==0.5.1rc1
```

Or download the exact wheel/sdist from [GitHub Release v0.5.1rc1](https://github.com/openjay/universal-agent-middleware/releases/tag/v0.5.1rc1) (byte-identical to PyPI).

### 2. Register workspaces

```bash
cp config/workspaces.example.json config/workspaces.json
# Edit workspace roots to match your machine

# Optional: root scope registry for autonomous discovery
cp examples/root_scopes.example.json config/root_scopes.json
```

### 3. Connect your MCP client

UAM exposes **19 read-only tools** over MCP stdio (`session-read` profile). Point your client at:

```text
uam mcp-sdk-stdio --profile session-read \
  --registry /path/to/workspaces.json \
  --state-dir ~/.local/share/uam
```

**Cursor** — add to `.cursor/mcp.json` (or global MCP settings):

```json
{
  "mcpServers": {
    "uam": {
      "command": "uam",
      "args": [
        "mcp-sdk-stdio",
        "--profile", "session-read",
        "--registry", "/path/to/workspaces.json",
        "--state-dir", "/Users/you/.local/share/uam"
      ]
    }
  }
}
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "uam": {
      "command": "uam",
      "args": [
        "mcp-sdk-stdio",
        "--profile", "session-read",
        "--registry", "/path/to/workspaces.json",
        "--state-dir", "/Users/you/.local/share/uam"
      ]
    }
  }
}
```

**ChatGPT** — requires an outbound MCP tunnel (Developer Mode). Configure tunnel credentials via environment only; see `docs/adapters/MCP.md` and `docs/day1a/TUNNEL_RUNBOOK.md`.

### 4. Smoke test (optional)

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
  uam mcp-sdk-stdio --profile session-read \
    --registry config/workspaces.json \
    --state-dir ~/.local/share/uam
```

### Developer install

Contributors may use `pip install -e ".[mcp]"` from a git checkout instead of the PyPI release above.

## Available MCP tools

| Tool | Description |
|------|-------------|
| `uam_list_workspaces` | List registered workspaces, capabilities, and project grouping |
| `uam_workspace_snapshot` | HEAD, branch, head_state, dirty count |
| `uam_session_bootstrap` | Full reasoning context in one call (project-aware, v2 schema) |
| `uam_tree` | Directory listing |
| `uam_read_file` | Read text files (relative paths only) |
| `uam_search_text` | Search across workspace files |
| `uam_git_status` | Git HEAD, branch, working tree changes |
| `uam_git_diff` | Git diff (optionally scoped) |
| `uam_git_log` | Recent commit history |
| `uam_verify_audit` | Hash-chain audit log integrity |
| `uam_project_reality` | Multi-instance project reality snapshot with coverage diagnostics |
| `uam_list_project_instances` | List workspace instances and discovered worktrees for a project |
| `uam_list_scopes` | List authorized RootScopes (standing trust zones) |
| `uam_discover_projects` | Autonomously discover all projects within a scope |
| `uam_scope_inventory` | Cached project inventory for a scope |
| `uam_search_scope` | Cross-project text search across entire scope |
| `uam_explain_coverage` | Per-project coverage gap analysis |
| `uam_what_am_i_missing` | Aggregate missing reality across active projects |
| `uam_explore` | Intent-driven exploration with ranking, graph, and retrieval plan |

All session-read tools expose `readOnlyHint=true, destructiveHint=false`. No write, exec, merge, deploy, or credential tools are part of the Public Preview contract.

## Security model

- **Read-only remote surface** — no mutation tools exposed in session-read profile
- **Path containment** — `.env`, `.git/**`, `../` traversal all denied
- **Prompt injection defense** — security is middleware-enforced, not model-dependent
- **No credentials in repo** — tunnel credentials via environment only
- **Outbound-only tunnel** — no public inbound listener required (optional adapter)
- **Secret firewall** — credential-like files denied even under broad scope authority

## Architecture

```text
Reasoning clients / humans
ChatGPT · Claude · Gemini · Cursor · Copilot · future agents
                    │
          northbound adapters
   HTTP/OpenAPI · MCP (official SDK) · Agent Plugins
                    │
                    ▼
┌────────────────────────────────────────────────┐
│ Universal Agent Middleware Core                 │
│ workspace registry → policy → observation      │
│ project registry → coverage diagnostics        │
│ audit → execution contract → result review     │
└──────────────────┬─────────────────────────────┘
                   │                     │
             READ ONLY                 .state/
                   │              contracts/results/audit
                   ▼
       registered project workspaces
       my-app · api-service · others
```

## Core invariants

- **Vendor-neutral core:** no OpenAI/Anthropic/Cursor/GitHub dependency
- **Project sovereignty:** target project SSOT remains authoritative
- **Read-only boundary:** session-read profile grants no write, shell, commit, push, merge, or deploy
- **Observation ≠ Authority:** UAM reports reality; project governance decides actions
- **Separate state:** UAM state is physically disjoint from target workspaces
- **Evidence-bound execution:** (v0.2+ contracts; legacy LocalExecutor is experimental)

## Project reality model (v0.3.1+)

UAM tracks multi-instance projects with orthogonal dimensions:

- **role** — structural function: `canonical-main`, `candidate`, `review-carrier`
- **lifecycle** — temporal state: `active`, `landed`, `stale`, `superseded`
- **coverage** — observation completeness per truth surface

Coverage states: `observed`, `externally_verified`, `not_applicable`, `not_observed`, `not_registered`

Project-specific observation profiles in `config/project-observation-profiles/` (local-only, gitignored) define per-project requirements without embedding project semantics into UAM core.

## Documentation

- `docs/REALITY_PREAMBLE.md` — Reality Preamble protocol
- `docs/BACKLOG.md` — Roadmap and hardening priorities
- `docs/adapters/MCP.md` — MCP adapter setup
- `docs/oss/public-profile-contract.md` — Public Preview supported surface
- `CHANGELOG.md` — Version history
- `SECURITY.md` — Vulnerability reporting
- `CONTRIBUTING.md` — Contribution guidelines

## Status

**v0.5.1rc1 — Public Preview RC1**

| Gate | Status |
|------|--------|
| Source implementation | PASS (19 read-only MCP tools) |
| RootScope foundation | PASS |
| Git repository discovery | PASS |
| Project grouping | PASS |
| CoverageGap MVP | PASS |
| Audit v2 integrity | PASS |
| Scope search enforcement | PASS (OSS-SEC-001 pre-read boundary) |
| Portable test suite | PASS (199 tests, 1 skipped; synthetic fixtures) |
| Python/OS matrix (3.11–3.14) | **PASS** — 8/8 public CI (run `33954828455`) |
| Public release gates (O0–O9) | **PASS** — live public repo; see `docs/oss/launch-packet.md` |
| GitHub Release `v0.5.1rc1` | **PASS** — wheel + sdist attached |
| PyPI distribution | **PASS** — [0.5.1rc1 live](https://pypi.org/project/universal-agent-middleware/0.5.1rc1/); `pip install universal-agent-middleware==0.5.1rc1` verified |

Public Preview supports SDK stdio session-read profile only. Legacy HTTP adapter and LocalExecutor are experimental and not part of the Preview contract. See `docs/oss/public-profile-contract.md`.

Deferred: forge/runtime observation, write-capable remote tools, autonomous execution, production OAuth.
