# Universal Agent Middleware (UAM) v0.6.3

**Scope-authorized, registration-optional read-only observation**

UAM is a vendor-neutral, local-first middleware that lets any reasoning client (ChatGPT, Claude, Cursor, future agents) observe your local project workspaces in real time through a secure read-only interface — with project-level reality coverage, lifecycle tracking, and observation-based diagnostics.

## What it does

```text
Reasoning client (new session, no history needed)
       │
       ▼
  UAM MCP App (20 read-only tools)
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

### 1. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install "universal-agent-middleware[mcp]==0.6.3"
uam --help
```

Python 3.11 or later. PyPI and the [GitHub release `v0.6.3`](https://github.com/openjay/universal-agent-middleware/releases/tag/v0.6.3) carry the same wheel and sdist, byte for byte; the release lists their SHA-256 in `SHA256SUMS`, and `.github/workflows/release.yml` checks that the three agree. The wheel contains the package only: it does not ship the `config/`, `examples/` or `tools/system-service` directories of this repository, so nothing below asks you to copy a file out of a checkout.

**Upgrading from `0.5.1rc1`.** This is for a standalone virtualenv of your own, such as the one step 1 creates. In it, `pip install --upgrade "universal-agent-middleware[mcp]==0.6.3"` replaces the package in place, and a registry file, a `--state-dir` and an audit chain written under `0.5.1rc1` keep working as they are. Do not run `pip` inside a managed UAM release (`releases/**/venv`): a release is immutable and sealed to its file inventory, and a managed install changes by stage, seal and release (`installer stage`, `uam release-seal`, `uam release --expect-seal`; see "Cutting a release (operators)" below), never by editing a release in place. Measured on the real stdio server (`uam mcp-sdk-stdio --profile session-read`) with one registered workspace, on macOS with Python 3.14, `0.5.1rc1` as published on PyPI against the `0.6.3` package:

- 20 tools instead of 19: `uam_file_digest` is added and none is removed. No tool's input schema or annotations changed; 11 tool descriptions changed, so an MCP client has to refresh its tool list (a ChatGPT connector: Refresh).
- On the six read calls compared, results only gained fields (for example `schema_version` in `uam_list_workspaces`, `history_available` in `uam_git_status`, `integrity_scope` in `uam_verify_audit`); none lost one.
- An audit chain written by `0.5.1rc1` verified under `0.6.3` (`uam_verify_audit` reported `PASS`), and `0.5.1rc1` verified it again after `0.6.3` had appended to it. To go back, `pip install "universal-agent-middleware[mcp]==0.5.1rc1"` in the same virtualenv. That was tried on one state directory only, so before you upgrade stop whatever writes to the registry and the state directory, and keep a copy of the original state directory, registry and configuration files, and the output of `pip freeze`, as they were before the upgrade: that copy is the rollback you can rely on.

Not covered by that measurement: anything beyond one workspace on macOS with Python 3.14 (other registries and state, Linux and other platforms, other Python versions), the `uam release` and macOS service path, and a state directory holding an index built by a longer-lived install.

### 2. Register a workspace

The registry is an explicit list: nothing is readable until it is named here. Create it anywhere; the examples use `~/.config/uam/`:

```bash
mkdir -p ~/.config/uam ~/.local/share/uam
cat > ~/.config/uam/workspaces.json <<'EOF'
{
  "registry_version": "uam-workspace-registry-v1",
  "workspaces": [
    {
      "workspace_id": "myproject",
      "label": "My project",
      "root": "/absolute/path/to/a/git/repository",
      "kind": "git-repository",
      "capabilities": ["filesystem.read", "git.observe"]
    }
  ]
}
EOF
uam doctor --registry ~/.config/uam/workspaces.json --state-dir ~/.local/share/uam
```

Replace `root` with an existing directory first. On a plain `pip` install the verdict is `DEGRADED` and the exit code is 1, and that is expected: `release`, `workspace_canary` and `tunnel` read `UNKNOWN` because there is no installed runtime, no canary list and no tunnel. What matters here is that `audit_chain`, `core`, `workspace_registry`, `mcp` and `reality_index` read `PASS`.

Optional: for autonomous discovery of projects below a directory, put a `root_scopes.json` next to the registry (`~/.config/uam/root_scopes.json`); see [`examples/root_scopes.example.json`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/examples/root_scopes.example.json). A scope is a standing grant, so read [`docs/SSOT.md`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/docs/SSOT.md) before widening one.

A folder that is **not** a Git repository can be read too, as a `filesystem-directory` workspace: read tools only, Git tools refuse it with a machine-readable `diagnostic`. Either register it explicitly (`"kind": "filesystem-directory"`, `"capabilities": ["filesystem.read"]`; third entry of [`config/workspaces.example.json`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/config/workspaces.example.json)) or let a *narrow* scope admit it on demand with `"directory_admit": true` (third scope of [`examples/root_scopes.example.json`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/examples/root_scopes.example.json)). Admission is off by default, and such folders are never discovered or indexed. See the `filesystem-directory` profile in [`docs/SSOT.md`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/docs/SSOT.md).

### 3. Connect your MCP client

UAM exposes **20 read-only tools** over MCP stdio (`session-read` profile, declared as
`READ_ONLY_SESSION_PROFILE_V3`: the 19 tools of V2 plus `uam_file_digest`, which only the SDK adapter serves).
V3 is adopted locally (the maintainer's own supervised runtime) and published in `0.6.3`; what that does and does not establish is in
[`docs/oss/public-profile-contract-v3.md`](https://github.com/openjay/universal-agent-middleware/blob/v0.6.3/docs/oss/public-profile-contract-v3.md). The command a client runs is:

```text
uam mcp-sdk-stdio --profile session-read \
  --registry ~/.config/uam/workspaces.json \
  --state-dir ~/.local/share/uam
```

A client starts it without your shell's virtualenv, and desktop clients do not expand `~`: in a client configuration give `command` the full path that `command -v uam` prints while the environment is active, and absolute paths for `--registry` and `--state-dir`.

**Cursor** — add to `.cursor/mcp.json` (or global MCP settings):

```json
{
  "mcpServers": {
    "uam": {
      "command": "/absolute/path/to/.venv/bin/uam",
      "args": [
        "mcp-sdk-stdio",
        "--profile", "session-read",
        "--registry", "/Users/you/.config/uam/workspaces.json",
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
      "command": "/absolute/path/to/.venv/bin/uam",
      "args": [
        "mcp-sdk-stdio",
        "--profile", "session-read",
        "--registry", "/Users/you/.config/uam/workspaces.json",
        "--state-dir", "/Users/you/.local/share/uam"
      ]
    }
  }
}
```

**ChatGPT** — requires an outbound MCP tunnel (Developer Mode). It is not part of the first-use path above. Configure tunnel credentials via environment only; see `docs/adapters/MCP.md`.

**Opt-in `task-continuity` profile (a separate process, never part of `uam mcp-sdk-stdio` or the service).** Eleven task tools (addressed contract delivery,
attempts, handover, continuity) are served by a module entry, like the Consumer's. It shares no tool name with the 20 read-only tools, has its own declared
contract (`src/universal_agent_middleware/task_tool_contract.json`, checked before it serves) and is started only on purpose:

```text
python -I -B -m universal_agent_middleware.task_profile \
  --registry /path/to/workspaces.json --state-dir /path/to/dedicated/task-state \
  --principal <label> [--runtime-manifest /path/to/uam-runtime.json]
```

`--principal` is the label the operator binds when the process starts: stdio carries no identity, so it is not an authenticated identity and a client
cannot name another one. Without `--authority-factory /abs/file.py:callable --authority-factory-sha256 <sha256>` (the existing authority port) there is no
verifier and every effect is denied. UAM ships no issuer, and the version-1 delivery entry stays closed. Name a dedicated `--state-dir` to keep task state
apart from the read-only service. The Consumer keeps its own module entry, `python -m universal_agent_middleware.consumer_cli run`.

With `--runtime-manifest` the profile runs sealed under an installed release (only from a release that contains this flag). Before it loads anything the launch names,
including a pinned authority factory, the process must be the current, whole release that manifest selects (the check `uam mcp-sdk-stdio` makes); `--registry` must be the
runtime's own registry; `--state-dir` must be a directory of its own that is not, contains no and sits inside no control-plane path of the runtime (the read-only service's
state, the recovery, credential, config and log roots, a release); a FROZEN latch of the runtime stops the launch and every later audit write; and each audit record names
the release. Without the flag the records say `development-unverified` and no latch is wired. A refusal prints one code and no path
(`TASK_PROFILE_RUNTIME_UNREADABLE`, `_RELEASE_NOT_SEALED`, `_REGISTRY_NOT_RUNTIMES`, `_STATE_NOT_DEDICATED`, `_RUNTIME_FROZEN`) and exits 2.
The latch is any entry named `FROZEN.json` in the recovery root, whatever it points at or holds (`os.path.lexists`, as `uam release` reads it), so a symlink that points nowhere
still stops the launch. A sealed launch uses the release's own interpreter with `-I -B`, like every launcher an installed release writes
(`<release>/venv/bin/python -I -B -m universal_agent_middleware.task_profile ...`): `-I` ignores `PYTHONPATH`, the user site and the working directory, so the package that runs
is the release's and not whatever the environment puts first, and `-B` writes no bytecode into the release.

### 4. Smoke test (optional)

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
  uam mcp-sdk-stdio --profile session-read \
    --registry ~/.config/uam/workspaces.json \
    --state-dir ~/.local/share/uam
```

A JSON-RPC response whose `instructions` begin `UAM v0.6.3 Read-Only Reality Observer (20 tools)` means the server started; it exits when its input ends.

### Developer install

Contributors, and anyone who wants the supervised macOS service (`tools/system-service`, `uam release`, `uam release-seal`), work from a checkout of this repository, which holds what the wheel does not:

```bash
git clone https://github.com/openjay/universal-agent-middleware
cd universal-agent-middleware
pip install -e ".[mcp]"
```

The supervised macOS service additionally needs the `service` extra, `pip install -e ".[service]"`.

### Index warm-up (v0.6+)

Build or refresh the cross-process SQLite reality index for faster scope inventory and bare-name resolution. It indexes the discover scopes of a `root_scopes.json` next to the registry; without one there is nothing to index and the command exits 0:

```bash
uam index --registry ~/.config/uam/workspaces.json --state-dir ~/.local/share/uam --scope code
uam index --registry ~/.config/uam/workspaces.json --state-dir ~/.local/share/uam  # all discover scopes
uam index --registry ~/.config/uam/workspaces.json --state-dir ~/.local/share/uam --scope code --background
```

Doctor checks index integrity, schema version, freshness, and policy generation alignment:

```bash
uam doctor --registry ~/.config/uam/workspaces.json --state-dir ~/.local/share/uam --json
```

The report names the instance it probed (`request_id`, `instance`) and separates `stages`:
`process_alive`, `initialization`, `workspace_readable`, `result_completeness`. A registered
workspace whose root no longer exists is reported by the `workspace_registry` check as a coverage
gap (`DEGRADED`) while the remaining workspaces stay served; it is never treated as absent and is
never silently rebound to another directory.

### Cutting a release (operators)

These commands are for an operator who runs UAM as a supervised macOS service from a checkout of this repository (`tools/system-service`, `launchctl`). The wheel does not contain that service, and none of this is needed for the first-use path above.

```bash
uam release --runtime-manifest <uam-runtime.json> --dry-run --json      # build and verify, do not activate
uam release --runtime-manifest <uam-runtime.json> --json                # activate and verify
uam release --runtime-manifest <uam-runtime.json> --json --acceptance gaps.json
uam release-seal --release-dir <releases/vX+commit> --source-root . --out seal.json   # read-only
uam release --runtime-manifest <uam-runtime.json> --json --expect-seal seal.json     # sealed activation
```

`uam release` builds an immutable release from a **clean** git checkout (the source tree is the
one the module was loaded from, then the working directory; the receipt records which). The wheel
is built from a private `git archive` export of the commit, never from the working tree, and
before the manifest is written the wheel and the installed package are proved to be that commit's
Git blobs (steps `export_commit`, `build_wheel`, `install_wheel`, `verify_build`). It
refuses while `recovery_root/FROZEN.json` exists and never deletes it. Before `current` is
switched it compares the tool contract the built artifact serves with the committed
`tool_contract.json` by tool name and digest, re-verifies the manifest, file inventory, wheel and
installed package against the source commit, and refuses an incomplete workspace registry or a
configuration that is not the combination the release was built with (below).
The running tunnel service freezes the host if the runtime manifest or `current` changes under it,
and the Supervisor restarts a tunnel it finds down, so the release first takes the Supervisor's
cycle lock (waiting for a running cycle, bounded; a Supervisor that starts meanwhile waits for the
verdict) and then stops the service (`launchctl bootout`, then waits until launchd reports it
unloaded and the previous tunnel process has exited), switches `current`, updates the global
manifest and starts the service on the new release (`launchctl bootstrap`). Without `--expect-seal`, a
failure before the switch is complete starts the old service again; a sealed run never does (below).
Never edit the runtime manifest or `current` by
hand while the service runs; the service start validates the whole release inventory and is slow
on a loaded host. Afterwards the release refreshes the index and judges Doctor with an exact
predicate.
There is no automatic rollback once `current` has changed; older releases may not start under the
current registry, so rolling back is not an availability recovery by itself. A dry run still
writes a new release directory under `release_root`.

**Sealed activation.** An ordinary run selects its release by the commit it finds and builds it when
the directory is missing, so it cannot promise that what is activated is the release that was
verified. `uam release-seal` (read-only; nothing is built, run or activated) records, for a staged
release, the exact commit and tree, the fixed release directory, the SHA-256 of the manifest, wheel,
runtime manifest and every installed package file (taken from the **Git blobs** of the commit and
required to equal both the installed files and the wheel), the version and `RECORD` hash of every
installed dependency, the inherited `service/` files and the interpreter executable. `uam release
--expect-seal seal.json` then never builds and never rewrites the release; it refuses a missing
directory, a different commit, tree or path, a dirty source and any fingerprint difference, in
three places: before the pre-activation gates execute the release's interpreter, again after the
Supervisor lock is held, and strictly before the tunnel is stopped (steps `seal_identity`,
`seal_guard`, `seal_guard_pre_activate`). Limits: the interpreter is pinned by its executable, not by
the libraries it loads; dependency *code* is covered by the manifest inventory, which is re-validated
under the lock, not by the seal; `service/` is pinned as observed at seal time because it is
inherited from the previous release, not from Git; and the check and the switch are not atomic, so
the window between them is shortened to the service stop, not closed. Without `--expect-seal`
nothing changes.

**A sealed activation that fails stays isolated.** A sealed run is how a release replaces a service
that had to be taken out of use, so the release that was active before it must not come back by
itself. Once the service is stopped, a sealed run starts nothing but the sealed release. If the
switch, the manifest update, the start, the index refresh or the Doctor verdict fails, or the process
is interrupted (`KeyboardInterrupt`, `SystemExit`, any other exception), it stops whatever may be
running (`isolation_stop`) and creates `recovery_root/FROZEN.json` exclusively (`isolation_latch`,
receipt key `isolation`; an existing latch is never replaced, and a latch that cannot be written is
reported as a failed step, never as success). While the latch exists the running service stops itself,
the service does not start, the Supervisor takes no action and a new `uam release` refuses; nothing
deletes it. A kill the process cannot catch (SIGKILL, power loss) leaves no latch. Without
`--expect-seal` the previous behavior (the old service is started again) is unchanged.

**One configuration combination per release.** The runtime manifest of a release records
`config_bundle`: the SHA-256 of the registry file, of the root-scopes file and of the canary list.
`installer stage` refuses an existing configuration file that differs from the one it is given, and
`installer activate`, `uam release` before its pre-activation gates run the release's code
(`config_bundle`) and `uam release` under the Supervisor lock, before anything is stopped
(`config_guard_pre_activate`), refuse a registry,
root-scopes file or canary list that is not the recorded one, a registry or scopes file that does not
load, and a canary that names an unregistered workspace. A sealed activation and `installer activate`
require the record (a release or plan without one is refused; stage again); an unsealed `uam release`
of an older release only checks that the configuration is coherent. The registry and the root scopes
are still re-read while the service runs, so a revocation takes effect without a restart: the bundle
is checked when a release is admitted, never as a runtime freeze trigger.

A release that must ship while specific workspaces are unavailable declares them; nothing else is
tolerated, and the declaration is checked against both the artifact and the live Doctor report:

```json
{
  "schema_version": "uam-release-acceptance-v1",
  "registry": {"registered": 6, "available": 4,
               "unavailable": [{"workspace_id": "old-main", "reason": "root_missing"},
                               {"workspace_id": "old-pr", "reason": "root_missing"}]},
  "canaries": {"total": 6, "failing": ["old-main", "old-pr"]}
}
```

Exit code `0` means a release was activated and accepted (`READY`, or `ACCEPTED_KNOWN_GAPS`). Every
other outcome, including `DRY_RUN` and `DEGRADED`, exits `1`; the JSON receipt names the failing
stage and the release that is active when the command ends.

## Available MCP tools

| Tool | Description |
|------|-------------|
| `uam_list_workspaces` | List registered + discovered workspaces with admission state, registry coverage, serving-instance identity, and the age of the discovered list (`freshness` per entry; `discovery` with an overall status and one `fresh` / `stale` / `unavailable` / `not_indexed` item per scope) |
| `uam_workspace_snapshot` | HEAD, branch, head_state, dirty count |
| `uam_session_bootstrap` | Full reasoning context in one call (project-aware, v2 schema); needs `git.observe`: a `filesystem-directory` workspace is refused with `UNSUPPORTED_CAPABILITY`, use `uam_tree`, `uam_read_file`, `uam_file_digest` and `uam_search_text` there |
| `uam_tree` | Directory listing |
| `uam_read_file` | Read text files (relative paths only) |
| `uam_file_digest` | SHA-256, size and modification time of a file's raw bytes, never its content (authorised like a read; bounded; reports `complete: false` with a `reason` instead of a digest when the file changed while it was hashed) |
| `uam_search_text` | Search across workspace files |
| `uam_git_status` | Git HEAD, branch, working tree changes (`head_state` is `attached`, `detached` or `unborn`; a repository with no commit yet reports `head: null`, `history_available: false`) |
| `uam_git_diff` | Git diff (optionally scoped) |
| `uam_git_log` | Recent commit history (empty with `reason: "unborn_head"` before the first commit) |
| `uam_verify_audit` | Hash-chain audit log integrity |
| `uam_project_reality` | Multi-instance project reality snapshot with coverage diagnostics (Git is asked only of an instance whose current registration grants `git.observe`; one that is not asked is reported `observable: false` and `worktree_discovery.complete: false`, never as clean) |
| `uam_list_project_instances` | List workspace instances and discovered worktrees for a project (`worktree_discovery` names the instances that could not be asked) |
| `uam_list_scopes` | List authorized RootScopes (standing trust zones) |
| `uam_discover_projects` | Autonomously discover all projects within a scope |
| `uam_scope_inventory` | Cached project inventory (in-process cache + cross-process SQLite index) |
| `uam_search_scope` | Cross-project text search across entire scope; authority is decided before any file is read (the server enumerates the scope, opens only what the current `text_search` authority allows and hands ripgrep those open files; a budget or ripgrep failure never falls back to a wider search) (results that are partial or failed carry `incomplete`, `failure_reason`, `failure_stage`; `search_domain` declares depth, exclusions and what is not covered, so `safe_to_conclude_absent` is never true and `absent_within_search_domain` is the narrower claim; each result carries a `locator` (`workspace_id`, `path`, `kind`) to read the hit through the workspace tools, a pointer and not a permission) |
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
│ reality index (SQLite/WAL) → alias lookup      │
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

- **Vendor-neutral core:** no OpenAI/Anthropic/Cursor/GitHub dependency. Two opt-in Consumer modules (`harness_adapter.py`, `consumer_cli.py`) name Codex and Cursor on purpose, because they drive those harnesses as subprocesses; `uam mcp-sdk-stdio` and the service never load them (`tests/test_vendor_neutrality.py` checks both)
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
- `docs/oss/public-profile-contract.md` — Public Preview supported surface (v0.5.1rc1, 19 tools, historical)
- `docs/oss/public-profile-contract-v3.md` — `READ_ONLY_SESSION_PROFILE_V3` successor contract (20 tools; adopted locally, published in 0.6.3)
- `CHANGELOG.md` — Version history
- `SECURITY.md` — Vulnerability reporting
- `CONTRIBUTING.md` — Contribution guidelines

## Status

**v0.6.3 — Public Preview: scope-authorized observation, the 20-tool V3 profile, an opt-in task-continuity profile**

| Gate | Status |
|------|--------|
| Source implementation | PASS (20 read-only MCP tools) |
| Unified RealityResolver | PASS |
| Cross-process SQLite index (WAL) | PASS |
| Policy generation invalidation | PASS |
| Index corruption recovery | PASS |
| CLI `uam index` + doctor index checks | PASS |
| Portable test suite | `pytest` from a checkout (CI runs Python 3.11-3.14) |

Public Preview supports SDK stdio session-read profile only. Legacy HTTP adapter and LocalExecutor are experimental and not part of the Preview contract. See `docs/oss/public-profile-contract-v3.md` (the current 20-tool contract) and `docs/oss/public-profile-contract.md` (the historical v0.5.1rc1 contract).

Deferred: forge/runtime observation, write-capable remote tools, autonomous execution, production OAuth.
