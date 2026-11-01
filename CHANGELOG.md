# Changelog

## 0.6.3 — first release since 0.5.1rc1: sealed launch of the `task-continuity` profile; capability-aware routing text of the read-only profile; the FROZEN latch read fail-closed

`0.6.3` is the first published version after `0.5.1rc1`. The versions `0.6.0`, `0.6.1` and `0.6.2` below were development versions that were never published; their sections keep
their original wording (read "local candidate" there as "before 0.6.3"), and everything they describe ships for the first time in `0.6.3`, together with this section. A `0.6.2` that was
installed in the maintainer's own runtime does not contain this section: it refuses `--runtime-manifest`, its read-only profile still tells a client to bootstrap every known
workspace, and its audit writer reads a `FROZEN.json` symlink that points nowhere as no latch. `0.6.3` is this tree's version on every surface (`pyproject.toml`, `__version__`,
`MANIFEST.json`, `README.md`, `docs/SSOT.md`, this file) and `tests/test_version_surfaces.py` keeps them together.

The maintainer adopted this tree's `READ_ONLY_SESSION_PROFILE_V3` and task profile in their own supervised runtime on 2026-10-31 (see `docs/oss/public-profile-contract-v3.md`); that is one
operator on one host, not evidence about any other environment. What an upgrade from `0.5.1rc1` changes was measured on the real stdio server and is in the README (20 tools instead of 19,
none removed, input schemas and annotations unchanged, 11 descriptions changed).

### Added
- **`python -m universal_agent_middleware.task_profile --runtime-manifest M` (opt-in).** Admission under an installed release before anything the launch names is loaded:
  the manifest loads; the process is the current, whole release it selects (`validate_release`, the check `uam mcp-sdk-stdio` makes); `--registry` is the runtime's own
  registry; `--state-dir` is a directory of its own, neither equal to, containing nor inside any control-plane path of the runtime; the runtime holds no FROZEN latch.
  A refusal is one code on stderr (`TASK_PROFILE_RUNTIME_UNREADABLE`, `_RELEASE_NOT_SEALED`, `_REGISTRY_NOT_RUNTIMES`, `_STATE_NOT_DEDICATED`, `_RUNTIME_FROZEN`), no path, exit 2.
  The serving notice names `runtime_release` and `release_manifest_sha256`.
- `runtime.py`: `AdmissionError`, `release_id`, `validate_dedicated_state`, `admit_dedicated_runtime`. Additive: no existing function changes.
- `MiddlewareGateway(registry_path, state_dir, *, sealed_runtime=None)`: with a sealed runtime the audit chain is stamped with the release and honours the runtime's FROZEN
  latch, the control plane is protected as for the read-only service, and the state directory stays the caller's own (`validate_paths`, which forces the runtime's state, is not used).
- `tests/test_task_profile_runtime_seal.py`: admission and its refusal codes, the gateway binding, the FROZEN latch (a file, a symlink that points nowhere, at itself or into a directory
  that cannot be searched, an unreadable file: at admission, at every audit write of a sealed gateway and of the read-only service's own binding), order of checks (admission before a
  pinned factory file runs) and real processes with `executing=True` (refused from the source tree; admitted from a package inside a fixture release; refused after one changed byte)
  and, started the way an installed release is (the release venv's interpreter, `-I -B`, an ambient `PYTHONPATH` naming another copy of the package), admitted from the release and
  refused without `-I`.
- `tests/test_version_surfaces.py`: `pyproject.toml`, `MANIFEST.json`, the README title, the SSOT (header, release acceptance, its "all reflect" line) and a CHANGELOG section all name the
  version the package reports (SSOT section 8 requires it; nothing checked it).
- `tests/test_bootstrap_capability_routing.py`: the description and the server `instructions` of the read-only profile against the behaviour they describe (every named tool exists,
  every tool recommended for a directory serves a directory, every tool a directory is said to refuse refuses it with `UNSUPPORTED_CAPABILITY`), and the unchanged refusal: exact
  payload, no process started, no `.git`, no tree change, the capability and not the kind deciding.

### Changed
- **The FROZEN latch is any entry of that name.** `admit_dedicated_runtime` (new in this section) and `HashChainedAuditLog.append` read the latch with `os.path.lexists`, as
  `release._freeze_evidence` does: a `FROZEN.json` that is a symlink pointing nowhere, at itself or into a directory that cannot be searched is a latch (`Path.exists` follows the
  link and read it as absent, so admission and the audit write went on). For the read-only service the audit write now stops for such an entry as it already did for a file;
  nothing else of its behaviour changes, and no code here creates, edits or removes a latch.
- **The Task entry is started like an installed release: `<release>/venv/bin/python -I -B -m universal_agent_middleware.task_profile ...`.** `-I` ignores `PYTHONPATH` and the working
  directory, which the sealed launch needs (it requires the executing package to be the release's own); `-B` writes no bytecode into the release. The README example and the module
  docstring say so; the code of the entry does not change.
- **Read-only profile text: `uam_session_bootstrap` says what it needs and the server `instructions` route by capability.** The description now states that the tool requires
  `git.observe` (see `capabilities` in `uam_list_workspaces`), that a `filesystem-directory` workspace can never hold it (refused with `UNSUPPORTED_CAPABILITY`) and which tools serve
  a directory (`uam_tree`, `uam_read_file`, `uam_file_digest`, `uam_search_text`). The `instructions` send a known workspace to `uam_session_bootstrap` only with `git.observe`, and name
  what a directory refuses (`uam_session_bootstrap`, `uam_workspace_snapshot`, the git tools). Text only: no executable statement changes, and the refusal, its diagnostic, the
  capability model, every output schema, `tool_contract.json` and `task_tool_contract.json` keep their bytes. The description is part of the profile-v3 declaration, so
  `docs/oss/profile-v3-declaration.json` is regenerated (this tool's description digest and its entry in `metadata_diff_vs_baseline.changed`) and `uam_session_bootstrap` joins the
  tools that a release reports as `client_refresh_needed` (description only: connectors Refresh; a STDIO client reads it at the next launch of a release that contains this).
- Docs follow: `docs/oss/public-profile-contract-v3.md` (description-only row), `README.md` (tool table) and the description-only count in `docs/adapters/MCP.md` and `docs/SSOT.md`
  (now seven tools; the text said four while the declaration already listed six).
- Without the flag nothing changes: a development launch, records say `development-unverified`, no latch. The read-only service keeps its `UAM_RUNTIME_MANIFEST` binding
  (registry and state forced to the runtime's own). `tool_contract.json` and `task_tool_contract.json` keep their bytes.
- `tests/test_task_profile.py`: `--runtime-manifest` leaves the list of refused extra flags (the `0.6.2` test and docstring encoded "takes no `--runtime-manifest`"), and the
  entry may import `universal_agent_middleware.runtime`. This is a deliberate amendment of that contract, not a loosened assertion elsewhere.

### Limits
- Admission is checked at launch; the FROZEN latch is also checked at every audit write. A process running from an unsealed tree is refused, so a sealed launch only works from
  an installed release that contains this change. Same-UID tampering after the check is not defended (as for every other release check here).
- No issuer or authenticated identity is added: without `--authority-factory` every effect is still denied, and `--principal` is still an operator-bound label.
- The other readers of the latch (`service.py` start, `supervisor.py`, `installer.py` activation, `doctor.py`, the `server.py` health endpoints) still use `Path.exists`; they are not part
  of this change. `os.path.lexists` reads False when the entry cannot be examined at all (for example the recovery root itself cannot be searched), as in `release._freeze_evidence`.
- A directory-aware `uam_session_bootstrap` (a context pack without Git) is a contract change and stays on `docs/BACKLOG.md`; until then a directory workspace is refused by it, by
  design. `uam_workspace_snapshot`'s description is unchanged (it already names the Git HEAD and branch).

## 0.6.2 — Task layer on the 0.6.1 base: an opt-in `task-continuity` profile (development version; never published, superseded by 0.6.3)

The read-only profile is the one of `0.6.1`: `tool_contract.json`, `adapters/mcp_sdk.py`, `server.py`, `mcp.py`, `runtime.py`, the release modules and every other
module outside the list below keep their `0.6.1` bytes. This version adds the accepted Consumer, Task-control and Task-continuity core and one explicit entry for it.
The version is `0.6.2` because `0.6.1` already names different bytes (release `v0.6.1+3217331`, wheel `166a787d…`).

### Added
- **`python -m universal_agent_middleware.task_profile` (opt-in, separate process).** Eleven tools (`task-control` seven plus continuity four) with their own
  declared contract, `task_tool_contract.json`, which the entry checks against the live tool list before it serves (names, schemas, annotations; a mismatch is a refusal).
  It shares no tool name with the 20 read-only tools. It is a module entry like the Consumer's: `cli.py` (so `uam mcp-sdk-stdio`, whose only profile stays `session-read`) and
  the service command that starts the tunnel keep their `0.6.1` bytes and do not know it. `--registry`, `--state-dir` and `--principal` are required.
- **Deny-all, operator-bound, no issuer.** `--principal` is a label the operator binds at launch (stdio carries no identity; the entry prints that on stderr). Without
  `--authority-factory /abs/file.py:callable --authority-factory-sha256 <sha256>` (the loader the Consumer command already uses) every effect is denied. The version-1
  delivery entry stays closed and has no flag.
- **Task core:** `task_control`, `task_continuity`, `task_continuity_control`, `results_v2`, `statefile`, `harness_adapter`, `consumer`, `consumer_cli` (the Consumer keeps its module
  entry, `python -m universal_agent_middleware.consumer_cli run`), the two `adapters/mcp_task_*` modules, and the `workspace-change-v2` contract schema in `contracts.py`,
  `models.py` and `gateway.py` (`create_contract` of both schemas, `record_result_v2`, `get_result_v2`).

### Changed
- `ResultV2Store` no longer creates `results-v2/` and `artifacts/sha256/` when it is constructed. Every gateway builds it, so the read-only session server wrote them into
  its state directory at start; they are now created by the first stored result or patch.
- Version `0.6.2` in `pyproject.toml`, `__version__` and `MANIFEST.json`; `task_tool_contract.json` is package data.

### Compatibility
- The 20 read-only tools, their schemas, annotations and descriptions are unchanged; the server `instructions` text differs only in its version token.
- Source changes take effect only after a new release is cut and the services are restarted. Nothing here selects, installs or restarts anything.

## 0.6.1 — Final release-gate closure (development version; never published, superseded by 0.6.3)

Five confirmed defects stood between the sealed integration candidate and a recoverable release. This section fixes exactly those, each with the smallest change that closes it, and adds no feature. The version is `0.6.1`; a release is named `v0.6.1+<commit>` only once the candidate is committed. `tool_contract.json` is unchanged: no tool name, input, output or safety fingerprint moved.

### Security
- **A revoked project identity is no longer served by a running process (F-G2-2).** The project view was built once, when the gateway was constructed, so a project removed from `workspaces.json` (or whose workspaces were revoked) kept answering `uam_list_project_instances` and `uam_project_reality` until the process restarted. `ProjectRegistry` now follows the registry generation: the SHA-256 of the registry text that `WorkspaceRegistry` is serving, returned together with the declarations from one read. A changed generation rebuilds the view, a registry that cannot be served drops it (fail closed), a missing registry serves nothing, and a worktree discovery or reality snapshot that was computed while the generation moved is refused (`RegistryGenerationChanged`) instead of being returned or answered from the index (the one timing that is answered at once, a project revoked as a whole while `uam_project_reality` observes its instances, is described under Compatibility).
- **No host path leaves in a tool answer (PR-1).** `uam_project_reality` listed `discovered_worktrees[].path` as an absolute host path, and error messages could name one. Every answer and error of the session-read MCP server now passes once through `NorthboundBoundary` (`northbound.py`): a discovered worktree leaves as `worktree_id` (a digest of its real path) and, inside an authorized RootScope, `scope_id` and `relative_path`; a field defined to hold a path keeps a relative value and drops an absolute one; any other string has each absolute host path replaced by a label (`<workspace:ID>`, `<scope:ID>`, `<state>`, `<registry-dir>`, `<home>`, `<tmp>`, otherwise `<host-path>`). Relative paths, file content, diffs and commit text are never rewritten.

### Fixed — release pipeline
- **The wheel is built from the commit, never from the working tree (F-REL-1).** `uam release` built the wheel in place, so ignored files, stale `build/` leftovers and files of other worktrees entered the artifact while the clean check saw nothing, and the artifact check compared the installed package with that same tree. The commit is now exported to a private directory (`git archive`, compared object by object with `git ls-tree`; a submodule or any entry that is not a regular file or link refuses), the wheel is built from that export only, and `verify_build` proves before the manifest exists that the wheel holds exactly the commit's package files plus its own `dist-info` (no bytecode, duplicate, unsafe member name or extra file) and that the installed package is exactly the commit's Git blobs. The `artifact_verify` gate of `uam release` and `uam release-seal` apply the same wheel inventory check to the wheel they are handed.
- **Registry, RootScopes and canaries are one combination bound to the release (F-REL-2).** `installer stage` kept an existing configuration file and silently ignored the one it was given while it embedded the supplied canaries, and nothing compared the files at activation with those the release was built with, so a mixed combination surfaced only after the switch, as a FROZEN latch. The release's runtime manifest now records `config_bundle`: the SHA-256 of the registry file, of the root-scopes file and of the canary list. It is verified (the files load, every canary names a registered workspace, the digests are the recorded ones) at every admission point: staging, `uam release` before the release's code is probed (`config_bundle`), `uam release` again under the Supervisor lock and before anything is stopped (`config_guard_pre_activate`), and `installer activate`. A sealed activation and `installer activate` require the record; an unsealed `uam release` of a release built before this version is only checked for coherence. `installer stage` refuses an existing configuration file whose bytes differ from the supplied one, before any child process runs. The registry and the root scopes stay hot-reloaded by design, because a revocation must not wait for a restart: the bundle is an admission contract, never a runtime freeze trigger.
- **A failed sealed activation keeps the install isolated and never restarts the old release (safe recovery).** A failed switch after the service was stopped started the previous release again (`tunnel_restore`), and every other failure left the Supervisor free to restart a tunnel it found down; for a secure recovery the previous release may be exactly the one that had to be taken out of service. After the stop, a sealed run (`--expect-seal`) starts nothing but the sealed release and, on any failure (the switch, the manifest update, the start, the index refresh, a Doctor verdict that is not accepted, an unexpected error or an interruption), stops whatever may be running (`isolation_stop`) and creates the `FROZEN.json` latch exclusively (`isolation_latch`; an existing latch is never replaced). The service and the Supervisor honour the latch, and it ends only through the incident procedure. A run without `--expect-seal` is unchanged, including `tunnel_restore`.

### Compatibility
- **Connectors must Refresh.** The descriptions of `uam_list_project_instances` and `uam_project_reality` changed (reported as `client_refresh_needed`); their input, output and safety fingerprints and every `tool_contract.json` digest did not. `docs/oss/profile-v3-declaration.json` is regenerated (against the V2 baseline six descriptions now differ: the four of the integration candidate below plus these two) and `docs/oss/public-profile-contract-v3.md` lists the change. The answers of both tools change shape: each entry of `discovered_worktrees` carries `worktree_id`, `scope_id` and `relative_path` instead of `path`.
- A project answer that is being assembled when the registry changes is now refused (`RegistryGenerationChanged`: `the workspace registry changed while the answer was being assembled; ask again`) instead of an answer with the changed instance marked unobservable. A refused answer is never completed from the reality index. The next call answers from the new registry, and that answer has one of three shapes: the registry's own declarations; an index-backed answer (`source: reality_index`, `derived:` identities only) when a RootScope index knows the project and the registry no longer declares it; or the `unknown project` error when neither does. One timing is answered on the first call instead of refused: when a project is revoked as a whole while `uam_project_reality` is still observing its instances, the project lookup fails before the generation is checked, and that call is answered the way a process started after the change would answer it (index-backed, or `unknown project`). `uam_list_project_instances` refuses in every timing. No answer or error of these shapes names an identity or content of the revoked registration. `tests/test_v061_registry_generation_with_index.py` pins the refusals, the index-backed shape and that one timing.
- Receipts gain the steps `export_commit`, `verify_build`, `config_bundle`, `config_guard_pre_activate`, `isolation_stop`, `isolation_latch` and `isolation_error`, and the keys `config_bundle` and (sealed failures only) `isolation`. A runtime manifest gains `config_bundle`; an older release ignores it. A plan staged by an older installer records no combination, so `installer activate` refuses it (`config_bundle_missing`): stage it again.
- Source changes take effect only after a new release is cut and the services are restarted.

### Known limits (documented, not changed)
- Supersedes the limit of the integration candidate below that a changed project definition needs a restart: the project view now follows the registry generation.
- An absolute path with an unquoted space is redacted only up to its first space: free text cannot say where it ends. A quoted path is bounded by its quote.
- Bytecode (`.pyc`) is ignored when the installed package is compared with the Git blobs, everywhere in the pipeline (`runtime.release_files`, the seal, the probe, the build check): a sourceless `.pyc` placed after the build by the same OS user is outside the verified set. The build backend and the interpreter that runs it are not pinned by this release.
- An interruption that cannot be caught (SIGKILL, power loss) after the stop leaves no latch: the service stays stopped, but the Supervisor may restart the release that `current` names.
- An `installer stage` refusal that comes after the exclusive release directory was created (a registry with gaps, canaries for an unregistered workspace) leaves that empty directory; remove it before staging again.

## Before 0.6.1, first published in 0.6.3 — Integration candidate: authority before reads, per-instance Git capability, a declared 20-tool profile

A **development integration candidate** (first published in 0.6.3). It integrates the sealed-activation guard (`uam release --expect-seal`) with the path-authority, observation-compatibility and directory-locator work that were built separately, and closes two authorization boundaries those packages left open. The sections below it keep each package's own notes.

### Security
- **`uam_search_scope` decides authority before it reads (Scope Search v2).** It used to hand ripgrep the scope root and a list of exclusion globs and then filter the hits that came back: ripgrep had already opened every file, including files under a nested scope that denies search, and its globs were anchored to its own working directory, not to the scope. The server now walks the scope itself (`scope_search.py`: directory descriptors opened with `O_NOFOLLOW`, `scandir(fd)`) and asks the *current* effective `text_search` authority (`PathPolicy`: the name as written and as a case- and normalization-insensitive filesystem sees it, the most specific nested scope wins) about each directory before listing it and about each file before opening it. A denied directory is never listed and a denied file never opened; an allowed scope nested inside a denied directory is still reached. A file is opened relative to its directory descriptor and must be a regular file, the object that was listed and, while a nested scope denies search, a file with a single name (a hard link is the same bytes under another name; this includes a link made after the file was listed). Ripgrep then receives only `/dev/fd/N` for descriptors that were opened and verified, in bounded batches and with a hermetic environment: it never walks a directory or opens a path, so a name replaced after the check cannot make it read something that was not authorized. The filter on ripgrep's hits stays as a second layer, not as the boundary.
- **Budgets and failures end a search as incomplete, never as a wider search.** `ScopeSearchLimits` bounds entries (1,000,000), files (250,000), bytes (4 GiB), the deadline (30 s) and ripgrep's output (1 MiB). Exhausting one (`scan_limit` with `limit_reached`, `timeout`, `result_limit`), a ripgrep failure (`execution_error`), a file that changed under the walk (`enumeration_incomplete`) or unreadable output (`unreadable_output`) gives `PARTIAL` or `FAILED` with `incomplete: true`. `safe_to_conclude_absent` stays `false`, and `absent_within_search_domain` is true only for a `COMPLETE` search with no hit and none withheld. The secret firewall still drops matches silently, and nothing in a response counts what authority keeps out.
- **`max_results` is bounded by the server.** The count asked for is served as `max(1, min(asked, 500))`: a request below one is served as one, a request above 500 as 500, and when more hits exist than were returned the result is `PARTIAL` with `failure_reason: result_limit`.
- **Project-level Git observation follows each instance's current capability.** `uam_list_project_instances`, `uam_project_reality`, the sibling list of `uam_session_bootstrap` and the Git enrichment of the cached inventory used to run Git for every `git-repository` entry without reading its capability list. A static instance is now asked only when the live registry entry grants `git.observe`, at the root it has now; a derived instance only when the live resolver and its effective RootScope allow it (defensive: a project definition holds registered workspaces only, so tests reach that branch by injection); a directory instance is never handed to Git. Denied, unavailable or unknown means no Git and no fallback to a same-named derived workspace, and one instance's failure does not hide the others. An instance that is not asked is `observable: false` and never reads as clean, without history or complete: `uam_list_project_instances` and `uam_project_reality` gain `worktree_discovery` (`complete`, `not_observed_instances`), including on the index-backed fallback, which launches no Git and reports `complete: false`, and `git_enrichment` is recomputed for what was actually asked.

### Changed
- **Declared approximations of the new search** (`search_domain` states them). The ignore files (`.gitignore`, `.ignore`, `.rgignore`) are interpreted in-process with the semantics of ripgrep 14's `ignore` crate (differential tests compare the walker's file set with `rg --files` on the same trees) and read only from inside the search root; `.git/info/exclude` and the global gitignore are no longer honored; a rule that cannot be translated faithfully is not applied and shows up as `ignore_rules_not_applied` in `not_covered`. Binary files are recognised by a NUL byte in the first 64 KiB, and a file handed over by descriptor is searched past a later NUL where a walked file would stop. `search_domain` gains `enumeration`, `ignore_files_read_from`, `binary_detection` and `limits`, and `not_covered` gains `unreadable_paths` (and `hard_linked_files` next to `scope_authority`). `DiscoveryEngine` takes a `search_limits` argument (default `DEFAULT_LIMITS`).
- **A static `git-repository` registration that grants `filesystem.read` only is no longer observed by Git at project level.** Add `git.observe` to restore it; a registration that grants both is unchanged. `content_authorized` for a project instance now also requires `filesystem.read`, and the `other_instances` of `uam_session_bootstrap` carry `observable`.

### Added
- **`READ_ONLY_SESSION_PROFILE_V3` is declared** in `docs/oss/profile-v3-declaration.json`: the 19 tools of V2 plus `uam_file_digest`, bound to the complete tool set, the `tool_contract.json` digest of every tool, the digest of every top-level field of each tool listing (input, output, safety, description) and the full metadata difference against the V2 baseline (source commit `e75fe4c88e438a88e52dc56886894930b536ad23`). The candidate side is produced by the release pipeline's own probe, unchanged. `tests/profile_declaration.py` writes and checks it, and `tests/test_profile_v3_declaration.py` fails when the server and the declaration disagree, in either direction. `docs/oss/public-profile-contract-v3.md` is the successor contract: a local candidate, not adopted; `uam_file_digest` served by the SDK adapter only; `directory_admit` off by default; static registration independent of RootScopes; unverified environments listed. README, `docs/adapters/MCP.md` and `docs/SSOT.md` (release acceptance: 20-tool parity) now describe the V3 profile. The 19-tool contract of the published v0.5.1rc1 and its receipts are historical and unchanged. The declared `description` digests are those of the text an interpreter that strips docstring indentation at compile time (Python 3.13 or later; the service interpreter is 3.14) advertises, recorded as `description_digest_basis`: on Python 3.11, which keeps the indentation, 16 of the 20 descriptions are advertised with different indentation and nothing else differs (measured, 3.11.15 against 3.14.6). The tests therefore compare every other digest on every interpreter and the description digests only where the indentation is stripped, and the builder refuses to run elsewhere; `tool_contract.json` excludes descriptions and is unaffected. A first version of the declaration tests compared the description digests on every interpreter and failed on 3.11 in a clean-room run.

### Compatibility
- **Metadata difference against V2, measured from both trees with the same probe:** one tool added (`uam_file_digest`), none removed, and the descriptions of **four** tools changed: `uam_git_log`, `uam_git_status`, `uam_list_workspaces` and `uam_search_scope`. Input, output and safety fingerprints and all 19 existing `tool_contract.json` digests are unchanged, so no schema changed; a release reports `client_refresh_needed` and connectors must Refresh. (An earlier entry of this file listed three descriptions: `uam_list_workspaces` was missing from it.)
- Additive response fields only (`worktree_discovery`, `observable` on bootstrap siblings, the new `search_domain` keys and `not_covered` codes); a client that ignores unknown keys is unaffected. `tool_contract.json` is unchanged.
- Source changes take effect only after a new release is cut and the services are restarted. Rolling back is a release of the previous commit; a registration that already grants `git.observe` works the same on the older release, which only reads the capability list.

### Known limits (documented, not changed)
- Authority is a snapshot taken when a scope search starts: a revocation during a running search is applied to its hits by the second layer but cannot un-read what was already read, and a process that can write inside the scope while the search runs can change which allowed file is read, never whether an unauthorized one is. Absence still holds only within the declared `search_domain`.
- The instances of a project are built when the gateway is constructed; a changed project definition needs a restart.
- Registered in `docs/BACKLOG.md`, not changed here: per-workspace `allowed_paths` / `denied_paths`, static-registration independence of RootScopes, cooperative change detection of `uam_file_digest`, the path-based `uam_search_text` and its text domain, and `uam_tree` sizes versus the hard-link rule.

## Before 0.6.1, first published in 0.6.3 — `filesystem-directory` workspaces (reading folders that are not Git repositories)

A folder inside an authorized scope but without `.git` used to be unreadable by every route: `derived workspace must be a discovered repository (no .git)`. That was a coverage gap against the v0.6 Git-only workspace contract, not a defect in the safety checks, and `git init` on the target was only a workaround. The `.git` requirement for repositories is unchanged; a second, explicitly weaker workspace kind now covers plain directories.

### Added
- **`filesystem-directory` workspace kind.** Read through the existing `uam_tree`, `uam_read_file` and `uam_search_text` (no new tool; `tool_contract.json` digests are unchanged). Capability: `filesystem.read` only. It can never carry `git.observe`: Git tools and `repository-change-v1` contracts refuse it. Two explicit routes: static registration (`"kind": "filesystem-directory"` in `workspaces.json`, served without any RootScope like a static Git workspace) and on-demand derived admission (`derived:<scope_id>:<rel>` or an absolute path) inside a scope whose most specific authority sets the new `directory_admit` bit together with `content_read`. Discovery, indexing and bare-name resolution still see Git repositories only; nothing admits a folder by itself.
- **`directory_admit`** in RootScope authority, default `false`. A scope that does not set it keeps its exact `policy_generation` (the digest basis omits the bit while it is `false`), so installing this release does not invalidate any reality-index snapshot; enabling it changes the digest like any authority change.
- **Machine-readable refusals.** An error may carry `diagnostic` (`workspace-diagnostic-v1`). For an authorized directory that was not admitted: `status: UNSUPPORTED_WORKSPACE_KIND`, `reason: NON_GIT_DIRECTORY`, `path_exists`, `scope_authorized`, `scope_id`, `directory_admission: NOT_ENABLED`, `suggested_actions`. For a Git call on a directory: `status: UNSUPPORTED_CAPABILITY`, `reason: CAPABILITY_NOT_SUPPORTED_BY_WORKSPACE_KIND`, `workspace_kind`, `capability`, `supported_capabilities`. The SDK MCP, stdio MCP and HTTP adapters add it next to the existing error fields; an error without a diagnostic keeps its exact previous shape. `ResolutionError.kind` gains `UNSUPPORTED`, and a missing path inside an authorized scope is `NOT_FOUND`.
- **A scope-search hit says where it can be read (`locator`).** `uam_search_scope` reported the scope-relative path of a match, but a file can only be read through a workspace and nothing connected the two: a hit in a plain directory led nowhere. Each result now carries `locator: {workspace_id, path, kind}`: the derived workspace that contains the hit (the nearest Git repository at or below the scope root; failing that the hit's top-level directory; for a file directly in the scope root, the scope root itself) and the path inside it. `kind` is `git-repository` or `filesystem-directory`, decided by the same `.git` rule admission uses (`models.is_git_checkout`, one definition for both). Read the hit with `uam_read_file` or `uam_file_digest` using that `workspace_id` and `path`. **A locator is a pointer, not a permission.** It carries no host path, a hit grants no authority, and using the locator resolves the handle against live authority like a handle typed by hand: a scope without `directory_admit` answers with the `UNSUPPORTED_WORKSPACE_KIND` diagnostic, a revoked scope or a nested scope that denies reading refuses (per path inside a repository), and protected names stay unreadable. A directory is looked at for `.git` only where the scope that governs it lets its metadata be observed (`metadata_read` or `content_read`); elsewhere it is reported as `filesystem-directory`, so the kind does not tell what a denying scope keeps hidden. Nothing is created in the target: no `git init`, no marker file.
- **Coverage says what it covers.** `coverage` gains `basis: registered_workspaces` and `unregistered_root_scope_paths: not_assessed`: `coverage.complete` never meant that everything inside the RootScopes is readable. The discovery coverage block gains `discovers: git-repositories` and `non_git_directories: not_discovered`. The project payloads (`uam_list_project_instances`, `uam_project_reality`) show `kind` for non-Git entries only, so Git-only payloads are byte-identical; `uam_list_workspaces` already reported `kind` for every entry.
- `schemas/workspace-registry-v1.schema.json` lists both kinds, the per-kind capability rule and the optional fields the loader has always accepted (`project_id`, `role`, `lifecycle`, `repository_identity`, `discovery`); `config/workspaces.example.json` and `examples/root_scopes.example.json` show the new kind and a narrow `directory_admit` scope.

### Security
- Directory admission checks authority before it touches the filesystem: a path outside every authorized scope, or in a scope that cannot admit, is refused identically whether or not it exists, and the message no longer echoes an absolute path (this also applies to the existing absolute-path and derived routes for repositories).
- A directory workspace cannot equal, contain or sit inside UAM's control plane (state directory, config directory and every runtime-manifest path), cannot have a protected name (`.ssh`, `.env`, `*.pem`, …) in its path below the scope root, and cannot span a nested scope, so a more specific scope is never bypassed by admitting one of its ancestors (with per-path authority, below, this admission-time refusal is stricter than the enforcement needs; relaxing it is a backlog item, not done here). A static directory is held to the control-plane rule when it is resolved. Static registrations are otherwise the owner's explicit grant and are not narrowed by scopes (as for static Git workspaces).
- **The secret denylist is case-insensitive.** On the default macOS filesystem `.SSH/config` is `.ssh/config` but did not match the exact-name list. This applies to every workspace kind and uses the same case- and normalization-insensitive folding as path-level authority (below).
- `uam_search_text` no longer blocks forever on a FIFO, socket or device inside a workspace: only regular files are opened.

### Compatibility
- **Rollout order.** Install this release first, then add `kind: filesystem-directory` entries or `directory_admit` to configuration. **Rollback order.** Remove them first. An older release rejects an unknown RootScope authority key and an unknown workspace kind (the whole registry), so config that keeps them makes the older release refuse to start.
- Existing Git workspaces, repository admission, bare-name resolution, discovery, indexing and the `policy_generation` of configs that do not use the bit are unchanged. The text `derived workspace must be a discovered repository (no .git): <rel>` no longer exists: that case is `ResolutionError(kind="UNSUPPORTED")` with a diagnostic, and it is `NOT_FOUND` when the path does not exist.
- The server `instructions` string gains one sentence about directory workspaces. `uam_search_scope` results gain a `locator` object per hit; every existing key is unchanged. Its tool description grows a paragraph about the locator (a description edit only, reported as `client_refresh_needed` together with the other description changes of this release).
- Source changes take effect only after a new release is cut and the services are restarted; the live instance keeps the configuration it loaded.

### Known limits (documented, not changed)
- `uam_search_scope` is governed by a scope's `text_search` bit alone: in such a scope it reports the relative paths of files containing a query even inside non-Git directories that are not workspaces (see `docs/SECURITY_MODEL.md`). Its `locator` leads to a read only where admission and authority allow one.
- `uam_session_bootstrap` and `uam_workspace_snapshot` need Git and so refuse a directory workspace with the diagnostic above; a directory-aware bootstrap is on the backlog together with automatic discovery of non-Git directories, which stays on hold.

## Before 0.6.1, first published in 0.6.3 — Local service remediation (UAM-01/02/03)

### Fixed
- **Stale registration no longer aborts initialisation (UAM-01).** A registered workspace whose root is missing, not a directory, or unresolvable previously raised during registry load and took every healthy workspace down with it. It is now unavailable on its own: never served, listed under `coverage.unavailable` with a reason (`root_missing`, `root_not_directory`, `root_unresolvable`), and its identity stays reserved. Schema, identifier, kind and capability violations still reject the whole registry.
- **No silent rebind.** Resolving a registered but unavailable workspace id raises `WorkspaceUnavailableError` (`ResolutionError.kind == "UNAVAILABLE"`) instead of falling through to derived or bare-name resolution, which could have mapped the id to a different directory.
- **Unobservable instances never read as absent.** `project_reality` keeps a registered main/candidate that cannot be read at `not_observed` (previously `not_registered` / `not_applicable`) and adds an `UNOBSERVABLE_INSTANCES` warning. `ReadOnlyGit` converts a missing root into `WorkspaceError`.
- **`uam_search_scope` bytes/path type error (UAM-02).** On timeout CPython hands `subprocess.TimeoutExpired.stdout` back as `bytes` (or `None`), which reached `Path(...)` and raised `TypeError`. ripgrep output is now captured as bytes and parsed at one boundary: strict UTF-8 per record, undecodable or cut-off records are dropped and counted, and a timeout returns the records read so far.
- **An index that cannot be trusted or read costs a scope, never the listing.** An index whose schema is newer than this release supports was refused by `check_integrity` (`INCOMPATIBLE`) while the snapshot read path kept serving its rows, so `list_workspaces` still reported the scope `fresh`; an index still locked after the retry budget raised `IndexLockedError` out of the snapshot read and failed the whole listing, registered workspaces included. Every index read (`get_active_snapshot`, `lookup_by_alias`, `list_projects`, `get_project_instances`) now checks the on-disk schema on each connection and answers "nothing indexed" for an incompatible or locked index instead of serving it or raising. `list_workspaces` builds each discovery scope whole or reports it `unavailable` (with the exception type only, never its text or paths) without touching the other scopes or the registered part, names an incompatible schema in the scope reason, and no longer reads the index at all for `view="registered"` (audit `discovery_status: "not_requested"`). `uam_scope_inventory` treats an index it cannot read or write as a cache miss and answers by live scan (`freshness.source: "live_scan"`); the explicit `index_scope` still fails loudly. No tool schema, annotation, description or `tool_contract.json` digest changes.

### Added
- Search results carry `incomplete`, `failure_stage` (`launch`, `execute`, `timeout`, `limit`, `decode`) and, when records were dropped, `paths_skipped`. A timeout is `FAILED`/`timeout` with partial results and is never reported as complete; audit details record the completeness, reason and stage.
- `uam_list_workspaces` / `list_workspaces` return `coverage`, a `request_id` that is also written to the corresponding audit record, and an `instance` block (instance id equal to the audit `writer_instance_id`, pid, start time, version, release, registry digest, policy generation). `uam_list_project_instances` marks unavailable instances with `available: false` and `unavailable_reason`.
- **`list_workspaces` says how old its discovered list is.** The listing serves the reality index without waiting for a scan, but a snapshot past its 300 s limit used to produce the same `discovered` list as a fresh one, and a scope without a usable snapshot contributed nothing: a consumer could not tell "not there" from "not looked at", or five minutes old from two hours old. Every `discovered`/`eligible` entry derived from the index now carries `freshness` (`stale`, `cache_age_ms`), and the response carries `discovery`: `status` (`fresh`, `stale`, `incomplete`, `not_configured`), `max_age_ms`, the bounded-scan `coverage`, and one item per discoverable scope that is `fresh`, `stale` (older than `max_age_ms`, still listed for compatibility), `unavailable` (indexable, but never indexed, indexed under another policy generation or an unreadable index; its projects are missing, not absent) or `not_indexed` (no index authority, so its projects are never part of this list; `uam_scope_inventory` covers it). `incomplete` (any `unavailable` or `not_indexed` scope) outranks `stale`. A project missing from `discovered` proves nothing unless the status is `fresh`, and then only within the bounded scan; `uam_scope_inventory` returns an inventory no older than `max_age_ms`. The audit record carries `discovery_status`, `stale_scopes`, `unavailable_scopes` and `not_indexed_scopes`. Nothing else changes: no refresh, no waiting, no new tool, `tool_contract.json` digests are unchanged (only the tool description grew, which a client sees as `client_refresh_needed`).
- Doctor reports `request_id`, an `instance` block (probe pid, version, release id, config digests, gateway identity), a derived `stages` block (`process_alive`, `initialization`, `workspace_readable`, `result_completeness`), a `workspace_registry` check (coverage gaps are `DEGRADED`, so the Supervisor classifies them as log-only `workspace_degraded`), canary failures that name the workspace and stage, `mcp.contract_sha256`, and tunnel identity (`pid`, `started_at`, `release_id`, `config_sha256`, failing `stage`). Doctor still never appends to the audit ledger.
- `/status` reports `degraded` (HTTP 200) with coverage counts when registered workspaces are unavailable; `/readyz` is unchanged and exposes no workspace ids or instance identity.

### Path-level authority inside derived workspaces
- **A RootScope nested inside a derived workspace now narrows it.** Admission checks the authority at the workspace root only, so a readable parent Git workspace made everything beneath it readable, enumerable and searchable, including a nested scope with `content_read=false` / `text_search=false` (reproduced against the real Reader with an in-memory scope file; scope-level `uam_search_scope` already honoured the nested denial). `uam_read_file`, `uam_tree`, `uam_search_text`, `uam_git_diff` and `uam_git_status` now apply the most specific scope per path, the rule `root_scope.py` always documented. A path is governed by the scope that covers it: read needs `content_read`; search needs `content_read` and `text_search` (it returns lines of content); enumeration needs `metadata_read` or `content_read`. An allowed scope nested inside a denied one stays reachable by explicit path (most specific wins).
- **Fail closed, no oracle.** A path is checked as written, before the filesystem is consulted (a denied subtree cannot be probed for which files exist, and a link planted inside it is judged by where it sits), and again on its real location (an alias of a denied file or directory is denied). The policy is re-read for every operation, so a revocation applies to the next call; one walk never straddles two policies. Denied directories are not walked. Workspace confinement is unchanged.
- **A path has other names than the one it was spelled with.** The default macOS volume compares names without regard to case or Unicode normalization, so `Evidence/x` is the file `evidence/x` there, and the caller chooses the spelling; changing the case of a name sidestepped a scope that denies it. A path is now judged twice, as spelled and as such a filesystem sees it (`policy.fold_name`: NFD, case-folded, NFD), and every governing zone must allow it. Where the two readings disagree about which scope governs, only what both scopes grant is granted (`RootScopeAuthority.meet`): respelling the name of a scope nested inside a denied one does not open it, a path that no scope covers as spelled stays uncovered, and a scope whose directory differs from the workspace root only in case is not "nested" in it. Nested scopes are found through a workspace root spelled differently, and the Git pathspec for a denied subtree is built below the root by components. The same folding applies to the fixed secret-name firewall (`.SSH`, `.Git`, `ID_RSA`, `Credentials`, … in any case; a name that merely resembles one, such as `credential-model.md`, stays readable) wherever the check is used: workspace paths, listings, the sensitive-hit flag of scope search, and the MCP adapter's direct `.git` guard.
- **A hard link is the same bytes under another name.** Authority is decided from a name, so a regular file with several names (a hard link outside a denied scope to a file inside it) was a way around the denial. While a nested scope denies the operation, such a file is refused: `ScopeAuthorityError` with `reason: hard_linked_file` for a read and for `git diff PATH`, and a search leaves it out and reports the result `PARTIAL`. Only a workspace that has a denying nested scope pays for the `stat`; a workspace without one is unchanged.
- **Honest completeness.** A listing that left something out says `excluded_by_scope_authority: true`. A search that skipped part of the tree reports `search_completeness: PARTIAL`, `excluded_by_scope_authority: true` and never `safe_to_conclude_absent: true`; denied files are not scanned and not counted (a count would reveal what is there). `git diff` and `git status` exclude denied subtrees with literal pathspecs (Git cannot re-include a scope nested in an excluded one, so such a scope is excluded too); `git diff PATH` on a denied path is denied.
- **A denial is explicit.** `ScopeAuthorityError` (a `PathPolicyError`) carries `code = "SCOPE_AUTHORITY_DENIED"`, the operation and the governing scope id; the SDK MCP adapter returns it as `error_code` next to `error` (errors without a code are unchanged; the stdio MCP and HTTP adapters name the class in `error`, as for every error), and the gateway appends a `DENIED` audit record (path as requested, code, operation, scope id; never content).

#### Compatibility
- **Static registrations are unchanged and pinned by a test.** A statically registered workspace is its own, separately authorized contract; it does not honour nested scope denials. Changing that is an authorization-semantics change for existing deployments and needs an explicitly designed compatibility policy (owner decision). The same directory addressed through a derived handle, an absolute path or a project name is guarded.
- Deployments whose scope file nests a narrower scope inside a project now see exactly that narrower result from the workspace tools. Without nested scopes nothing changes (no new response keys, no extra work). The admission scope's own `text_search` flag still does not gate workspace-level search (unchanged).
- Additive response fields only; no tool schema, annotation, description or `tool_contract.json` digest changes.
- Limits: a Git observation cannot express a hole, so it excludes the whole denied subtree; commit subjects in `git log` and the dirty-file counts in project and discovery summaries are not path-filtered. A whole-repository `git diff` (no path) is not checked for hard links: it shows a changed file under its own name even when its bytes are also reachable inside a denied subtree. Bind mounts and APFS firmlinks are not detected. The conservative reading over-denies: on a case-sensitive volume a path that differs from a denied scope only in case is refused although it is a different directory, and a path that reaches a scope nested inside a denied one through another case is refused where the exact spelling is read. Names that a volume folds differently from `fold_name` (a volume-specific case table) are not modelled.

### Observation compatibility: unborn Git, a declared search domain, `uam_file_digest`
- **A repository with no commit yet is observable, not an error.** `git rev-parse HEAD` fails on an unborn branch, so `uam_git_status` (and everything built on it) answered a freshly initialised repository with `git returned 128: ambiguous argument 'HEAD'`. `status` now returns `head: null`, `head_state: "unborn"`, the `branch` Git recorded in HEAD (read from the symbolic ref, never a guessed default), `history_available: false` and the working-tree `status` as before (staged and untracked files are real); `log` returns `commits: []`, `history_available: false` and `reason: "unborn_head"`. Attached and detached results gain `history_available: true`. The unborn state is recognised from Git's own answers (HEAD names a branch, Git reports that ref missing, no loose ref file sits at that name): a detached HEAD that names no commit, or a branch ref that exists but cannot be resolved, is still an error rather than an empty history.
- **Consumers follow.** `project_reality` keeps an unborn instance observable (`head: null`, `head_state: "unborn"`, `history_available: false`); discovery enrichment records its branch and keeps `head: ""`; `uam_session_bootstrap` of a sibling instance no longer fails on an unborn peer (its `head` was sliced as a string); a `repository-change-v1` contract on a repository without a commit is refused with an explicit message instead of a Git error; `uam_workspace_snapshot` and `uam_session_bootstrap` report `history_available` next to `head_state`.
- **A scope search declares what it searched.** `uam_search_scope` runs ripgrep with a fixed depth, the repository ignore files, no hidden or binary files, no symlinks and a list of excluded directories, yet a finished search without a match answered `COMPLETE` / `safe_to_conclude_absent: true` without saying so. The result now carries `search_domain` (`engine`, `match`, `max_depth` and `max_depth_from`, `excluded_directory_names`, `ignore_files_honoured`, `scope_authority_exclusions`, `exhaustive: false`, and `not_covered` reason codes: `beyond_max_depth`, `ignored_by_ignore_files`, `hidden_paths`, `binary_files`, `symlinked_paths`, `excluded_directory_names`, `secret_firewall_paths`, `system_directories`, and `scope_authority` when a scope's authority keeps a subtree out). The declaration is built from the same constants as the command line, and a test compares the two. A bounded search can never prove absence from the scope, so **`safe_to_conclude_absent` is now always `false` for `uam_search_scope`**; the true statement has its own field, `absent_within_search_domain` (a `COMPLETE` search with no match, and no hit withheld by scope authority). A match inside a path the secret firewall hides is dropped silently, as before, and does not turn it `false`: answering otherwise would tell a caller that a protected file contains the query (`secret_firewall_paths` is in `not_covered` for that reason). The domain names no path and counts nothing a scope keeps out (a count would reveal what is there). `uam_search_text` is unchanged: it already reports `files_scanned`, `files_skipped` and `excluded_by_scope_authority` for its own walk.
- **`uam_file_digest` (new tool).** The SHA-256 of a file's raw bytes, its size and modification time, never its content: "is this the file I was shown?" for evidence that cannot be read as text (a binary, a file over the read limit). It is authorised exactly like `uam_read_file` (same path rules, secret names, nested-scope authority, revocation, and the refusal of a hard-linked file while a nested scope denies reading; `permission_check` reports the authority decision and the operating-system read result), streamed in 1 MiB chunks, bounded to 256 MiB and 10 s, and change-detecting: a digest is claimed only when the path still names the same file (device, inode, size, modification time) before, during and after hashing. Otherwise `complete` is `false`, `sha256` is `null` and `reason` is `byte_limit`, `time_limit`, `changed_while_hashing` or `os_permission_denied`. The audit record carries the path, completeness, size and digest, never content. A missing file is an error answer (`path does not exist`) like the other tools' errors, not an exception.

#### Compatibility
- **Profile and contract.** The session-read profile grows from 19 to 20 tools (`READ_ONLY_SESSION_PROFILE_V3` = V2 plus `uam_file_digest`); `tool_contract.json` gains exactly one entry and no existing digest changes. The descriptions of `uam_git_status`, `uam_git_log`, `uam_search_scope` and `uam_list_workspaces` changed (four, as measured against V2 in the integration entry at the top of this file; this entry originally listed three), so a release reports `client_refresh_needed` and connectors must Refresh before the new tool appears. `uam_file_digest` is served by the MCP SDK adapter only (not by the legacy HTTP/OpenAPI or custom stdio adapters). `docs/oss/public-profile-contract.md` (baseline v0.5.1rc1, 19 tools) and `docs/oss/private-scan-coverage.json` are historical records and are not edited here; publishing a 20-tool profile needs a successor contract, which now exists as a local candidate: `docs/oss/public-profile-contract-v3.md`.
- **A consumer that read `safe_to_conclude_absent` from `uam_search_scope` as permission to conclude absence now always sees `false`.** That is the intended correction; such a consumer should read `absent_within_search_domain` together with `search_domain.not_covered`.
- Additive response fields otherwise (`history_available`, `reason`, `search_domain`, `absent_within_search_domain`); a client that ignores unknown keys is unaffected.
- Limits: `max_seconds` is checked between chunks, so one read that blocks on a stalled device is not interrupted; a file rewritten in place with the same size and the same modification time is indistinguishable from an unchanged one; a missing-path error for the other path-taking tools is still an exception (not changed here).

### Release pipeline hardening (`uam release`)
- **A freeze is never cleared by a release.** `_activate()`, `_stop_tunnel()` and `_start_tunnel()` no longer delete `recovery_root/FROZEN.json`. The release refuses while the latch exists, before building, before switching `current`, before updating the global manifest and before any `launchctl bootout/bootstrap`; the receipt carries the latch's size and SHA-256 and the file is left untouched. Clearing a freeze remains an authorized incident-handling step outside the release.
- **The running service is stopped before anything it guards changes.** The tunnel service compares the SHA-256 of the runtime manifest and the target of `current` with the values it started with every 0.5 s and freezes itself (`runtime_path_failure`) on any difference, so the former order (switch, rewrite the manifest, then restart) changed both under the still-running old service and would have tripped that guard. Activation is now: `launchctl bootout`, wait until `launchctl print` reports the service unloaded (exit 113, bounded), switch `current`, update the global manifest, `launchctl bootstrap` on the new release. The manifest is replaced atomically and left alone when the new release already carries it. A failure before the switch is complete starts the old service again (`tunnel_restore`); a service whose state cannot be established (timeout, unexpected exit status, still loaded after the wait) is never switched under. Once `current` has changed there is still no automatic rollback.
- **Exact acceptance.** Success is no longer "Doctor said READY" or "DEGRADED with `post_ok`". `READY` now also requires the tunnel start and index refresh to have succeeded and the Doctor report to describe the activated release. A release that must ship with unavailable workspaces passes `--acceptance FILE` (`uam-release-acceptance-v1`): the exact registered/available counts, the exact unavailable ids with reasons, and the exact failing canaries. Any other difference in either direction (extra gap, changed reason, a declared gap that disappeared, another canary failing, a required check that is not `PASS`, an unknown extra check) is rejected. Without the file any unavailable workspace fails the release, and the same gate runs on the built artifact before `current` is switched.
- **Complete failure receipts.** Index refresh, Doctor, tunnel `launchctl`, `git` and the tool probe run through one bounded runner: timeouts (partial output kept as bytes and truncated safely), launch errors, non-zero exits and invalid output all become receipt entries with the failing stage, elapsed time and exit code; `git` failures are fatal instead of reading as a clean tree. The receipt also records the active release when the run ended, the orchestrator interpreter/module/cwd, the source root and how it was found, commit/tree, artifact hashes, and the build interpreter.
- **Independent verification before the switch.** The tool contract served by the built artifact (probed in the release's own interpreter) is compared by tool name and digest with the committed `tool_contract.json` (a matching count proves nothing); the manifest, every file, the wheel and the installed package files are re-verified against the source commit. Tool description/schema/annotation differences against the active release are listed separately as metadata differences (`client_refresh_needed`).
- **`doctor.result_completeness`** is `PASS` only when both coverage checks completed and no gap is known; an `ERROR`, `UNKNOWN`, skipped or missing check leaves it `UNKNOWN` (`evidence_problems` names why), and a known gap outranks unusable evidence as `DEGRADED`.

#### Compatibility
- Exit code: `0` only when a release was activated **and** accepted (`READY`, or `ACCEPTED_KNOWN_GAPS` with `--acceptance`); `DRY_RUN`, `DEGRADED`, `ACTIVATION_INCOMPLETE` and `FAILED` exit `1` (unchanged for dry runs). Wrappers that previously saw `READY`/`0` despite a failed tunnel start or index refresh now see `ACTIVATION_INCOMPLETE`/`1`.
- Receipts gain `schema_version`, `accepted`, `exit_code`, `failure_stage`, `activation`, `orchestrator`, `source`, `tool_contract`, `coverage`, `artifacts`, `tool_metadata_diff`, `acceptance`, `doctor_attempts` and `duration_seconds`; `overall` gains `ACCEPTED_KNOWN_GAPS`. New step names: `freeze_guard`, `freeze_guard_pre_activate`, `acceptance_declaration`, `git_identity`, `reviewed_contract`, `coverage_gate`, `artifact_verify`, `tool_metadata`, `acceptance`, `load_runtime`, `unexpected_error`, `supervisor_quiesce`, `tunnel_stop`, `tunnel_start`, `tunnel_restore`. The former `tunnel_restart` step no longer exists.
- A release whose probed contract differs from the committed `tool_contract.json` is now refused instead of having the artifact's own answer written into its manifest.
- `--dry-run` still writes a complete immutable release directory under `release_root`; it only skips the service stop, the switch, the service start, the index refresh and Doctor.
- A release now stops the tunnel service for the duration of the switch, and the service start validates the whole release inventory, which takes noticeably longer on a loaded host. Never edit the runtime manifest or `current` by hand while the service runs.

### Sealed release activation (`uam release --expect-seal`)
- **Why.** A second ordinary `uam release` selected its release by the commit it found, built it when the directory was missing, had no way to demand the already-verified artifact, and after taking the Supervisor lock re-checked no fingerprint before `tunnel_stop`. The pipeline's own artifact check compares the installed package with the *working tree*, not with Git, so "the artifact equals the tree" did not prove "the artifact equals the commit".
- **`uam release-seal --release-dir D --out FILE`** (read-only: nothing is built, executed or activated; an existing seal is never overwritten) seals a staged release (`uam-release-seal-v1`): exact commit and tree, the fixed release directory, SHA-256 of the manifest, wheel and runtime manifest, every installed package file (taken from the **Git blobs** of the commit and required to equal both the installed files and the wheel's), the version and `RECORD` hash of every installed distribution, the inherited `service/` files and the interpreter executable (real path and bytes). It refuses a release built from another commit, one whose installed package or wheel differs from the commit, and one that has not passed the pre-activation gates.
- **`uam release --expect-seal FILE`** turns the run into a sealed activation: it never builds (a missing directory is `seal_identity`/`release_missing`, and a directory that vanishes mid-run is `release_exists`), never rewrites the release (`rewrite_manifest=False` for the tool-contract gate), and refuses any difference, reporting every one. The guard is static (no code of the release runs) and sits in three places: `seal_identity` (commit, tree, path, directory exists) before anything is validated; `seal_guard` before the gates, which run the release's interpreter; and `seal_guard_pre_activate` after the Supervisor lock and the freeze re-check and strictly **before `tunnel_stop`**, where it also re-validates the whole manifest inventory (which is what covers dependency code). It also re-reads the commit's Git blobs, so a seal edited together with the artifact is still contradicted by Git (`seal_contradicts_git`). A dry run verifies the seal without the lock.
- **Limits, stated so they are not read as guarantees.** The interpreter is pinned by its executable, not by the libraries it loads; dependency code is covered by the manifest inventory, not by the seal; `service/` is pinned as observed at seal time because it is inherited from the previous release, not from Git; the check and the switch are not atomic (the remaining window is the service stop); the seal is an operator-supplied expectation, not a trust root; and a build is still not byte-reproducible, so a rebuilt release is deliberately a different release.
- **Compatibility.** Without `--expect-seal` the pipeline behaves exactly as before, including building a missing release. New CLI surface: `uam release-seal`, `uam release --expect-seal`; new steps `seal_declaration`, `seal_identity`, `seal_guard`, `seal_guard_pre_activate`; the receipt gains `seal` (path, SHA-256, release id, commit). No tool, schema or `tool_contract.json` change. Whether `--expect-seal` should become mandatory for non-dry-run activation is a CLI-contract decision left to the owner.

### Evidence that must not contradict itself
- **Acceptance rejects receipts that contradict themselves.** A canary summary of `FAIL` over all-`PASS` details (or the reverse), a registry summary of `DEGRADED` without gaps or `PASS` over listed gaps, counts that are not non-negative integers (`True`, `4.0`, `"4"`, `None`), `registered` and `available` that do not agree with the gap list, and a `complete` flag that disagrees with the gaps are all refused (`canary_status_inconsistent`, `registry_counts_invalid`, `registry_counts_inconsistent`, `registry_complete_inconsistent`, `registry_status_inconsistent`), in strict and in declared-gap mode, and by the coverage gate that runs on the built artifact.
- **`scope_inventory` names its source by what happened.** `freshness.source` is `live_scan_indexed` only when the scan was actually persisted to the index; a scan of a scope without index authority, or without an index, is `live_scan`.

### Availability under host overload
- **Scheduling class.** Both LaunchAgent templates use `ProcessType` `Interactive` instead of `Background`. Measured on the production host at a load of about 400 on 16 cores, the same CPU loop took 0.12 s as `Interactive`, 2.1 s as `Standard` and did not finish in 100 s as `Background`: the Supervisor and the tunnel were starved behind other tenants' default-priority work, health probes and the Doctor timed out, MCP requests timed out, and the last published verdict was 40 minutes old. Hosts installed earlier must change the same key in both installed plists and reload them (`uam release` does not touch LaunchAgents).
- **A slow probe is not a dead tunnel.** The Doctor reports a tunnel probe that timed out as `UNKNOWN` with `uncertain: true` and the stage that did not answer, instead of `FAIL`. The Supervisor classifies it as log-only `tunnel_probe_uncertain` and never restarts on it. Definite answers (process gone, identity mismatch, port not owned, refused connection, HTTP error) still `FAIL` and are restarted within the existing budget. A `launchctl kickstart` that times out is recorded as an uncertain restart (`restart_state: uncertain_timeout`) instead of freezing the install.
- **Unknown failure classes are logged, never frozen.** The policy file is copied from the previous release, so a class introduced by a newer Supervisor may be missing from it. P0 classes remain mandatory in the file; any other class falls back to log-only instead of raising into a P0 `recovery_state_failure`. `tunnel_probe_uncertain` and `supervisor_cycle_timeout` are added to the shipped policy file.
- **The reality index is refreshed before it is judged.** The index is served for 300 s while the Supervisor ticks every 300 s plus its own duration, and the former refresh only reacted to a stale verdict, behind a 600 s cooldown: the verdict alternated between READY and DEGRADED. Each cycle now starts one detached worker per scope that is both discoverable and indexable, waits for it for at most 90 s, then runs the Doctor. A worker that is still running is never duplicated, workers start at most once per 120 s, a failure to start is a receipt and never a freeze, and the summary is published as `index_refresh`. The 300 s freshness contract is unchanged. A refresh lands about every 324 s (the 300 s interval counts from the end of each run), so a snapshot is older than its limit for roughly 24 s of every cycle, about 7 % of the time. The Doctor runs right after the refresh and never sees that window; a client that lists workspaces inside it does, which is why `list_workspaces` reports the age (see Added). Closing the window needs a longer freshness or a shorter tick, which is a contract change, not a scheduling one.
- **Snapshot retention.** `scope_snapshots` kept every refresh's full inventory although only the active generation is ever read (3,095 rows, 250 MB in four weeks). Each snapshot write now keeps the new generation and the two before it, and removes at most 200 older rows per write so a table that is already far over the bound is trimmed over a few refreshes without a long write lock.
- **Every verdict is dated, and a cycle has a deadline.** `health_status.json` carries `observed_at` and `cycle_seconds`, so a verdict left behind by a stalled Supervisor is recognisable by its age. A cycle that has not finished after 240 s publishes `FAILED`/`supervisor_cycle_timeout` (log-only) instead of staying silent; the deadline is not an `Exception`, so it can never be turned into a P0 freeze, and it never overwrites a freeze latch's status.
- **`uam release` and the Supervisor exclude each other.** The Supervisor validates the release and restarts a tunnel it finds down; a tick that fell into a release's switch would meet a service that is stopped on purpose, or a runtime manifest and a `current` that disagree for a moment, and could restart or freeze the install. Activation now takes the Supervisor's cycle lock (`recovery_root/supervisor.lock`) first, waits for a running cycle (at most 300 s; step `supervisor_quiesce`, and nothing has been changed when it gives up), re-checks `FROZEN.json` under the lock and holds it until the acceptance verdict. A Supervisor that starts meanwhile waits, and reads the runtime manifest again once it holds the lock. Dry runs never take it.
- **`uam release` waits for the old tunnel process, not only for launchd.** `launchctl print` stops listing the job before its tunnel-client has exited; a client still shutting down keeps the port and answers the health probes, so a service started in that window found the port taken and exited. Activation now also waits (bounded) until the process recorded in `tunnel-identity.json` is gone, and refuses to switch if it is not or if `ps` cannot answer.

### Removed (unreferenced code)
No MCP tool, CLI command, schema or runtime behaviour changes. These Python symbols had no caller in the package, the tests, the documentation or the packaging, and are gone: `errors.AuthorizationError`, `ExecutionOutcome.to_result_payload`, `ExplorationEngine.rank_projects`, `MiddlewareGateway.refresh_stale_indexes` (index refresh is owned by the Supervisor; Doctor never refreshes), `policy.redact_environment_value`, `RealityResolver.resolve_spec`, `RootScope.can_read_content` / `can_discover`, `RootScopeRegistry.can_discover` / `can_git_observe` / `can_auto_admit`, `release._find_source_root`, and unused imports across `src/` and `tests/`.

### Notes
- Tunnel start and Doctor tolerate a stale registration (it is served as unavailable). Release staging and activation keep failing early on one: `validate_configs(runtime, require_complete_registry=True)` runs before `current` is switched, so a coverage gap cannot first surface as a non-READY Doctor after activation and a FROZEN latch.
- Source changes take effect only after a new release is cut and the services are restarted; the live instance keeps the registry snapshot it loaded.
- With stale registrations present, a failing tunnel was previously masked by the core failure; with this change it is classified `tunnel_unavailable` under the existing bounded `restart_tunnel` policy.

## v0.6.0 — Cross-process reality index & resolver convergence

### Added
- **RealityIndex**: persistent SQLite (WAL) index for scope snapshots, discovered instances, and inverted alias lookup (project_id, basename, remote tail)
- Cross-process index sharing with busy timeout, atomic snapshot writes, and corruption recovery (automatic rebuild)
- **policy_generation** binding: index entries invalidated when RootScope policy changes
- Stale-while-revalidate background refresh (single-flight per scope; Supervisor spawns detached processes that survive caller exit)
- CLI `uam index --scope <scope_id> [--background] [--enrich-git]` for index warm-up
- Doctor `reality_index` check: integrity, schema version, freshness, policy alignment, per-scope obligation (required vs orphaned)
- Doctor phase timing: 7-phase `_timing` dict and `total_duration_ms` for timeout diagnostics
- `authority.index` enforcement: `index_scope` denies scopes where `index=false`
- `list_workspaces` views: `registered`, `discovered`, `eligible` (default `all` preserves backward compat)
- Indexed fallback for `uam_project_reality` and `uam_list_project_instances` on discovered-only projects

### Changed
- `scope_inventory` fast path queries RealityIndex first (<50ms when warm)
- `RealityResolver` resolves bare project names via index before filesystem scan
- DiscoveryEngine persists live scans to index automatically
- Supervisor incident classification: `reality_index_stale`, `reality_index_missing`, `reality_index_policy_mismatch`, `reality_index_locked`, `reality_index_integrity_failure`, `reality_index_schema_incompatible` replace generic `workspace_degraded` for index-related degradation
- Doctor no longer triggers background refresh (daemon threads killed with short-lived subprocess); Supervisor owns refresh lifecycle via detached workers

## v0.5.1rc1 — Public Preview RC1

- OSS convergence: 111-file export allowlist with SHA256 verification, 100% pinned GitHub Action SHAs, 8-cell CI matrix qualified.
- OSS-SEC-001 pre-read boundary enforcement with rg exclusion globs and disjoint sub-roots.
- `public-profile-contract.md` ACCEPTED — 19 read-only MCP tools, session-read Preview surface.
- Path 1 clean public genesis procedure documented; private repo retained as provenance.

## v0.5.0 — operational hardening

- POSIX audit v2 with process locking, durable writes, structured verification and explicit legacy migration.
- Shared runtime manifest, semantic Doctor, persistent P0 freeze and transactional recovery budget.
- Clean archived source, immutable release identity, verified staging and explicit macOS activation.
- Isolated test state and explicit search dependency/timeout failures. No new MCP tools or workspace authorization.
- Production migration and canonical landing remain pending; see the hardening program document.

All notable changes to Universal Agent Middleware are documented here.

## [0.4.0] — 2026-08-09 — Autonomous Reality Discovery

### Added
- RootScopeV1 authority model: standing trust zones with capability inheritance
- DiscoveryEngine: deterministic Git repository scanning and project identification
- Remote identity resolution: groups worktrees into logical projects
- Activity classification: active/recent/dormant/archived
- Cross-project search via ripgrep across entire authorized scope
- CoverageGapV1: referenced-but-unobserved surface inference
- ExplorationEngine: "what am I missing?" aggregation
- Project-specific observation profiles (`config/project-observation-profiles/`)
- 6 new MCP tools: `uam_list_scopes`, `uam_discover_projects`, `uam_scope_inventory`, `uam_search_scope`, `uam_explain_coverage`, `uam_what_am_i_missing`
- `uam_explore`: intent-driven autonomous exploration with RealityGraphV1, retrieval planning
- `config/root_scopes.json`: machine discovery + code root read authority
- Program SSOT archived in `docs/programs/`

### Changed
- Tool surface: 10 → 19 read-only tools
- Architecture: passive registration → autonomous discovery within trust zones
- Version numbering: v0.4 = Reality Discovery (Autonomous Execution deferred to v0.5)

### Security
- Secret firewall preserved under broad scope authority
- All new tools remain `readOnlyHint=true, destructiveHint=false`
- Discovery reuses hermetic ReadOnlyGit (fsmonitor/pager/external disabled)
- RootScope capability enforcement: `git_observe=false` blocks all git probing
- Auto-admitted derived workspaces inherit secret firewall and path containment
- Broad discovery operations recorded in hash-chained audit log

## [0.3.2] — 2026-08-08 — Semantic Correctness Hardening

### Added
- `lifecycle` field: orthogonal to `role` (active/landed/stale/superseded)
- `not_applicable` coverage state: absent candidate is healthy
- `observation_requirements`: renamed from `decision_requirements`
- `authority_evaluation`: explicit `{mode: PROJECT_DEFINED, evaluated_by_uam: false}`
- Project observation profiles: `config/project-observation-profiles/`
- 20 acceptance tests (T1-T6)

### Changed
- Schema version: `project-reality-snapshot-v2`
- Machine invariant: `UAM_COVERAGE_COMPLETE ≠ PROJECT_AUTHORITY_GRANTED`

## [0.3.1] — 2026-08-08 — Project Reality Coverage

### Added
- `ProjectRegistry`: multi-instance project model
- `WorkspaceInstance`: role + project grouping
- Git worktree discovery: auto-detect worktrees for registered repos
- `ProjectRealitySnapshotV1`: coverage diagnostics (COMPLETE/PARTIAL/UNKNOWN)
- 2 new MCP tools: `uam_project_reality`, `uam_list_project_instances`
- `session-context-pack-v2`: project-aware bootstrap

## [0.3.0] — 2026-08-08 — Live Human Reasoning Bridge

### Added
- Official MCP Python SDK adapter (`src/universal_agent_middleware/adapters/mcp_sdk.py`)
- Read-only ChatGPT session profile (`READ_ONLY_SESSION_PROFILE_V1`)
- Secure MCP Tunnel integration via `tunnel-client` v0.0.11
- ChatGPT Developer Mode plugin: 10 read-only observation tools
- `WorkspaceSnapshotV1` — lightweight workspace state in one call
- `SessionContextPackV1` — full reasoning bootstrap in one call
- Workspace context profiles (`config/workspace-contexts/*.json`)
- `head_state` field: explicit `attached`/`detached` disambiguation
- Freshness test workspace for live-data proof
- Prompt injection test fixture

### Security
- No mutation tools exposed to remote clients
- Direct `.git/` reads denied at adapter level
- Secret/dotfile path denial (`.env`, credentials)
- Path traversal containment (`../` cross-workspace)
- Prompt-injection containment: security is middleware-enforced, not model-dependent
- Absolute paths omitted in remote responses
- No credentials committed to repository

### Verified (E2E)
- 78 regression tests (all pass)
- Local MCP interoperability (stdio, annotations)
- Secure tunnel connectivity and health
- ChatGPT Web live invocation (Gate E1)
- Ground-truth parity: HEAD, branch, dirty state (Gate E2)
- Security negatives: .env, .git, traversal all denied (Gate E3)
- Runtime freshness: HEAD/content change without reconnect (Gate E4)
- Fresh-clone reproducibility from tag (Gate F): 78/78 tests, MCP 10/10, zero mutations
- Source/runtime skew detection and resolution: serving process reload verified
- Session continuity across UAM runtime reload: existing ChatGPT session consumed new `head_state` semantics without Refresh or reconnect
- Secret provenance scan: 0 credentials in tree or full git history

### Operational Properties Proven
- Workspace data freshness: live per-invocation (no caching)
- Middleware runtime upgrade: existing sessions survive backend restart
- Session disposability: conversation history ≠ project state
- Tunnel health continuity: readyz/healthz maintained across process cycles

### Known Non-blocking
- `tunnel-client` "harpoon" channel warning: does not affect MCP data path
- Large dirty worktree in example workspace: workspace-level, not UAM issue; bootstrap truncation in backlog
- Tunnel is runtime-live, not yet 24/7 durable service (launchd hardening in backlog)

### Not Yet Included
- Write-capable northbound MCP tools
- Goal/WorkItem continuation engine
- Persistent external executor (24h autonomous)
- Mobile MCP support (web only)
- Production OAuth / service-account hardening
- Multi-executor routing (Claude Code / Codex)

## [0.2.0] — 2026-08-08

### Established
- UAM v0.2.0 baseline: 50/50 tests, manifest-verified source
- Independent standalone repository
- Example workspace registration with synthetic and local fixtures
- Observation E2E: tree/read/search/git against real repos
- Security controls: traversal, secret, cross-workspace denial
- First `repository-change-v1` Execution Contract
- Local executor adapter with scope checking and verification
- Full closed-loop: Contract → Execute → Result → Review

### Architecture
- Vendor-neutral core with no required vendor dependency
- Physical state/workspace isolation enforced
- Hash-chained audit log
- Immutable contracts and executor results
- Bounded execution with explicit path allowlists
