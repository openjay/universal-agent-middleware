# UAM Security Model V2

## Threat model

Treat reasoning clients, remote transports, plugin packages, target workspace content, and executor output as independently fallible or adversarial inputs. Prompt injection in workspace content is expected. Authorization is code-enforced and cannot be granted by text found in a repository or plugin skill.

## Protected assets

- files outside registered roots;
- credentials/keys inside registered roots;
- target workspace bytes;
- shell/process execution authority;
- UAM auth credentials;
- UAM control-state integrity;
- contract/result identity and audit lineage;
- isolation between projects/workspaces.

## Core controls

- loopback-only HTTP bind by default;
- Bearer auth on `/v1/*` and `/mcp`;
- versioned, closed-world workspace kind/capability registry;
- UAM state/workspace physical disjointness;
- canonical `Path.resolve()` confinement;
- traversal + symlink escape rejection;
- secret/key path denial (names compared case-folded, because the default macOS filesystem is case-insensitive);
- `filesystem-directory` workspaces are read-only and can never carry `git.observe`; derived admission is default-off (`directory_admit`), checks authority before it touches the filesystem (no existence oracle for out-of-scope paths), and refuses directories that overlap UAM's control plane or span a nested scope;
- no target-write API;
- no caller-supplied shell execution API;
- hardened fixed Git observations with dangerous config surfaces disabled;
- bounded file/search/diff/request sizes;
- contract creation bound to clean observed `HEAD`;
- authoritative contract files must be tracked by that repository snapshot;
- immutable contracts and results;
- hash-chained audit.

## MCP-specific controls

For Streamable HTTP:

- require supported `MCP-Protocol-Version`;
- bind `Mcp-Method` to the JSON-RPC method;
- bind applicable `Mcp-Name` to tool name;
- require auth;
- reject invalid `Origin` when present;
- do not implement a standalone GET/SSE stream unless deliberately added;
- never expose more tools than the underlying gateway capabilities.

## Agent Plugins-specific controls

- portable package contains no credentials;
- `mcp.json` headers are not used as a secret mechanism;
- the skill is instructional only and cannot grant capabilities;
- client-specific extensions, if added later, cannot change UAM core authority;
- package paths must not be treated as target-project authority.

## Known pre-production limitations

- HTTP Bearer token is shared, not per-principal OAuth.
- Agent Plugins 1.0.0 is a Working Draft and client support may differ.
- MCP adapter is deliberately minimal and does not implement the full optional protocol surface.
- audit chain is locally tamper-evident but not externally anchored.
- OS sandbox/service account isolation is not yet implemented.
- search is linear.
- Executor Result review validates the submitted evidence against the contract but does not independently attest executor truth; malicious/fabricated evidence needs later signed attestation and/or independent repository/CI readback.
- denylist is defense in depth, not a substitute for narrow roots.
- `uam_search_scope` is governed only by a scope's `text_search` bit: it is neither limited to Git repositories nor to admitted workspaces. In a `text_search=true` scope it reports the scope-relative paths of files containing a query, including files in non-Git directories. It never returns content and honors the secret denylist, but it is a path/membership oracle. Exclude a sensitive subtree by nesting a scope with `text_search=false` around it. Each hit carries a `locator` (`workspace_id`, `path`, `kind`) naming the derived workspace to read it through. The locator is a pointer, not a permission: it carries no host path and is resolved against live authority when used, so a hit in a plain directory is readable only where `directory_admit` is enabled, and a hit inside a nested scope that denies reading stays unreadable.
- `uam_search_scope` decides authority before it reads, not after: the server walks the scope itself and asks the current `text_search` authority about each directory before listing it and about each file before opening it, so a denied directory is never listed and a denied file is never opened. Each open file is verified (regular file, the object that was listed, and, while a nested scope denies the operation, no other hard link), and ripgrep is handed only those open, verified descriptors in bounded batches. It never walks a directory or reopens a path, so a name replaced after the check cannot make it read something that was not authorized. Filtering ripgrep's hits against live authority remains as a second layer, not the control. Budgets (entries, files, bytes, a deadline, ripgrep output) and any ripgrep failure end the search as an explicitly incomplete answer (`scan_limit`, `timeout`, `execution_error`, `result_limit`, `enumeration_incomplete`, `unreadable_output`); there is no fallback to a wider search, `safe_to_conclude_absent` is always false and `absent_within_search_domain` is bound to the declared `search_domain`. A file that cannot be searched because a secret pattern, a binary probe or an ignore rule excludes it is not reported as such, so the answer is not an oracle for those files. Residual limits: authority is a snapshot taken when the search starts (a revocation during a running search is applied to its hits by the second layer but cannot un-read what was already read), and a process that can write inside the scope while the search runs can change which allowed file is read, never whether an unauthorized one is.
- Derived workspaces of either kind apply RootScope authority per path, not only at the workspace root: the most specific scope covering a path governs it (read needs `content_read`; search needs `content_read` and `text_search`; enumeration needs `metadata_read` or `content_read`). Names are compared case- and normalization-insensitively and both readings must allow, and a regular file with other hard links is refused while a nested scope denies the operation on it. A directory workspace additionally refuses at admission to span a nested scope.
- Inside a scope whose most specific authority may admit (`auto_admit` or `directory_admit`, with `content_read`), a caller can tell an existing directory from a missing path: `UNSUPPORTED_WORKSPACE_KIND` with `path_exists: true` against `NOT_FOUND`. Outside every authorized scope the answer is uniform and does not depend on existence.
- Static workspace registrations (either kind) are the owner's explicit grant and are not narrowed by RootScopes. Enabling `directory_admit` on a broad scope admits every directory below it that is not protected: grant it on narrow scopes only.
- Project-level tools (`uam_list_project_instances`, `uam_project_reality`, the sibling list of `uam_session_bootstrap`, and the Git enrichment of the cached inventory) ask Git about an instance only under that instance's *current* capability: a static instance needs `git.observe` in the live registry entry and is observed at the root it has now; a derived instance needs the live resolver and its effective RootScope to allow it (that branch is defensive: a project definition holds registered workspaces only, so tests reach it by injection, and the derived workspaces of the index-backed fallback listing are never handed to Git); `filesystem-directory` instances are never handed to Git. An instance that is not asked is reported `observable: false` and listed in `worktree_discovery.not_observed_instances`, never as clean, without history or complete; one instance's failure does not hide the others, and a denied static instance is never answered through a same-named derived one. A `git-repository` registration that grants only `filesystem.read` is therefore no longer observed by Git at project level: add `git.observe` to restore it. Static registrations remain the owner's explicit grant, independent of RootScopes. The set of instances of a project is built when the gateway is constructed.
- built-in HTTP server does not yet enforce a configurable Host-header allowlist; production reverse proxy/gateway must enforce accepted hosts in addition to UAM Origin/auth checks.
- HTTPS termination is delegated to a reverse proxy/tunnel in remote mode.

## Production upgrade order

1. dedicated unprivileged OS principal/sandbox;
2. per-client/per-workspace scoped authentication;
3. OAuth/identity-aware remote access;
4. rate limits and concurrency ceilings;
5. external audit anchoring/signing;
6. structured privacy-preserving telemetry;
7. profile-specific effect controls before adding any write/external-effect profile.
