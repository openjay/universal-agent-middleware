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
- secret/key path denial;
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
