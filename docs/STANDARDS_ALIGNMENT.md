# Standards Alignment — 2026-08-08

This document records interoperability targets; it is not a substitute for upstream specifications.

## Agent Plugins 1.0.0

Upstream: `agent-plugins.org` / `agentplugins/agent-plugins-spec`.

Current official status: **Specification version 1.0.0, Working Draft**.

Portable core:

- required `plugin.json`;
- optional `skills/` immediate children containing `SKILL.md`;
- optional root `mcp.json`;
- client-specific data only under reverse-domain extension namespaces.

Agent Plugins v1 defines exactly two portable component types: Agent Skills and MCP servers. Distribution, installation, permissions, runtime execution, authorization UX, and client UX remain client-owned.

UAM policy:

- target Agent Plugins v1 as an optional package adapter;
- do not put secrets in `mcp.json` headers;
- do not encode UAM authority into client extension metadata;
- do not make UAM core ABI depend on a Working Draft package schema;
- re-run package conformance when the upstream schema/version changes.

Upstream schema SHAs observed 2026-08-08:

- `plugin.schema.json`: `8fed0e1fe45d0464aee880d3fbab228b71ecfc1e`
- `mcp.schema.json`: `a9139a4259b932c60b5351c8d9da6a5c60c97646`

## Agent Skills

UAM's portable skill follows the Agent Skills directory model: a skill directory with required `SKILL.md` YAML frontmatter and Markdown instructions. UAM keeps core operational policy in code/SSOT; a skill only teaches a client how to use the middleware and cannot grant permissions.

## MCP 2026-07-28

UAM targets the modern stateless MCP revision for new integrations:

- no protocol-level session requirement;
- `server/discover` for capability/version discovery;
- per-request protocol version and client-capability metadata (`clientInfo` is optional/SHOULD in the final revision);
- server identity stamped in response `_meta`;
- Streamable HTTP request routing with `MCP-Protocol-Version`, `Mcp-Method`, and applicable `Mcp-Name` headers;
- `tools/list` and `tools/call` over a stateless core;
- result cache hints on cacheable operations;
- server identity reported in response metadata in the final 2026-07-28 wire behavior;
- Origin validation and authentication on HTTP transport.

UAM v0.2 implements only the bounded tools surface it needs. Its tests target the final 2026-07-28 wire behavior used by the Tier-1 SDK migration guidance; it does not claim full protocol conformance. It does not implement MCP Tasks, Apps, resources, prompts, subscriptions, MRTR, OAuth, or legacy sessionful compatibility and does not claim conformance for those features.

## OpenAPI 3.1

The generic HTTP API is described with OpenAPI 3.1 without vendor extensions. Client-specific overlays may add vendor metadata in their adapter files; such fields never enter the generic schema or core policy.

## Compatibility rule

Upstream standards can change independently. UAM versioning treats protocol/package support as adapters:

```text
UAM core version != MCP version != Agent Plugins version != client version
```

A standards upgrade should replace or version an adapter and conformance suite, not rewrite project authority or contract truth.
