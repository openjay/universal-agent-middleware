# MCP Adapter

UAM v0.5.1rc1 (Public Preview RC1) targets MCP revision `2026-07-28` for modern integrations.

The session-read profile exposes **19 read-only MCP tools** derived from `tool_contract.json`. See `docs/oss/public-profile-contract.md` for the canonical inventory.

HTTP endpoint: `POST /mcp`
Stdio entry: `uam mcp-sdk-stdio --profile session-read --registry ... --state-dir ...`

Implemented RPCs:

- `server/discover`
- `tools/list`
- `tools/call`

The tool set is a direct translation of `MiddlewareGateway`; MCP cannot create capabilities not present in core.

HTTP clients must authenticate and send the modern protocol/header envelope. UAM binds `MCP-Protocol-Version`, `Mcp-Method`, and applicable `Mcp-Name` to the JSON-RPC body and requires the final-revision per-request `_meta` protocol/capability envelope. `clientInfo` is accepted when present but is not used as authority. Invalid Origin, content type, protocol version, or header/body binding fails closed.

Successful 2026-07-28 responses stamp server identity in response `_meta`; `tools/list` is deterministic and carries private/zero-TTL cache hints.

Not implemented/claimed: resources, prompts, subscriptions, Tasks extension, MCP Apps, MRTR, OAuth discovery, or legacy sessionful compatibility.
