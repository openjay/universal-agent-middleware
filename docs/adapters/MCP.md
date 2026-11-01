# MCP Adapter

UAM v0.6.3 (Public Preview) targets MCP revision `2026-07-28` for modern integrations.

The session-read profile of this source tree is `READ_ONLY_SESSION_PROFILE_V3`: **20 read-only MCP tools** derived from `tool_contract.json` — the 19 tools of `READ_ONLY_SESSION_PROFILE_V2` plus `uam_file_digest`, which only this SDK adapter serves (the legacy HTTP/OpenAPI and custom stdio adapters do not). `docs/oss/profile-v3-declaration.json` binds the complete tool set, the input/output/safety/description fingerprints and the metadata difference against V2 (seven tool descriptions changed, so connectors must Refresh); `docs/oss/public-profile-contract-v3.md` is the successor contract. V3 is **adopted locally** (the maintainer's own supervised runtime) and **published in 0.6.3**. The 19-tool inventory of the published v0.5.1rc1 stays the historical baseline in `docs/oss/public-profile-contract.md`.

**Distribution:** Install from PyPI (`pip install "universal-agent-middleware[mcp]==0.6.3"`) or download the wheel and sdist from [GitHub Release v0.6.3](https://github.com/openjay/universal-agent-middleware/releases/tag/v0.6.3); `SHA256SUMS` lists their digests and PyPI serves the same bytes. The CI evidence for a release is the GitHub Actions run of its tagged commit.

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
