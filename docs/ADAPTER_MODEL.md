# Adapter Model V1

UAM uses ports-and-adapters semantics.

## Northbound client adapters

A client adapter translates a client's invocation model into UAM core operations. It may not add capabilities.

Current:

- `http-openapi-v1`
- `mcp-2026-07-28`
- `agent-plugins-1.0.0` portable package
- `openai-actions` optional overlay example

Future examples:

- Claude/Anthropic-specific extension
- Cursor extension
- GitHub Copilot extension
- VS Code extension
- custom native client

Client-specific code must remain optional and isolated. No vendor adapter can become the default authority source.

## Southbound executor adapters

An executor adapter consumes an already READY contract and returns an Executor Result. The adapter is responsible for mapping UAM's bounded contract to its runtime, but it may not broaden scope silently.

Potential executors:

- coding agents;
- IDE agents;
- local models;
- CI repair agents;
- native execution workers;
- future specialized execution systems.

A specific executor's quotas, prompt syntax, model routing, or proprietary tool calls belong only in that adapter.

## Workspace adapters

v0.2 implements `git-repository` with capabilities:

- `filesystem.read`
- `git.observe`

Additional workspace kinds require explicit implementation and tests. A directory is not automatically treated as a database, cloud account, brokerage account, or runtime environment.

## Adapter conformance law

Every adapter must prove:

1. same core authorization result as direct gateway use;
2. no capability amplification;
3. deterministic mapping of required fields;
4. explicit failure on unsupported semantics;
5. no secret material in portable package metadata;
6. evidence retains workspace/contract identity across the boundary;
7. vendor-specific metadata stays outside the stable core ABI.
