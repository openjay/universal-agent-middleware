# UAM Architecture V2

## Layer model

```text
+-------------------------------------------------------------------+
| Reasoning / control clients                                       |
| Human UI | Chat clients | IDE agents | autonomous planners        |
+-------------------------------+-----------------------------------+
                                |
                  Northbound adapter boundary
       HTTP/OpenAPI | MCP | Agent Skills/Plugins | client extensions
                                |
                                v
+-------------------------------------------------------------------+
|                    UAM CORE / STABLE ABI                          |
|                                                                   |
| Workspace Registry -> Capability Policy -> Observation Gateway    |
|                    |                    |                          |
|                 Audit Chain          Contract Store               |
|                                          |                        |
|                                     Result Reviewer               |
+----------------------+-------------------+-------------------------+
                       |                   |
              read-only resource      UAM-owned state
                       |                   |
                       v                   v
+------------------------------+      .state/
| Target project workspaces    |      contracts/
| my-app | api-service | others   |      results/
| project authority stays here |      audit.jsonl
+------------------------------+           |
                       |                   |
                       +---------+---------+
                                 v
                         Execution Contract
                                 |
                    Southbound adapter boundary
                                 |
       Codex | Claude Code | Cursor | CI worker | local agent | CI
                                 |
                                 v
                         bounded external effect
                                 |
                                 v
                         Executor Result evidence
                                 |
                                 +------> UAM review PASS/HOLD
```

## Stable vs replaceable surfaces

Stable core:

- versioned workspace identity and capabilities;
- physical state/workspace isolation;
- path/effect policy;
- observation semantics;
- profiled execution contracts;
- result evidence contract;
- audit lineage.

Replaceable adapters:

- client UX;
- LLM/model/provider;
- protocol transport;
- plugin/package format;
- remote tunnel;
- executor runtime;
- vendor billing/quota semantics.

## Why Agent Plugins is not the core

Agent Plugins 1.0.0 standardizes a portable package containing `plugin.json`, Agent Skills under `skills/`, and MCP configuration in `mcp.json`. It intentionally does not standardize installation, permissions, runtime execution, or client UX. UAM therefore uses Agent Plugins as a distribution/discovery adapter while keeping authorization, workspace policy, execution contracts, and evidence review in UAM core.

## Why MCP is not the core

MCP defines the wire/lifecycle semantics for tools and data. UAM exposes MCP and generic HTTP over the same `MiddlewareGateway`. MCP cannot broaden the underlying capabilities; adding an MCP client never creates a write or shell surface that the core does not already provide.

## Evidence trust boundary

The core reviewer is a **contract-conformance reviewer**, not an omniscient execution oracle. It can prove that submitted evidence names the correct contract/workspace/base, stays inside the changed-path allowlist, reports every declared verification command with successful exit status, advances the final revision, and carries no unresolved risk. It cannot by itself prove that a hostile executor did not fabricate those fields. Production-grade executor trust therefore requires a later independent readback/CI attestation or signed executor identity layer.

## Profile extensibility

The stable contract envelope is versioned and includes `profile`.

Implemented:

- `repository-change-v1`

Possible future profiles, not implemented or claimed:

- `read-only-analysis-v1`
- `data-transform-v1`
- `external-effect-v1`
- `deployment-v1`

Each new profile requires its own authority model, schema, reviewer, tests, and explicit effect boundary. A generic `execute(anything)` profile is prohibited.
