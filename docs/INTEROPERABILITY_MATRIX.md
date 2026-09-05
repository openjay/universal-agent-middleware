# UAM Interoperability Matrix V1

UAM deliberately separates **core semantics** from **protocol/package/client/runtime adapters**.

| Layer | Standard / interface | UAM role | Authority | v0.2 status |
|---|---|---|---|---|
| Core ABI | UAM Workspace Registry | workspace identity + explicit capabilities | UAM configuration only | implemented |
| Core ABI | UAM Execution Contract | bounded handoff | cannot exceed target-project authority | `repository-change-v1` implemented |
| Core ABI | UAM Executor Result | submitted execution evidence | evidence claim, not independent attestation | implemented |
| Observation transport | Generic HTTP/OpenAPI 3.1 | protocol-neutral API | no capability amplification | implemented |
| Agent tool transport | MCP 2026-07-28 | stateless tool exposure | adapter only | bounded subset implemented |
| Agent instruction | Agent Skills | portable usage procedure | instructional only | portable skill implemented |
| Portable packaging | Agent Plugins 1.0.0 | package Skills + MCP discovery | no UAM authority semantics | adapter implemented; upstream Working Draft |
| Client overlay | vendor/client-specific metadata | compatibility shim | never core authority | one optional example implemented |
| Executor boundary | READY Contract -> Result | runtime-specific mapping | executor may not broaden scope | generic boundary implemented; live adapters pending |
| Project governance | target-project SSOT/policies | source of project truth | highest authority for that project | external to UAM by design |

## Compatibility law

```text
project authority
    > UAM contract/review semantics
        > adapter metadata
            > conversational/model claims
```

A client or executor is compatible with UAM when it can preserve the stable core identities and semantics. It does **not** need to share another vendor's plugin format, prompt format, billing model, or runtime.

## Version independence

```text
UAM core version
!= workspace-registry version
!= execution-contract profile/version
!= MCP protocol version
!= Agent Plugins version
!= Agent Skills implementation version
!= client version
!= executor version
```

Changes in one layer should normally require an adapter/conformance update, not a rewrite of unrelated layers.
