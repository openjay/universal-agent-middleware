# Naming and Scope Decision

Canonical name: **Universal Agent Middleware**
Abbreviation: **UAM**
Python package: `universal_agent_middleware`
CLI: `uam`
Environment prefix: `UAM_`

## Why “Middleware”

The system sits between heterogeneous clients, project resources, and heterogeneous executors. It translates and constrains interactions but does not own the target project's product authority or perform the effects itself.

## Why not “Research Control Plane”

That name overweights one current use case and one human-interactive workflow. Research is a northbound workload, not the product identity.

## Why not name an executor or vendor

Any name containing Codex, GPT, OpenAI, Claude, Cursor, or another vendor would turn an adapter choice into architecture. UAM must remain usable when model/client market share, pricing, protocols, or product names change.

## Meaning of “Universal”

Universal means **architecturally neutral and extensible**, not “supports every effect today.” v0.2 truthfully supports one workspace kind and one execution profile. New kinds/profiles require explicit conformance and safety work.


## External naming discipline

Use **Universal Agent Middleware** as the primary external name and `UAM` only as shorthand. The acronym is not treated as globally unique, and this engineering naming decision is not a trademark/domain clearance. Product identity must not depend on acronym exclusivity.
