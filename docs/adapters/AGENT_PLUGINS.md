# Agent Plugins Adapter

Portable package: `adapters/agent-plugin/universal-agent-middleware/`

Layout:

```text
universal-agent-middleware/
├── plugin.json
├── skills/
│   └── uam-research-handoff/
│       └── SKILL.md
└── mcp.json
```

The package targets Agent Plugins `1.0.0`. As of 2026-08-08 the official specification status is `Working Draft`; UAM therefore treats the package as an adapter with its own conformance tests, not a core dependency.

`mcp.json` deliberately contains no Authorization header or secret. Agent Plugins v1 does not make portable package metadata the UAM authorization source; authentication remains client/deployment managed. A client that cannot supply the required application authorization may fail to connect without expanding or weakening UAM capabilities.

The package is a discovery/distribution shell only. It cannot modify workspace policy, create new effect authority, or override a project SSOT.
