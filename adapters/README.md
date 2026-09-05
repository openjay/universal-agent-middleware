# UAM Adapters

Everything in this directory is replaceable compatibility surface around the vendor-neutral UAM core.

- `http/` — generic OpenAPI representation of the HTTP API.
- `agent-plugin/` — Agent Plugins 1.0.0 portable packaging adapter (Working Draft upstream).
- `openai/` — optional client-specific example overlay; it is not imported by UAM core policy and grants no additional capability.

An adapter may translate invocation or metadata. It may not add workspace capabilities, relax path/security policy, broaden an Execution Contract, or become project authority.
