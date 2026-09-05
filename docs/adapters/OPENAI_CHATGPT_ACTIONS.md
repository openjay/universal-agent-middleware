# Optional OpenAI / ChatGPT Actions Adapter

This is an optional client adapter example, not part of UAM core identity.

Generate the generic OpenAPI surface:

```bash
uam openapi
```

Generate a client-specific Actions overlay:

```bash
uam openapi --adapter openai-actions
```

The overlay adds OpenAI-specific consequential-operation metadata only to this adapter output. Those fields are absent from UAM's generic OpenAPI schema and do not change capabilities or authority.

For remote use, expose the loopback service through authenticated HTTPS infrastructure and configure the client to send the same application authorization. Never treat a tunnel as authentication.
