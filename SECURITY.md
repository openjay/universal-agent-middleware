# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes (Public Preview) |
| < 0.5   | No |

Public Preview receives security fixes for permission-boundary and audit-integrity issues. Breaking API changes may ship in patch releases during Preview.

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

1. Use [GitHub Private Vulnerability Reporting](https://github.com/openjay/universal-agent-middleware/security/advisories/new) on the public repository (preferred once visibility is public).
2. If reporting is unavailable, contact the maintainers through the private channel established for OpenJay project security.

Include:

- Description of the vulnerability and affected surfaces (MCP stdio, HTTP adapter, LocalExecutor, etc.)
- Steps to reproduce with synthetic fixtures where possible
- Impact assessment (confidentiality, integrity, availability)
- Suggested fix if you have one

## Response Expectations

Maintainers will acknowledge receipt and provide a triage update. Public Preview does not publish fixed SLA commitments; critical permission-boundary issues in the session-read profile are prioritized.

## Scope Notes

- **In scope:** path traversal, scope search leakage, secret firewall bypass, audit tampering, unauthorized write via read-only profile
- **Out of scope for session-read Preview:** LocalExecutor write paths (documented as experimental), legacy HTTP adapter unless it bypasses read-only policy
- **Prompt injection:** returned file content is untrusted; middleware enforces containment but cannot eliminate model-level injection risk

## Safe Harbor

We appreciate responsible disclosure. Researchers who follow this policy and avoid privacy violations (no access to others' systems or data) will not be pursued for good-faith research on their own installations.
