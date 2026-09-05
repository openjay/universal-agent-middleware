# Governance

Universal Agent Middleware is maintained by **OpenJay** under the direction of the project owner.

## Decision Model

| Decision type | Authority |
|---------------|-----------|
| Public release, license, namespace | Project owner (Jay) |
| Security advisories and embargo | Project owner + security reporters |
| Merged code changes | Maintainers via PR review |
| Supported surface / Preview contract | Documented in `docs/oss/public-profile-contract.md`; changes require owner review |
| Dependency and CI policy | Maintainers; major changes need owner awareness |

## Maintainer Responsibilities

- Review PRs for security, portability, and contract alignment
- Triage issues and security reports
- Cut releases from tagged commits with verified artifacts
- Keep documentation consistent with the Public Preview contract

## Contribution Path

1. Open an issue for significant changes before large PRs
2. Submit PR with tests
3. Maintainer review — at least one approval for merge
4. CI must pass on the full supported matrix

CODEOWNERS may be configured for automatic review requests; branch protection enforcement is configured at the repository level.

## Release Process

Releases follow the workflow in `.github/workflows/release.yml`:

1. Tag with PEP 440 version (e.g. `0.5.1rc1` for preview candidates)
2. GitHub Release triggers build, attestation, and PyPI publish (Trusted Publishing)
3. Release notes document supported surfaces and known limitations

## RFC / Major Changes

Changes that affect the MCP tool contract, authorization model, or Preview supported surface should be discussed in an issue labeled `rfc` before implementation.

## No Foundation (Preview)

UAM is not currently governed by a separate foundation or CLA program. Contributors license work under MIT via contribution to the repository.
