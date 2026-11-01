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

A release is one frozen pair of artifacts, a wheel and an sdist, built once from the tagged commit. The same bytes are attached to the GitHub Release (with a `SHA256SUMS` file) and uploaded to PyPI by the maintainer; nothing rebuilds them afterwards.

1. Tag the reviewed commit with a PEP 440 version (e.g. `0.6.3`); CI must be green on that commit.
2. Build the wheel and the sdist once, record their SHA-256 in `SHA256SUMS`, and attach the three files to a draft GitHub Release.
3. Upload the same two files to PyPI, then publish the GitHub Release.
4. `.github/workflows/release.yml` runs when the release is published (and on demand for a tag). It builds nothing and publishes nothing: it fails unless the release assets, `SHA256SUMS` and the files PyPI serves agree byte for byte (`tools/verify_release_assets.py`).
5. Release notes document supported surfaces and known limitations.

No workflow in this repository publishes to PyPI, and a PyPI Trusted Publisher is not part of this process; do not read the verification workflow as one.

## RFC / Major Changes

Changes that affect the MCP tool contract, authorization model, or Preview supported surface should be discussed in an issue labeled `rfc` before implementation.

## No Foundation (Preview)

UAM is not currently governed by a separate foundation or CLA program. Contributors license work under MIT via contribution to the repository.
