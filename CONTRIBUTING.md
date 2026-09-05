# Contributing to Universal Agent Middleware

Thank you for your interest in contributing. UAM is in **Public Preview** — we welcome fixes, tests, and documentation improvements that strengthen the read-only observation contract.

## Getting Started

1. Fork the repository and create a feature branch from `main` (or `master` during transition).
2. Install in editable mode with test dependencies:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[service]" pytest build
```

3. Run the full test suite before submitting:

```bash
python -m pytest -q
```

## Development Guidelines

- **Minimize scope** — focused changes that match existing conventions
- **No machine-specific fixtures** — use `tests/synthetic_fixtures.py` and temporary Git repos
- **Preserve invariants** — session-read profile must remain read-only; document any experimental surfaces
- **Tests required** — bug fixes and new behavior need regression tests
- **Imports at module top** — no inline imports unless circular dependency is documented

## Pull Request Process

1. Update documentation if you change user-visible behavior, tool contracts, or supported surfaces
2. Ensure CI passes (Python 3.11–3.14 on Linux and macOS)
3. Reference related issues in the PR description
4. One logical change per PR when possible — easier review and revert

Use the PR template and complete the checklist.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License, consistent with the project.

## Areas We Need Help

- Negative security test cases (scope precedence, symlinks, path encoding)
- Portable documentation and examples
- MCP Registry metadata validation
- Windows support exploration (not yet in supported matrix)

See `docs/BACKLOG.md` and `docs/oss/public-profile-contract.md` for current scope boundaries.
