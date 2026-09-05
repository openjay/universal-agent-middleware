# License Decision Record

**Decision:** Retain **MIT License** for Public Preview  
**Status:** PROPOSED — pending explicit Jay approval (OSS-011)  
**Date:** 2026-09-05  
**Baseline:** v0.5.1rc1 Public Preview RC1 candidate

## Rationale

- Existing `LICENSE` file is MIT; copyright holder display name is consistent.
- No third-party code with incompatible license obligations identified in baseline inventory.
- Apache-2.0 remains an alternative if patent-licensing clarity is desired before GA; switching requires NOTICE review and contributor re-acknowledgment.

## Conditions before public flip

1. Confirm no embedded third-party assets require additional attribution (wheel/sdist scan — OSS-032).
2. Confirm no contributor agreements or employer IP claims block MIT release.
3. If license changes to Apache-2.0, update `LICENSE`, `pyproject.toml` classifiers, and release metadata in same commit.

## Current license file

See repository root `LICENSE` — MIT License, Copyright (c) 2026 OpenJay.
