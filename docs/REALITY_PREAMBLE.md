# Reality Preamble Protocol (v0.3.2)

> **Every transition decision must be preceded by a coverage check.**
> If a required truth surface is not covered, the decision cannot be made.

## Principle

UAM is an **epistemic control plane** — it observes and reports reality.
It is NOT a constitutional authority plane — it does not authorize actions.

```text
Observation   ≠   Interpretation   ≠   Authority

UAM_COVERAGE_COMPLETE  ≠  PROJECT_AUTHORITY_GRANTED
```

## Protocol

Before any transition decision in any project:

```text
1. uam_project_reality(project_id)
2. Identify required truth surfaces for THIS decision type
3. Check: are all required surfaces at least "observed", "externally_verified", or "not_applicable"?
4. If YES → proceed with decision using observed evidence
5. If NO  → mark uncovered claims as UNKNOWN, do not infer from other surfaces
```

## Observation Requirements (not Decision Requirements)

These define which surfaces must be observable — NOT what authority is needed.
Authority is always `PROJECT_DEFINED` and never evaluated by UAM.

| Decision Context | Required Surfaces | Notes |
|------------------|-------------------|-------|
| Candidate consideration | `active_candidate`, `canonical_source`, `forge_ci` | candidate must exist |
| Merge consideration | `active_candidate`, `canonical_source`, `forge_ci` | Does NOT grant merge authority |
| Runtime consideration | `canonical_source`, `runtime` | |
| Full activation | ALL: `canonical_source`, `active_candidate`, `forge_ci`, `runtime` | |

## Coverage States

| State | Meaning |
|-------|---------|
| `observed` | UAM can read live data from this surface |
| `externally_verified` | Verified via external tool (e.g. GitHub API), not native UAM |
| `not_applicable` | Surface is not relevant in current project state (e.g. no candidate exists) |
| `not_registered` | Role exists logically but no instance is authorized |
| `discovered_not_authorized` | Worktree found but not registered for content reads |
| `not_observed` | No information available for this surface |

## Instance Model: role × lifecycle

Workspace instances have two orthogonal dimensions:

| Dimension | Values | Meaning |
|-----------|--------|---------|
| `role` | canonical-main, candidate, review-carrier, development, runtime | Structural function |
| `lifecycle` | active, landed, stale, superseded, historical | Temporal state |

Example: a PR that merged has `role=candidate, lifecycle=landed`.
This replaces the old conflated `active-candidate` / `merged-candidate` roles.

## Rules

1. **Never infer a covered surface from an uncovered one.**
   - `active_candidate = observed` does NOT imply `forge_ci = observed`
   - Local candidate clean does NOT imply remote CI green

2. **`externally_verified` is acceptable but must cite source.**
   - GitHub API readback, terminal evidence, or human attestation
   - Must include timestamp and exact reference (SHA, run ID, etc.)

3. **`not_observed` surfaces produce UNKNOWN claims, not FALSE claims.**
   - "I don't see runtime" ≠ "runtime is down"
   - "I don't see CI" ≠ "CI failed"

4. **`not_applicable` is a valid satisfied state.**
   - No active candidate when the merge train is complete = healthy
   - This does NOT reduce coverage status to PARTIAL

5. **Coverage is per-decision, not per-project.**
   - A project can be PARTIAL overall but SUFFICIENT for a specific decision
   - Example: `merge_consideration` only needs candidate + source + CI, not runtime

6. **UAM reality is live per invocation.**
   - Snapshots have timestamps; they are observations, not durable facts
   - Stale snapshots (>5 min for active decisions) should be refreshed

7. **`observation_requirements` ≠ authorization.**
   - All observation surfaces satisfied does NOT imply permission to act
   - Project authority is always separate and defined by the project's own governance

## Boundary: What UAM Does NOT Do

- Does not authorize merges, deploys, or activations
- Does not interpret project authority or SSOT
- Does not substitute for project-defined governance
- Does not cache observations across invocations
- Does not make decisions based on coverage alone
- Does not evaluate whether authority has been granted

## Project-specific Observation Profiles

Projects define their own observation requirements via:
```text
config/project-observation-profiles/<project_id>.json
```

These profiles are informational and loaded by UAM to provide
project-tailored `observation_requirements` in coverage diagnostics.
They do NOT grant authority — project SSOT controls real gate semantics.

## Example project observation profile

```text
Phase A exit observation:
  canonical_source    observed
  forge_ci            observed or externally_verified
  runtime_identity    observed or externally_verified
  active_candidate    observed IF candidate exists
                      not_applicable otherwise

Phase B exit observation:
  canonical_source    observed
  runtime             observed
  serving_artifact    observed or externally_verified

Phase C (G51 activation):
  ALL surfaces        observed or externally_verified
  no critical warnings
```

Human Decisions (#1, #2, #3) are the ONLY points where:
- Coverage gaps can be accepted by human judgment
- Authority transitions happen
- Standing permissions are granted or revoked
