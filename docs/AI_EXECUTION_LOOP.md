# Universal Agent Work Loop V2

The loop is vendor-agnostic:

```text
OBSERVE
  -> REASON
  -> DECIDE
  -> CONTRACT_READY / HOLD
  -> ROUTE_TO_EXECUTOR
  -> EXECUTOR_RESULT
  -> REVIEW_PASS / HOLD
```

## 1. Observe

A reasoning client uses an adapter to inspect a registered workspace. UAM enforces workspace capabilities and treats all target content as untrusted data.

## 2. Reason

The client may use any model, human interaction, web research, or project-specific knowledge. This reasoning is not project authority by itself.

## 3. Decide

Close material unknowns and identify the smallest bounded task. Project SSOT and explicit human/product decisions remain authoritative where applicable.

## 4. Contract

For `repository-change-v1`, UAM first proves a clean observed Git workspace and exact current `HEAD`. The caller-supplied base must equal that `HEAD`; authoritative paths must resolve safely and be tracked by the bound snapshot; allowed change paths must be safe relative paths. Acceptance, verification, rollback, and open questions are then evaluated before READY.

## 5. Route

An external router or user chooses an executor. UAM core does not prefer a vendor. Selection can optimize capability, cost, quota, latency, locality, privacy, or risk.

## 6. Execute

The executor operates in its own capability domain. It must not infer extra authority from conversation history or adapter metadata.

## 7. Evidence

The executor returns immutable result evidence: actual changed paths, base/final revisions, verification results, unresolved risks, and executor identity.

## 8. Review

UAM mechanically checks scope and the submitted evidence. PASS means the submitted Executor Result is internally consistent with UAM's contract checks; it does not independently prove a hostile executor told the truth, and it does not automatically satisfy the target project's deployment/merge/product gates. Independent repository/CI readback or signed executor attestation is a later production hardening layer.

## Human escalation

Human attention is reserved for objectives, scope/authority expansion, material ambiguity, irreversible/high-impact effects, and failures that invalidate the current decision. Routine observation, handoff generation, bounded execution, and mechanical review need not be human checkpoints.

## Resource economics

UAM optimizes scarce execution resources generically. The research context can be large while the execution handoff stays small. Measure executor-specific credits/tokens/API cost/GPU time through adapters, but keep them out of the core contract identity.
