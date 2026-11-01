"""Pure rules of the successor contract for ``task-control`` (candidate, not deployed).

``task_control`` keeps its version-1 behaviour. This module holds what a successor needs and the first
batch could not say, as functions over plain delivery records (no I/O, no clock, no state of its own):

* the **version-2 authority binding**: which transition exactly (who hands what to whom, in which role and
  namespace, bound to which attempt, fence and data scope) a request asks the authority about, and the
  ``binding_digest`` that UAM computes and a verifier recomputes with ``compute_binding_digest``;
* **stop evidence**: what, if anything, shows that an attempt's executor stopped. A closed lease and a
  handover closure are *not* evidence of that; only the original executor's own report or a recorded
  result is, and even that is a self-report, not fencing (there is no Runner/PEP to fence an effect);
* **new-effect permission**: what the record alone says about starting another attempt, kept apart from
  the live conditions (an unchanged baseline observed now, and an authority that allows it now);
* **unresolved effects** of the other deliveries of one business task, so a new contract for the same task
  cannot silently drop a partial or unknown effect;
* the **Context Package**: references and digests that let a successor locate a task and its pending
  evidence. It carries no secrets, no original chat, no transferable Grant and no contract or result text,
  and holding it grants no right to read any of that.

Limits, stated once: ``owner_ref``, ``endpoint_ref`` and ``declared_region`` are declarations that UAM
records and passes on but cannot verify; whether a principal may act for an owner is the authority's
decision. Nothing here is an issuer, a task ledger, a consensus step or a global identifier.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .contracts import ContractBinding, canonical_digest
from .task_control import (
    ATTEMPT_ACTIVE,
    ATTEMPT_ENDED,
    ATTEMPT_RESULT,
    EFFECT_NONE_OBSERVED,
    MAX_ATTEMPTS,
    STATE_CANCELLED,
    STATE_RECONCILIATION_REQUIRED,
    STATE_RESULT_RECORDED,
    AuthorityRequest,
    TaskControlError,
    _delivery_id,
    _text,
)

DELIVERY_SCHEMA_V2 = "uam-task-control-delivery-v2"
BINDING_VERSION = "uam-authority-binding-v2"
CONTEXT_PACKAGE_SCHEMA = "uam-context-package-v1"

EFFECT_HANDOVER = "handover"
EFFECT_CONTINUE_TASK = "continue_task"
EFFECT_CONTEXT_RECEIVE = "context_receive"
EFFECT_DEREFERENCE = "dereference"

ROLE_REQUESTER = "requester"
ROLE_RECIPIENT = "recipient"
ROLE_FORMER_RECIPIENT = "former_recipient"
HANDOVER_ROLES = (ROLE_REQUESTER, ROLE_RECIPIENT)

END_LEASE_EXPIRED = "LEASE_EXPIRED"
END_HANDED_OVER = "HANDED_OVER"
UNCONFIRMED_ENDS = (END_LEASE_EXPIRED, END_HANDED_OVER)

STOP_ACTIVE = "ATTEMPT_ACTIVE_NOT_CONFIRMED"
STOP_SELF_REPORTED = "SELF_REPORTED_BY_EXECUTOR"
STOP_SELF_REPORTED_LATE = "SELF_REPORTED_LATE"
STOP_NOT_CONFIRMED = {
    END_LEASE_EXPIRED: "NOT_CONFIRMED_LEASE_EXPIRED",
    END_HANDED_OVER: "NOT_CONFIRMED_HANDED_OVER",
}
STOP_NOT_APPLICABLE_RESULT = "NOT_APPLICABLE_RESULT_RECORDED"
STOP_NOT_APPLICABLE_NO_ATTEMPT = "NOT_APPLICABLE_NO_ATTEMPT"
_CONFIRMED_STOPS = frozenset({STOP_SELF_REPORTED, STOP_SELF_REPORTED_LATE, STOP_NOT_APPLICABLE_RESULT})

SCOPE_SELF = "self"
SCOPE_PREDECESSOR = "predecessor"
SCOPE_WORKSPACE = "workspace"

EFFECT_FENCING = "NOT_PROVIDED"  # no Runner/PEP exists to fence an effect; stated in every v2 view
MAX_HANDOVERS = 20
MAX_CONTINUES = 8
MAX_EVENTS_IN_PACKAGE = 20

_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_REGION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

_BINDING_FIELDS = (
    "effect", "authority_ref", "principal", "initiator", "role", "endpoint_ref", "owner_ref", "requester",
    "recipient", "from_principal", "to_principal", "handover_seq", "delivery_id", "contract_id",
    "contract_digest", "workspace_id", "business_task_ref", "task_revision", "attempt_ref", "fence",
    "original_executor", "late_after_attempt_end", "data_scope",
)


class ContinuityRefusal(TaskControlError):
    """A refusal that also carries a small, deliberately limited ``details`` object for the caller."""

    def __init__(self, code: str, message: str, details: dict[str, Any]):
        super().__init__(code, message)
        self.details = details


# --- validation -----------------------------------------------------------------------------------


def validate_label(value: Any, name: str, *, optional: bool = False) -> str | None:
    """A namespace label (``owner_ref``, ``endpoint_ref``). A declaration UAM records and never verifies."""
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise TaskControlError("INVALID_ARGUMENT", f"{name} must match {_LABEL.pattern}")
    return value


def validate_region(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _REGION.fullmatch(value):
        raise TaskControlError("INVALID_ARGUMENT", f"declared_region must match {_REGION.pattern}")
    return value


def validate_role(value: Any) -> str:
    if value not in HANDOVER_ROLES:
        raise TaskControlError("INVALID_ARGUMENT", f"role must be one of {', '.join(HANDOVER_ROLES)}")
    return value


def validate_task(task_ref: Any, revision: Any) -> tuple[str, int]:
    """A v2 delivery always belongs to one business task revision (the owner's, correlated and not owned here)."""
    ref = _text(task_ref, "business_task_ref", limit=200)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise TaskControlError("INVALID_ARGUMENT", "task_revision must be a positive integer")
    return ref, revision


def validate_continues(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > MAX_CONTINUES:
        raise TaskControlError("INVALID_ARGUMENT", f"continues must be a list of at most {MAX_CONTINUES} delivery ids")
    ids = [_delivery_id(item) for item in value]
    if len(set(ids)) != len(ids):
        raise TaskControlError("INVALID_ARGUMENT", "continues must not repeat a delivery id")
    return tuple(sorted(ids))


def reason_code(value: Any) -> str:
    """A verifier's reason is kept only when it is a code, never as free text."""
    return value if isinstance(value, str) and _REASON_CODE.fullmatch(value) else "UNSPECIFIED"


# --- identity of a v2 delivery and its data scope -------------------------------------------------


def is_continuity(delivery: Mapping[str, Any]) -> bool:
    return delivery.get("schema") == DELIVERY_SCHEMA_V2


def continuity_delivery_id(endpoint_ref: str | None, owner_ref: str, principal: str, idempotency_key: str) -> str:
    """Same shape as a v1 id, but derived inside the namespace, so two owners' local keys cannot collide."""
    seed = f"uam-delivery-v2\0{endpoint_ref or ''}\0{owner_ref}\0{principal}\0{idempotency_key}"
    return "dlv-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def derive_data_scope(binding: ContractBinding, scope_ref: str, declared_region: str | None) -> dict[str, Any]:
    """What UAM can state about the data a delivery covers; ``declared_region`` is a claim, not a residency proof."""
    return {
        "scope_ref": scope_ref,
        "declared_region": declared_region,
        "workspace_id": binding.workspace_id,
        "contract_digest": binding.digest,
        "paths_digest": canonical_digest({
            "authoritative_paths": list(binding.authoritative_paths),
            "allowed_change_paths": list(binding.allowed_change_paths),
        }),
        "baseline_digest": canonical_digest(binding.baseline),
    }


def region_claim(data_scope: Mapping[str, Any]) -> dict[str, Any]:
    """What UAM says about a region wherever it shows one: a declaration of the requester, never a verification."""
    declared = data_scope["declared_region"]
    return {
        "declared_region": declared,
        "declared_region_status": "DECLARED_NOT_VERIFIED" if declared is not None else "NOT_DECLARED",
        "processing_region_check": "NOT_VERIFIED_BY_UAM",
    }


# --- the version-2 authority binding --------------------------------------------------------------


def pending_evidence_digest(pending: Iterable[Mapping[str, Any]]) -> str | None:
    """Order-independent digest of the evidence a request carries; ``None`` when there is none."""
    items = sorted(pending, key=lambda item: (item["scope"], item["delivery_id"]))
    return canonical_digest({"pending_evidence": items}) if items else None


def binding_of(request: Any) -> dict[str, Any]:
    """The canonical binding of an ``AuthorityRequest``: everything a verifier must check, from the request alone."""
    values = {name: getattr(request, name) for name in _BINDING_FIELDS}
    values["continues"] = sorted(request.continues)
    values["pending_evidence_digest"] = pending_evidence_digest(request.pending_evidence)
    values["binding_version"] = BINDING_VERSION
    return values


def compute_binding_digest(request: Any) -> str:
    """The digest UAM puts in ``binding_digest``. A verifier recomputes it from the request and compares.

    ``authority_ref`` is inside the digest: it proves which reference was presented for exactly this
    transition. A verifier must still check, for itself, that the reference is valid now for this effect,
    principal and binding; a matching digest alone is not an allow.
    """
    return canonical_digest(binding_of(request))


def make_request(
    *,
    effect: str,
    principal: str,
    authority_ref: str,
    delivery_id: str,
    contract_id: str,
    contract_digest: str,
    workspace_id: str,
    endpoint_ref: str | None,
    owner_ref: str,
    role: str,
    requester: str,
    recipient: str,
    business_task_ref: str,
    task_revision: int,
    data_scope: dict[str, Any],
    handover_seq: int = 0,
    initiator: str | None = None,
    from_principal: str | None = None,
    to_principal: str | None = None,
    attempt_ref: str | None = None,
    fence: int | None = None,
    original_executor: str | None = None,
    late_after_attempt_end: str | None = None,
    continues: Sequence[str] = (),
    pending_evidence: Sequence[dict[str, Any]] = (),
) -> AuthorityRequest:
    """A version-2 request with its ``binding_digest`` filled in by UAM (a caller never supplies one)."""
    request = AuthorityRequest(
        authority_ref=authority_ref, principal=principal, effect=effect, delivery_id=delivery_id,
        contract_id=contract_id, contract_digest=contract_digest, workspace_id=workspace_id,
        business_task_ref=business_task_ref, task_revision=task_revision, request_version=2,
        endpoint_ref=endpoint_ref, owner_ref=owner_ref, role=role, initiator=initiator, requester=requester,
        recipient=recipient, from_principal=from_principal, to_principal=to_principal,
        handover_seq=handover_seq, attempt_ref=attempt_ref, fence=fence, original_executor=original_executor,
        late_after_attempt_end=late_after_attempt_end, continues=tuple(sorted(continues)),
        data_scope=copy.deepcopy(data_scope), pending_evidence=tuple(copy.deepcopy(dict(item)) for item in pending_evidence),
    )
    return dataclasses.replace(request, binding_digest=compute_binding_digest(request))


# --- stop evidence, and what the record alone permits ---------------------------------------------


def attempt_stop_evidence(attempt: Mapping[str, Any]) -> str:
    """Whether anything shows that this attempt's executor stopped. A closure by UAM is never that."""
    if attempt["state"] == ATTEMPT_ACTIVE:
        return STOP_ACTIVE
    if attempt["state"] == ATTEMPT_RESULT:
        return STOP_NOT_APPLICABLE_RESULT
    how = attempt["end"]["how"]
    if how == "REPORTED":
        return STOP_SELF_REPORTED
    if "late_stop_report" in attempt:
        return STOP_SELF_REPORTED_LATE
    return STOP_NOT_CONFIRMED[how]


def delivery_stop_evidence(delivery: Mapping[str, Any]) -> str:
    if delivery["result"] is not None:
        return STOP_NOT_APPLICABLE_RESULT
    if not delivery["attempts"]:
        return STOP_NOT_APPLICABLE_NO_ATTEMPT
    return attempt_stop_evidence(delivery["attempts"][-1])


def unconfirmed_end(attempt: Mapping[str, Any]) -> str | None:
    """``how`` when the attempt was closed by UAM and its executor never said it stopped, else ``None``."""
    if attempt["state"] != ATTEMPT_ENDED:
        return None
    how = attempt["end"]["how"]
    if how in UNCONFIRMED_ENDS and "late_stop_report" not in attempt:
        return how
    return None


def stop_blockers(delivery: Mapping[str, Any]) -> list[str]:
    """The blockers that only the original executor's evidence can lift (the stop gate of ``start_attempt``)."""
    attempts = delivery["attempts"]
    how = unconfirmed_end(attempts[-1]) if attempts else None
    return [f"STOP_NOT_CONFIRMED_{how}"] if how is not None else []


def new_effect_permission(delivery: Mapping[str, Any]) -> dict[str, Any]:
    """What the *record* says about a new attempt. It is not a grant: the live conditions still apply.

    Late evidence lifts only the stop blockers and ``ATTEMPT_ACTIVE``; a workspace that is not observed to
    match the baseline, a sibling delivery of the same task that is active or unsettled (a live fact about
    *other* records, so not in ``blockers``), and an authority that does not allow it, still refuse a new attempt.
    """
    blockers: list[str] = []
    if delivery["result"] is not None or delivery["state"] == STATE_RESULT_RECORDED:
        blockers.append("RESULT_RECORDED")
    if delivery["cancel"] is not None or delivery["state"] == STATE_CANCELLED:
        blockers.append("CANCELLED")
    attempts = delivery["attempts"]
    if attempts and attempts[-1]["state"] == ATTEMPT_ACTIVE:
        blockers.append("ATTEMPT_ACTIVE")
    blockers.extend(stop_blockers(delivery))
    if len(attempts) >= MAX_ATTEMPTS:
        blockers.append("ATTEMPT_LIMIT")
    return {
        "record_permits_new_attempt": not blockers,
        "blockers": blockers,
        "still_required": ["BASELINE_UNCHANGED_LIVE", "SAME_TASK_SINGLE_ACTIVE_LIVE", "AUTHORITY_attempt_start"],
        "reconciliation_pending": delivery["state"] == STATE_RECONCILIATION_REQUIRED,
        "effect_fencing": EFFECT_FENCING,
    }


def evidence_ingestion(delivery: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The late evidence the delivery accepted: who gave it, for which attempt, after which closure."""
    log: list[dict[str, Any]] = []
    for attempt in delivery["attempts"]:
        if "late_receipt" in attempt:
            log.append({
                "kind": "LATE_RECEIPT", "attempt_ref": attempt["attempt_ref"], "executor": attempt["executor"],
                **attempt["late_receipt"],
            })
        if "late_stop_report" in attempt:
            log.append({
                "kind": "LATE_STOP_REPORT", "attempt_ref": attempt["attempt_ref"], "executor": attempt["executor"],
                **{key: attempt["late_stop_report"][key] for key in ("outcome", "reported_at")},
            })
    return log


# --- the other deliveries of one task -------------------------------------------------------------


def is_unresolved(delivery: Mapping[str, Any]) -> bool:
    """Whether an effect of this delivery is still open, so that a new contract for the same task could drop it.

    * a recorded result settles the effect plane only; whether it is accepted stays the owner's decision, so
      a held review does not keep a task unresolved;
    * a delivery nobody ever started has no effect to drop (a requester may still hold several fresh
      deliveries for one task; cancelling a stale one stays the requester's business, and ``start_attempt`` still
      lets only one of them be active at a time);
    * an active attempt, an effect that is partial or unknown, or an attempt whose executor never said it
      stopped, is open, whether or not the delivery was cancelled since.
    """
    if delivery["state"] == STATE_RESULT_RECORDED:
        return False
    attempts = delivery["attempts"]
    if not attempts:
        return False
    last = attempts[-1]
    if last["state"] != ATTEMPT_ENDED or last["end"]["effect"] != EFFECT_NONE_OBSERVED:
        return True
    return any(attempt_stop_evidence(attempt) not in _CONFIRMED_STOPS for attempt in attempts)


def predecessor_evidence(delivery: Mapping[str, Any], *, scope: str, effect: str) -> dict[str, Any]:
    """A bounded summary of another delivery: references, states and digests, never content."""
    return {
        "scope": scope,
        "delivery_id": delivery["delivery_id"],
        "payload_digest": delivery["payload_digest"],
        "state": delivery["state"],
        "effect": effect,
        "stop_evidence": delivery_stop_evidence(delivery),
        "attempts_used": len(delivery["attempts"]),
        "contract_digest": delivery["contract_digest"],
        "task_revision": delivery["task_revision"],
        "unresolved": is_unresolved(delivery),
    }


# --- views ----------------------------------------------------------------------------------------


def _coarse(observation: Mapping[str, Any]) -> dict[str, Any]:
    return {"state": observation.get("state"), "observed_at": observation.get("observed_at")}


def withhold_content(view: dict[str, Any]) -> dict[str, Any]:
    """The metadata of a delivery without any path-level observation or free text of the executor.

    Used when ``dereference`` was not granted: the planes (state, effect, stop evidence, permission) stay
    readable, what the workspace or the executor said does not.
    """
    out = copy.deepcopy(view)
    for item in out.get("attempts", []):
        end = item.get("end")
        if isinstance(end, dict):
            if isinstance(end.get("observation"), dict):
                end["observation"] = _coarse(end["observation"])
            if "note" in end:
                end["note"] = ""
        stop_report = item.get("late_stop_report")
        if isinstance(stop_report, dict) and "note" in stop_report:
            stop_report["note"] = ""
    cancel = out.get("cancel")
    if isinstance(cancel, dict) and isinstance(cancel.get("effect_evidence"), dict):
        cancel["effect_evidence"] = _coarse(cancel["effect_evidence"])
    result = out.get("result")
    if isinstance(result, dict) and "review_blockers" in result:
        result["review_blockers"] = []
    return out


def coarse_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    return _coarse(observation)


def former_view(delivery: Mapping[str, Any], attempt: Mapping[str, Any], *, effect: str) -> dict[str, Any]:
    """What a replaced executor sees after reporting on its own attempt: that attempt, nothing else."""
    end = attempt.get("end")
    return {
        "delivery_id": delivery["delivery_id"],
        "viewer_role": ROLE_FORMER_RECIPIENT,
        "state": delivery["state"],
        "effect": effect,
        "stop_evidence": attempt_stop_evidence(attempt),
        "attempt": {
            "attempt_ref": attempt["attempt_ref"],
            "fence": attempt["fence"],
            "state": attempt["state"],
            "end_how": end["how"] if isinstance(end, dict) else None,
            "late_stop_report": attempt.get("late_stop_report"),
            "late_receipt": attempt.get("late_receipt"),
        },
        "business_acceptance": "NOT_DETERMINED_BY_UAM",
    }


def build_context_package(
    delivery: Mapping[str, Any], *, effect: str, viewer: str, viewer_role: str, generated_at: str,
) -> dict[str, Any]:
    """The minimal Context Package of one v2 delivery: references and digests only."""
    result = delivery["result"]
    package: dict[str, Any] = {
        "schema": CONTEXT_PACKAGE_SCHEMA,
        "generated_at": generated_at,
        "viewer": {"principal": viewer, "role": viewer_role},
        "namespace": {"endpoint_ref": delivery["endpoint_ref"], "owner_ref": delivery["owner_ref"]},
        "business_task_ref": delivery["business_task_ref"],
        "task_revision": delivery["task_revision"],
        "delivery": {
            "delivery_id": delivery["delivery_id"],
            "payload_digest": delivery["payload_digest"],
            "schema": delivery["schema"],
            "state": delivery["state"],
            "fence": delivery["fence"],
            "created_at": delivery["created_at"],
        },
        "contract": {
            "contract_id": delivery["contract_id"],
            "contract_digest": delivery["contract_digest"],
            "workspace_id": delivery["workspace_id"],
        },
        "goal_acceptance": {
            "contract_ref": delivery["contract_id"],
            "contract_digest": delivery["contract_digest"],
            "business_acceptance": "NOT_DETERMINED_BY_UAM",
            "content": "BY_REFERENCE_ONLY",
        },
        "baseline": {
            "baseline_digest": delivery["data_scope"]["baseline_digest"],
            "paths_digest": delivery["data_scope"]["paths_digest"],
        },
        "artifacts": [] if result is None else [{
            "result_id": result["result_id"],
            "submission_digest": result["submission_digest"],
            "review_state": result["review_state"],
        }],
        "participants": {
            "requester": delivery["requester"],
            "recipient": delivery["recipient"],
            "origin_requester": delivery["origin_requester"],
            "origin_recipient": delivery["origin_recipient"],
            "handovers": [
                {key: item[key] for key in ("seq", "role", "from", "to", "initiator", "at", "binding_digest", "stop_at_handover")}
                for item in delivery["handovers"]
            ],
        },
        "continuation": {
            "coordination": delivery["requester"],
            "execution": delivery["recipient"],
            "continues": list(delivery["continues"]),
            "continuation_evidence_digest": delivery["continuation_evidence_digest"],
        },
        "effect": {
            "state": delivery["state"],
            "effect": effect,
            "consumption": {
                "attempts_used": len(delivery["attempts"]),
                "attempts_max": MAX_ATTEMPTS,
                "reset": "NEVER_BY_UAM",
            },
            "attempts": [
                {
                    "attempt_ref": attempt["attempt_ref"],
                    "fence": attempt["fence"],
                    "executor": attempt["executor"],
                    "end_how": attempt["end"]["how"] if attempt["end"] is not None else None,
                    "stop_evidence": attempt_stop_evidence(attempt),
                }
                for attempt in delivery["attempts"]
            ],
            "new_effect_permission": new_effect_permission(delivery),
        },
        "authorization": {
            "authority_ref": delivery["authority_ref"],
            "reference_transfers_authority": False,
            "dereference_requires": [EFFECT_DEREFERENCE],
        },
        "data_scope": {"scope_ref": delivery["data_scope"]["scope_ref"], **region_claim(delivery["data_scope"])},
        "limits": {
            "carries": "references and digests only",
            "excludes": ["secrets", "original_chat", "transferable_grants", "contract_text", "result_artifacts"],
        },
    }
    unsigned = {key: value for key, value in package.items() if key != "generated_at"}
    package["package_digest"] = canonical_digest(unsigned)
    return package
