"""Addressed contract delivery between two independent Harnesses (profile ``task-control``).

This is a bounded active-receiver integration, not a task system. It does not create business tasks,
a Run or Task ledger, an authorization table or a budget balance:

* the business task stays with its owner; a delivery only *correlates* ``business_task_ref`` and
  ``task_revision`` with a contract;
* permission comes from an ``AuthorityVerifier`` port that is asked before a delivery is made, before an
  attempt starts and when a result is submitted. The default denies everything, and a verifier that
  raises or answers anything but an explicit allow is a denial (the port bounds its own latency);
* what the work did to the workspace is read from UAM's own observation (``ResultV2Store``), never from
  what the receiver says about itself.

What it adds is what MCP alone does not provide and the Runner does not exist to provide yet: a durable,
addressed hand-off of one contract to one recipient, with one active attempt at a time (claim, lease and
fence), a payload-bound idempotency key, cancel intent that does not pretend to stop anything, and a
reconciliation step before any new attempt.

Planes that this module keeps apart, in every answer:

``state``
    where the delivery is: DELIVERED, ATTEMPT_ACTIVE, RECONCILIATION_REQUIRED, RESULT_RECORDED, CANCELLED.
``effect``
    what UAM observed of the workspace: NO_ATTEMPT_STARTED, NO_EFFECT_OBSERVED, PARTIAL_EFFECT_OBSERVED,
    EFFECT_UNKNOWN, EFFECT_RECORDED_IN_RESULT. ``NO_EFFECT_OBSERVED`` needs a UNCHANGED observation; an
    observation that cannot be made is ``EFFECT_UNKNOWN`` and blocks the next attempt.
``result.review``
    the machine review of a recorded result. ``business_acceptance`` is always ``NOT_DETERMINED_BY_UAM``.

Limits, stated once: a principal is a launch-time configuration of the server a client talks to, not an
authenticated identity (stdio has none); state is protected against torn writes and concurrent writers on
one host by a file lock and atomic replacement, not against another process running as the same user; a
lease bounds how long one attempt excludes another and is not a Grant.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from . import statefile
from .contracts import CONTRACT_V2, ContractBinding, ContractStore, canonical_digest
from .errors import ContractError, UAMError
from .results_v2 import BASELINE_CHANGED, BASELINE_UNCHANGED, ResultV2Store, describe_result_contract

DELIVERY_SCHEMA = "uam-task-control-delivery-v1"

STATE_DELIVERED = "DELIVERED"
STATE_ATTEMPT_ACTIVE = "ATTEMPT_ACTIVE"
STATE_RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
STATE_RESULT_RECORDED = "RESULT_RECORDED"
STATE_CANCELLED = "CANCELLED"
TERMINAL_STATES = frozenset({STATE_RESULT_RECORDED, STATE_CANCELLED})

EFFECT_NOT_STARTED = "NO_ATTEMPT_STARTED"
EFFECT_NONE_OBSERVED = "NO_EFFECT_OBSERVED"
EFFECT_PARTIAL = "PARTIAL_EFFECT_OBSERVED"
EFFECT_UNKNOWN = "EFFECT_UNKNOWN"
EFFECT_RECORDED = "EFFECT_RECORDED_IN_RESULT"

ATTEMPT_ACTIVE = "ACTIVE"
ATTEMPT_ENDED = "ENDED"
ATTEMPT_RESULT = "RESULT_RECORDED"

REPORTED_OUTCOMES = ("FAILED_BEFORE_EFFECT", "STOPPED", "FAILED")

DEFAULT_LEASE_SECONDS = 900
MIN_LEASE_SECONDS = 10
MAX_LEASE_SECONDS = 3_600
MAX_ATTEMPTS = 20
MAX_INBOX = 50
MAX_SCAN = 2_000

_PRINCIPAL = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_DELIVERY_ID = re.compile(r"^dlv-[0-9a-f]{24}$")
_ATTEMPT_REF = re.compile(r"^att-([0-9a-f]{24})\.([0-9]{1,6})$")
_RESULT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"  # the authority allowed, the allow could not be written to the audit log

EFFECT_DELIVER = "deliver"
EFFECT_ATTEMPT_START = "attempt_start"
EFFECT_RESULT_SUBMIT = "result_submit"


class TaskControlError(UAMError):
    """A refusal with a stable, machine-readable ``code``; the message never carries a host path."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --- the authority port ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRequest:
    """What the enforcement point asks the existing authority about: who, for which effect, on what.

    The first nine fields are the version-1 request and are all a v1 delivery ever sends. The rest are the
    version-2 binding used only by the successor contract (``task_continuity``): who hands what to whom, in
    which role and namespace, bound to which attempt and data scope, with a ``binding_digest`` that UAM
    computes and a verifier recomputes. For a v1 delivery every one of them keeps its default.
    """

    authority_ref: str
    principal: str
    effect: str
    delivery_id: str | None
    contract_id: str
    contract_digest: str
    workspace_id: str
    business_task_ref: str | None
    task_revision: int | None
    request_version: int = 1
    endpoint_ref: str | None = None
    owner_ref: str | None = None
    role: str | None = None
    initiator: str | None = None
    requester: str | None = None
    recipient: str | None = None
    from_principal: str | None = None
    to_principal: str | None = None
    handover_seq: int = 0
    attempt_ref: str | None = None
    fence: int | None = None
    original_executor: str | None = None
    late_after_attempt_end: str | None = None
    continues: tuple[str, ...] = ()
    data_scope: dict[str, Any] | None = None
    pending_evidence: tuple[dict[str, Any], ...] = ()
    binding_digest: str | None = None


@dataclass(frozen=True)
class AuthorityDecision:
    allowed: bool
    reason: str  # a stable code from the issuer, for example GRANTED, REVOKED, EXPIRED, REVISION_MISMATCH


class AuthorityVerifier(Protocol):
    """The existing issuer/delegation contract, asked at the enforcement point. UAM keeps no grants.

    A verifier that understands the version-2 binding declares a class attribute ``request_version = 2``.
    One that declares nothing is a version-1 verifier: it is never asked about a v2 delivery, which is
    refused as ``AUTHORITY_PORT_VERSION`` instead of being handed a request it cannot read.
    """

    def verify(self, request: AuthorityRequest) -> AuthorityDecision: ...


class DenyAllAuthority:
    """The default: no authority port is wired, so nothing is authorised."""

    request_version = 2  # it understands every request shape, and refuses all of them

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        return AuthorityDecision(False, "NO_AUTHORITY_PORT_CONFIGURED")


class AuditSink(Protocol):
    def append(
        self, *, action: str, workspace_id: str | None, outcome: str, details: dict[str, Any] | None = None,
    ) -> Any: ...


# --- argument validation --------------------------------------------------------------------------


def validate_principal(value: Any, name: str = "principal") -> str:
    """A principal name, or ``TaskControlError``. A principal is a configured label, not an authenticated identity."""
    if not isinstance(value, str) or not _PRINCIPAL.fullmatch(value):
        raise TaskControlError("INVALID_ARGUMENT", f"{name} must match {_PRINCIPAL.pattern}")
    return value


def _text(value: Any, name: str, *, limit: int, required: bool = True) -> str:
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > limit:
        raise TaskControlError("INVALID_ARGUMENT", f"{name} must be a string of at most {limit} characters")
    return value


def _task_binding(task_ref: Any, revision: Any) -> tuple[str | None, int | None]:
    if task_ref is None:
        if revision is not None:
            raise TaskControlError("INVALID_ARGUMENT", "task_revision requires a business_task_ref")
        return None, None
    ref = _text(task_ref, "business_task_ref", limit=200)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise TaskControlError("INVALID_ARGUMENT", "task_revision must be a non-negative integer")
    return ref, revision


def _delivery_id(value: Any) -> str:
    if not isinstance(value, str) or not _DELIVERY_ID.fullmatch(value):
        raise TaskControlError("INVALID_ARGUMENT", "invalid delivery_id")
    return value


def _attempt_ref(value: Any) -> str:
    if not isinstance(value, str) or not _ATTEMPT_REF.fullmatch(value):
        raise TaskControlError("INVALID_ARGUMENT", "invalid attempt_ref")
    return value


def _fence(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise TaskControlError("INVALID_ARGUMENT", "fence must be a positive integer")
    return value


def _lease(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not MIN_LEASE_SECONDS <= value <= MAX_LEASE_SECONDS:
        raise TaskControlError(
            "INVALID_ARGUMENT", f"lease_seconds must be an integer from {MIN_LEASE_SECONDS} to {MAX_LEASE_SECONDS}"
        )
    return value


def _summary(observation: dict[str, Any]) -> dict[str, Any]:
    """The part of a baseline observation that is kept as evidence: bounded, with no content and no paths of the host."""
    return {
        "state": observation["state"],
        "observed_at": observation.get("observed_at"),
        "changed": list(observation.get("changed", []))[:20],
        "unknown": list(observation.get("unknown", []))[:20],
        "limits": list(observation.get("limits", [])),
        "reason": observation.get("reason"),
    }


def _effect_of(observation: dict[str, Any]) -> str:
    if observation["state"] == BASELINE_UNCHANGED:
        return EFFECT_NONE_OBSERVED
    if observation["state"] == BASELINE_CHANGED:
        return EFFECT_PARTIAL
    return EFFECT_UNKNOWN


class TaskControl:
    """Durable delivery, attempt and cancel state for one contract at a time, under UAM's own observation."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        contracts: ContractStore,
        results: ResultV2Store,
        authority: AuthorityVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        audit: AuditSink | None = None,
    ):
        self.root = Path(state_dir) / "task-control"
        self._deliveries = self.root / "deliveries"
        self._by_contract = self.root / "by-contract"
        self._lock = self.root / "lock"
        self._deliveries.mkdir(parents=True, exist_ok=True)
        self._by_contract.mkdir(parents=True, exist_ok=True)
        self.contracts = contracts
        self.results = results
        self._authority: AuthorityVerifier = authority if authority is not None else DenyAllAuthority()
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        self._audit = audit

    # -- requester ----------------------------------------------------------------------------

    def deliver(
        self,
        principal: str,
        *,
        contract_id: str,
        contract_digest: str,
        recipient: str,
        authority_ref: str,
        idempotency_key: str,
        business_task_ref: str | None = None,
        task_revision: int | None = None,
    ) -> dict[str, Any]:
        """Address one contract to one recipient. The same key and payload is the same delivery, never a second one."""
        principal = validate_principal(principal, "principal")
        recipient = validate_principal(recipient, "recipient")
        if recipient == principal:
            raise TaskControlError("INVALID_ARGUMENT", "recipient must differ from the requesting principal")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise TaskControlError("INVALID_ARGUMENT", f"idempotency_key must match {_IDEMPOTENCY_KEY.pattern}")
        authority_ref = _text(authority_ref, "authority_ref", limit=300)
        task_ref, revision = _task_binding(business_task_ref, task_revision)
        binding = self._deliverable(contract_id, contract_digest)
        payload_digest = canonical_digest({
            "contract_id": contract_id,
            "contract_digest": binding.digest,
            "requester": principal,
            "recipient": recipient,
            "business_task_ref": task_ref,
            "task_revision": revision,
            "authority_ref": authority_ref,
        })
        delivery_id = "dlv-" + hashlib.sha256(f"{principal}\0{idempotency_key}".encode("utf-8")).hexdigest()[:24]
        existing = self._read_optional(delivery_id)
        if existing is not None:
            return self._replay(existing, payload_digest, principal)
        self._authorize(
            EFFECT_DELIVER, principal, authority_ref, delivery_id, binding, task_ref, revision,
        )
        with statefile.exclusive_lock(self._lock):
            existing = self._read_optional(delivery_id)
            if existing is not None:
                return self._replay(existing, payload_digest, principal)
            self._claim_contract(contract_id, delivery_id)
            now = self._now()
            delivery: dict[str, Any] = {
                "schema": DELIVERY_SCHEMA,
                "delivery_id": delivery_id,
                "payload_digest": payload_digest,
                "contract_id": contract_id,
                "contract_digest": binding.digest,
                "workspace_id": binding.workspace_id,
                "requester": principal,
                "recipient": recipient,
                "business_task_ref": task_ref,
                "task_revision": revision,
                "authority_ref": authority_ref,
                "created_at": _iso(now),
                "state": STATE_DELIVERED,
                "fence": 0,
                "attempts": [],
                "cancel": None,
                "result": None,
                "events": [],
            }
            self._event(delivery, now, "DELIVERED", principal)
            statefile.write_new(self._path(delivery_id), _dump(delivery))
        self._record("deliver", delivery, "PASS", principal)
        return {**self._view(delivery, principal), "replayed": False}

    def cancel(self, principal: str, *, delivery_id: str, reason: str = "") -> dict[str, Any]:
        """Record the intent to stop. It blocks every later claim; it neither stops a running attempt nor undoes an effect.

        Only the requester may cancel. A result that was recorded first is kept and the cancel answers
        ``TOO_LATE_RESULT_RECORDED``; a result that arrives after the intent is kept and flagged. In both
        orders the committed effects and the owner's decision are preserved.
        """
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        reason = _text(reason, "reason", limit=500, required=False)
        with statefile.exclusive_lock(self._lock):
            delivery = self._load_for(principal, delivery_id, role="requester")
            now = self._now()
            if delivery["state"] == STATE_RESULT_RECORDED:
                outcome = "TOO_LATE_RESULT_RECORDED"
            elif delivery["cancel"] is not None:
                outcome = "CANCEL_ALREADY_RECORDED"
                if self._close_expired_attempt(delivery, now):
                    self._save(delivery)
            else:
                delivery["cancel"] = {"requested_by": principal, "requested_at": _iso(now), "reason": reason}
                self._event(delivery, now, "CANCEL_INTENT", principal)
                if delivery["state"] == STATE_ATTEMPT_ACTIVE:
                    self._close_expired_attempt(delivery, now)
                if delivery["state"] == STATE_ATTEMPT_ACTIVE:
                    outcome = "CANCEL_INTENT_RECORDED_ATTEMPT_ACTIVE"
                else:
                    if not delivery["attempts"]:
                        delivery["cancel"]["effect_evidence"] = _summary(self._observe(delivery))
                    delivery["state"] = STATE_CANCELLED
                    outcome = "CANCELLED"
                self._save(delivery)
        self._record("cancel", delivery, outcome, principal)
        return {
            "outcome": outcome,
            "delivery": self._view(delivery, principal),
            # Three different facts that an acknowledgement must never be mistaken for:
            "intent": "RECORDED" if delivery["cancel"] is not None else "NOT_RECORDED",
            "stop": self._stop_of(delivery),
            "rollback": "NOT_PERFORMED_BY_UAM",
        }

    # -- recipient ----------------------------------------------------------------------------

    def inbox(self, principal: str, *, limit: int = 20) -> dict[str, Any]:
        """The open deliveries addressed to the principal. Reading it claims nothing and writes nothing."""
        principal = validate_principal(principal, "principal")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_INBOX:
            raise TaskControlError("INVALID_ARGUMENT", f"limit must be an integer from 1 to {MAX_INBOX}")
        items: list[dict[str, Any]] = []
        scanned = 0
        truncated = False
        for path in self._delivery_paths():
            scanned += 1
            if scanned > MAX_SCAN:
                truncated = True
                break
            delivery = self._load_path(path)
            if delivery["recipient"] == principal and delivery["state"] not in TERMINAL_STATES:
                items.append(self._summary_view(delivery))
        items.sort(key=lambda item: (item["created_at"], item["delivery_id"]))
        if len(items) > limit:
            truncated = True
        return {"items": items[:limit], "truncated": truncated, "claims_nothing": True}

    def start_attempt(
        self, principal: str, *, delivery_id: str, lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> dict[str, Any]:
        """Claim the delivery for one attempt: one at a time, fenced, leased, and only from an unchanged baseline."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        lease = _lease(lease_seconds)
        with statefile.exclusive_lock(self._lock):
            delivery = self._load_for(principal, delivery_id, role="recipient")
            now = self._now()
            self._require_open(delivery)
            if self._close_expired_attempt(delivery, now):
                self._save(delivery)
            if delivery["state"] == STATE_ATTEMPT_ACTIVE:
                raise TaskControlError(
                    "ATTEMPT_ACTIVE",
                    "an attempt is active; read it with uam_delivery_get, or wait for its lease to end",
                )
            if len(delivery["attempts"]) >= MAX_ATTEMPTS:
                raise TaskControlError("ATTEMPT_LIMIT", "this delivery has used every attempt it may have")
            self._attempt_gate(delivery)
            binding = self._bound_contract(delivery)
            observation = self._observe(delivery)
            if observation["state"] != BASELINE_UNCHANGED:
                code = "BASELINE_CHANGED" if observation["state"] == BASELINE_CHANGED else "BASELINE_UNOBSERVABLE"
                raise TaskControlError(
                    code,
                    "the workspace is not observed to match the contract baseline, so no attempt may start; "
                    "an earlier effect has to be reconciled by the owner",
                )
            self._authorize_attempt(delivery, principal, binding)
            if delivery["state"] == STATE_RECONCILIATION_REQUIRED:
                self._event(delivery, now, "RECONCILED_NO_EFFECT", principal)
            fence = delivery["fence"] + 1
            attempt = {
                "attempt_ref": f"att-{delivery_id[4:]}.{fence}",
                "fence": fence,
                "state": ATTEMPT_ACTIVE,
                "started_at": _iso(now),
                "lease_expires_at": _iso(now + timedelta(seconds=lease)),
                "baseline_at_start": _summary(observation),
                "end": None,
                "result_id": None,
            }
            self._stamp_attempt(delivery, attempt, principal)
            delivery["attempts"].append(attempt)
            delivery["fence"] = fence
            delivery["state"] = STATE_ATTEMPT_ACTIVE
            self._event(delivery, now, "ATTEMPT_STARTED", principal, attempt_ref=attempt["attempt_ref"], fence=fence)
            self._save(delivery)
        self._record("start_attempt", delivery, "PASS", principal)
        return self._view(delivery, principal)

    def submit_result(
        self, principal: str, *, delivery_id: str, attempt_ref: str, fence: int, result: dict[str, Any],
    ) -> dict[str, Any]:
        """Hand the attempt's ``uam-result-v2`` to UAM: bound to this delivery, observed live, reviewed.

        Re-sending the very same result after a lost acknowledgement returns the recorded outcome and
        does nothing else. A different result for a delivery that already has one is refused.
        """
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        attempt_ref = _attempt_ref(attempt_ref)
        fence = _fence(fence)
        if not isinstance(result, dict):
            raise TaskControlError("INVALID_ARGUMENT", "result must be an object")
        try:
            digest = self.results.submission_digest(result)
        except ContractError as exc:
            raise TaskControlError("RESULT_INVALID", str(exc)) from exc
        with statefile.exclusive_lock(self._lock):
            delivery = self._load_for(principal, delivery_id, role="recipient")
            now = self._now()
            if delivery["state"] == STATE_RESULT_RECORDED:
                recorded = delivery["result"]
                if recorded["submission_digest"] != digest:
                    raise TaskControlError("RESULT_ALREADY_RECORDED", "this delivery already has a different result")
                return self._answer_result(delivery, principal, replayed=True)
            attempt = self._active_attempt(delivery, attempt_ref, fence)
            self._require_result_binding(delivery, attempt, principal, result)
            binding = self._bound_contract(delivery)
            self._authorize(
                EFFECT_RESULT_SUBMIT, principal, delivery["authority_ref"], delivery_id, binding,
                delivery["business_task_ref"], delivery["task_revision"],
            )
            stored = self._stored_result(result["result_id"])
            if stored is None:
                try:
                    stored = self.results.put(result)
                except ContractError as exc:
                    raise TaskControlError("RESULT_INVALID", str(exc)) from exc
            elif stored["submission_digest"] != digest:
                raise TaskControlError("RESULT_ID_CONFLICT", "result_id already holds a different result")
            # else: stored by an earlier call that was cut off before this delivery was updated.
            review = stored["review"]
            after_cancel = delivery["cancel"] is not None
            attempt["state"] = ATTEMPT_RESULT
            attempt["result_id"] = result["result_id"]
            attempt["end"] = {"how": "RESULT", "ended_at": _iso(now)}
            delivery["state"] = STATE_RESULT_RECORDED
            delivery["result"] = {
                "result_id": result["result_id"],
                "attempt_ref": attempt_ref,
                "fence": fence,
                "submitted_by": principal,
                "recorded_at": _iso(now),
                "submission_digest": digest,
                "review_state": review["state"],
                "review_blockers": review["blockers"],
                "after_cancel_request": after_cancel,
            }
            self._event(
                delivery, now, "RESULT_RECORDED", principal, result_id=result["result_id"],
                review=review["state"], after_cancel_request=after_cancel,
            )
            self._save(delivery)
        self._record("submit_result", delivery, review["state"], principal)
        return self._answer_result(delivery, principal, replayed=False)

    def end_attempt(
        self, principal: str, *, delivery_id: str, attempt_ref: str, fence: int, outcome: str, note: str = "",
    ) -> dict[str, Any]:
        """Close an attempt that produced no result. The report is self-reported; the effect is what UAM observes."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        attempt_ref = _attempt_ref(attempt_ref)
        fence = _fence(fence)
        if outcome not in REPORTED_OUTCOMES:
            raise TaskControlError("INVALID_ARGUMENT", f"outcome must be one of {', '.join(REPORTED_OUTCOMES)}")
        note = _text(note, "note", limit=500, required=False)
        with statefile.exclusive_lock(self._lock):
            delivery = self._load_for(principal, delivery_id, role="recipient")
            attempt = self._active_attempt(delivery, attempt_ref, fence)
            self._close_attempt(delivery, attempt, self._now(), how="REPORTED", reported=outcome, note=note)
            self._save(delivery)
        self._record("end_attempt", delivery, attempt["end"]["effect"], principal)
        return self._view(delivery, principal)

    # -- both parties -------------------------------------------------------------------------

    def get(self, principal: str, *, delivery_id: str, observe: bool = False) -> dict[str, Any]:
        """The delivery as its requester or recipient sees it. Pure read: it claims nothing and changes no state."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        delivery = self._load_for(principal, delivery_id, role="participant")
        view = self._view(delivery, principal)
        try:
            view["contract"] = self.contracts.get_record(delivery["contract_id"])
        except ContractError:
            view["contract"] = None
        result_contract = self._result_contract_for(delivery, principal)
        if result_contract is not None:
            view["result_contract"] = result_contract
        if delivery["result"] is not None:
            try:
                view["result_record"] = self.results.get(delivery["result"]["result_id"])
            except ContractError:
                view["result_record"] = None
        if observe:
            view["baseline_observation"] = _summary(self._observe(delivery))
        return view

    def _result_contract_for(self, delivery: dict[str, Any], viewer: str) -> dict[str, Any] | None:
        """What the recipient has to submit for this delivery's contract (``describe_result_contract``), read from the same
        rules the submission is validated by. Only the recipient gets it, because only the recipient submits; a contract that
        cannot be read gives none, and nothing here changes what ``submit_result`` accepts."""
        if viewer != delivery["recipient"]:
            return None
        try:
            binding = self.contracts.binding(delivery["contract_id"])
        except ContractError:
            return None
        active = _active(delivery)
        return describe_result_contract(
            binding, business_task_ref=delivery["business_task_ref"], task_revision=delivery["task_revision"], executor=viewer,
            attempt_ref=active["attempt_ref"] if active else None,
            result_id=f"res-{delivery['delivery_id'][4:]}-{active['fence']}" if active else None,
        )

    # -- internals ----------------------------------------------------------------------------

    def _now(self) -> datetime:
        moment = self._clock()
        if moment.tzinfo is None:
            raise TaskControlError("INTERNAL", "the clock must return an aware datetime")
        return moment.astimezone(timezone.utc)

    def _path(self, delivery_id: str) -> Path:
        return self._deliveries / f"{delivery_id}.json"

    def _read_optional(self, delivery_id: str) -> dict[str, Any] | None:
        path = self._path(delivery_id)
        return self._load_path(path) if path.exists() else None

    def _read_required(self, delivery_id: str) -> dict[str, Any]:
        delivery = self._read_optional(delivery_id)
        if delivery is None:
            raise TaskControlError("NOT_FOUND", "delivery not found")
        return delivery

    @staticmethod
    def _load_path(path: Path) -> dict[str, Any]:
        delivery = json.loads(path.read_text(encoding="utf-8"))
        if delivery.get("schema") != DELIVERY_SCHEMA:
            raise TaskControlError("INTERNAL", "unsupported delivery record")
        return delivery

    def _save(self, delivery: dict[str, Any]) -> None:
        statefile.replace(self._path(delivery["delivery_id"]), _dump(delivery))

    def _load_for(self, principal: str, delivery_id: str, *, role: str) -> dict[str, Any]:
        delivery = self._read_required(delivery_id)
        parties = {"requester": delivery["requester"], "recipient": delivery["recipient"]}
        if principal not in parties.values():
            raise TaskControlError("NOT_FOUND", "delivery not found")  # no oracle for deliveries of others
        if role != "participant" and parties[role] != principal:
            raise TaskControlError("WRONG_ROLE", f"only the {role} of a delivery may do this")
        return delivery

    def _deliverable(self, contract_id: Any, contract_digest: Any) -> ContractBinding:
        if not isinstance(contract_id, str) or not isinstance(contract_digest, str):
            raise TaskControlError("INVALID_ARGUMENT", "contract_id and contract_digest are strings")
        try:
            binding = self.contracts.binding(contract_id)
        except ContractError as exc:
            raise TaskControlError("CONTRACT_MISSING", str(exc)) from exc
        if binding.contract_version != CONTRACT_V2:
            raise TaskControlError(
                "CONTRACT_NOT_DELIVERABLE", f"only {CONTRACT_V2} contracts are delivered by this profile",
            )
        if binding.digest != contract_digest:
            raise TaskControlError("CONTRACT_MISMATCH", "contract_digest is not the digest of the stored contract")
        if binding.readiness_state != "READY":
            raise TaskControlError(
                "CONTRACT_NOT_READY", f"the contract is on hold: {', '.join(binding.readiness_blockers)}",
            )
        return binding

    def _bound_contract(self, delivery: dict[str, Any]) -> ContractBinding:
        return self._deliverable(delivery["contract_id"], delivery["contract_digest"])

    def _authorize(
        self, effect: str, principal: str, authority_ref: str, delivery_id: str | None, binding: ContractBinding,
        task_ref: str | None, revision: int | None,
    ) -> None:
        self._decide(AuthorityRequest(
            authority_ref=authority_ref, principal=principal, effect=effect, delivery_id=delivery_id,
            contract_id=binding.contract_id, contract_digest=binding.digest, workspace_id=binding.workspace_id,
            business_task_ref=task_ref, task_revision=revision,
        ))

    def _decide(self, request: AuthorityRequest) -> None:
        """Refuse unless the authority explicitly allows ``request``; a refusal is audited, and so is an allow."""
        refusal = self._verdict(request)
        if refusal is None:
            return
        reason, errored = refusal
        if errored and reason == _AUDIT_UNAVAILABLE:
            raise TaskControlError("AUTHORITY_DENIED", "the allow could not be audited, so the effect was refused")
        if errored:
            raise TaskControlError("AUTHORITY_DENIED", "the authority could not be verified")
        raise TaskControlError("AUTHORITY_DENIED", f"the authority does not cover this effect ({reason})")

    def _verdict(self, request: AuthorityRequest) -> tuple[str, bool] | None:
        """``None`` when the authority explicitly allowed ``request``, else ``(reason, verifier_errored)``; a denial is audited.

        An allow is audited too, here and before the caller does anything, so every effect that happens has its
        authorisation on the chain. If that record cannot be written the effect is refused (``AUDIT_UNAVAILABLE``).
        A version-2 request is only put to a verifier that declares ``request_version`` of at least 2.
        """
        if request.request_version > 1:
            supported = getattr(self._authority, "request_version", 1)
            if not isinstance(supported, int) or isinstance(supported, bool) or supported < request.request_version:
                self._record_denial(request, "AUTHORITY_PORT_VERSION")
                return "AUTHORITY_PORT_VERSION", False
        try:
            decision = self._authority.verify(request)
        except Exception:  # a verifier that cannot answer has not allowed anything
            self._record_denial(request, "VERIFIER_ERROR")
            return "VERIFIER_ERROR", True
        if not isinstance(decision, AuthorityDecision) or decision.allowed is not True:
            reason = decision.reason if isinstance(decision, AuthorityDecision) else "INVALID_DECISION"
            self._record_denial(request, reason)
            return reason, False
        if not self._record_allow(request, decision.reason):
            try:
                self._record_denial(request, _AUDIT_UNAVAILABLE)
            except Exception:  # the log that just failed may still be failing; the effect is refused either way
                pass
            return _AUDIT_UNAVAILABLE, True
        return None

    def _stored_result(self, result_id: str) -> dict[str, Any] | None:
        try:
            return self.results.get(result_id)
        except ContractError:
            return None

    def _claim_contract(self, contract_id: str, delivery_id: str) -> None:
        """One delivery per contract: the first claim wins, a repeat of the same delivery is accepted."""
        path = self._by_contract / contract_id
        try:
            statefile.write_new(path, delivery_id + "\n")
        except FileExistsError:
            if path.read_text(encoding="utf-8").strip() != delivery_id:
                raise TaskControlError(
                    "CONTRACT_ALREADY_DELIVERED", "this contract was already delivered under another idempotency key",
                ) from None

    def _replay(self, delivery: dict[str, Any], payload_digest: str, principal: str) -> dict[str, Any]:
        if delivery["payload_digest"] != payload_digest:
            raise TaskControlError(
                "IDEMPOTENCY_CONFLICT", "this idempotency key was used for a different delivery payload",
            )
        return {**self._view(delivery, principal), "replayed": True}

    def _observe(self, delivery: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.results.observe_baseline(delivery["contract_id"])
        except ContractError:
            return {"state": "UNOBSERVABLE", "reason": "contract_missing"}

    def _require_open(self, delivery: dict[str, Any]) -> None:
        if delivery["state"] == STATE_RESULT_RECORDED:
            raise TaskControlError("RESULT_ALREADY_RECORDED", "this delivery already has a recorded result")
        if delivery["cancel"] is not None or delivery["state"] == STATE_CANCELLED:
            raise TaskControlError("CANCELLED", "the requester cancelled this delivery")

    def _active_attempt(self, delivery: dict[str, Any], attempt_ref: str, fence: int) -> dict[str, Any]:
        attempts = delivery["attempts"]
        attempt = next((item for item in attempts if item["attempt_ref"] == attempt_ref), None)
        if attempt is None:
            raise TaskControlError("NOT_FOUND", "attempt not found")
        if attempt["fence"] != fence or delivery["fence"] != fence:
            raise TaskControlError("FENCE_MISMATCH", "this attempt was superseded by a later one")
        if attempt["state"] != ATTEMPT_ACTIVE:
            raise TaskControlError("ATTEMPT_NOT_ACTIVE", "this attempt has already ended")
        return attempt

    def _require_result_binding(
        self, delivery: dict[str, Any], attempt: dict[str, Any], principal: str, result: dict[str, Any],
    ) -> None:
        expected = {
            "contract_id": delivery["contract_id"],
            "contract_digest": delivery["contract_digest"],
            "workspace_instance": delivery["workspace_id"],
            "business_task_ref": delivery["business_task_ref"],
            "task_revision": delivery["task_revision"],
            "attempt_ref": attempt["attempt_ref"],
            "executor": principal,
        }
        wrong = sorted(name for name, value in expected.items() if result.get(name) != value)
        if wrong:
            raise TaskControlError(
                "RESULT_BINDING_MISMATCH",
                f"the result does not belong to this delivery and attempt: {', '.join(wrong)}",
            )

    def _close_expired_attempt(self, delivery: dict[str, Any], now: datetime) -> bool:
        """End an attempt whose lease ran out. The lease only ever frees the delivery; it proves nothing about effects."""
        attempt = _active(delivery)
        if attempt is None or datetime.fromisoformat(attempt["lease_expires_at"]) > now:
            return False
        self._close_attempt(delivery, attempt, now, how="LEASE_EXPIRED")
        return True

    def _close_attempt(
        self, delivery: dict[str, Any], attempt: dict[str, Any], now: datetime, *,
        how: str, reported: str | None = None, note: str = "",
    ) -> None:
        observation = self._observe(delivery)
        effect = _effect_of(observation)
        attempt["state"] = ATTEMPT_ENDED
        attempt["end"] = {
            "how": how,
            "reported_outcome": reported,
            "note": note,
            "effect": effect,
            "observation": _summary(observation),
            "ended_at": _iso(now),
        }
        if delivery["cancel"] is not None:
            delivery["state"] = STATE_CANCELLED
        elif effect == EFFECT_NONE_OBSERVED:
            delivery["state"] = STATE_DELIVERED
        else:
            delivery["state"] = STATE_RECONCILIATION_REQUIRED
        self._event(
            delivery, now, "ATTEMPT_ENDED", self._closer_of(delivery, attempt, how),
            attempt_ref=attempt["attempt_ref"], how=how, reported_outcome=reported, effect=effect,
        )

    # -- extension points of the successor contract (task_continuity). A plain TaskControl keeps every default.

    def _delivery_paths(self) -> list[Path]:
        return sorted(self._deliveries.glob("dlv-*.json"))

    def _stop_of(self, delivery: dict[str, Any]) -> str:
        return _stop_evidence(delivery)

    def _attempt_gate(self, delivery: dict[str, Any]) -> None:
        """Called before an attempt may be offered; a subclass refuses by raising."""

    def _stamp_attempt(self, delivery: dict[str, Any], attempt: dict[str, Any], principal: str) -> None:
        """Called on a new attempt record before it is stored."""

    def _authorize_attempt(self, delivery: dict[str, Any], principal: str, binding: ContractBinding) -> None:
        self._authorize(
            EFFECT_ATTEMPT_START, principal, delivery["authority_ref"], delivery["delivery_id"], binding,
            delivery["business_task_ref"], delivery["task_revision"],
        )

    def _closer_of(self, delivery: dict[str, Any], attempt: dict[str, Any], how: str) -> str:
        """Who the ``ATTEMPT_ENDED`` event names: the receiver for its own report, UAM for everything else."""
        return delivery["recipient"] if how == "REPORTED" else "uam"

    @staticmethod
    def _event(delivery: dict[str, Any], now: datetime, kind: str, principal: str, **details: Any) -> None:
        delivery["events"].append({"at": _iso(now), "type": kind, "principal": principal, **details})

    def _record_denial(self, request: AuthorityRequest, reason: Any) -> None:
        """A blocked effect leaves evidence too. The verifier's reason is kept only when it is a code, never as free text."""
        if self._audit is None:
            return
        code = reason if isinstance(reason, str) and _REASON_CODE.fullmatch(reason) else "UNSPECIFIED"
        self._audit.append(
            action=f"task_control.{request.effect}",
            workspace_id=request.workspace_id,
            outcome="DENY",
            details={
                "delivery_id": request.delivery_id,
                "contract_id": request.contract_id,
                "principal": request.principal,
                "reason": code,
            },
        )

    def _record_allow(self, request: AuthorityRequest, reason: Any) -> bool:
        """Put an allow on the chain before the effect; ``False`` when it could not be written (the caller refuses).

        What is kept: the effect, who asked and in which role, the task and revision, the contract, the attempt and
        the ``binding_digest`` the verifier recomputed, plus the verifier's reason when it is a code. Never the
        ``authority_ref``, never content, never the verifier's free text. The action is ``task_authority.<effect>``
        so that the ``task_control.*`` records (``PASS`` after an effect, ``DENY``) keep their names and counts.
        With no audit sink wired nothing is recorded (as for every other record of this class).
        """
        if self._audit is None:
            return True
        fields = {
            "effect": request.effect, "request_version": request.request_version, "principal": request.principal,
            "role": request.role, "requester": request.requester, "recipient": request.recipient,
            "from_principal": request.from_principal, "to_principal": request.to_principal,
            "delivery_id": request.delivery_id, "contract_id": request.contract_id,
            "contract_digest": request.contract_digest, "business_task_ref": request.business_task_ref,
            "task_revision": request.task_revision, "endpoint_ref": request.endpoint_ref, "owner_ref": request.owner_ref,
            "attempt_ref": request.attempt_ref, "fence": request.fence, "binding_digest": request.binding_digest,
            "reason": reason if isinstance(reason, str) and _REASON_CODE.fullmatch(reason) else "UNSPECIFIED",
        }
        try:
            self._audit.append(
                action=f"task_authority.{request.effect}",
                workspace_id=request.workspace_id,
                outcome="ALLOW",
                details={key: value for key, value in fields.items() if value is not None},
            )
        except Exception:  # an allow that cannot be written down is not acted on
            return False
        return True

    def _record(self, action: str, delivery: dict[str, Any], outcome: str, principal: str) -> None:
        if self._audit is None:
            return
        self._audit.append(
            action=f"task_control.{action}",
            workspace_id=delivery["workspace_id"],
            outcome=outcome,
            details={
                "delivery_id": delivery["delivery_id"],
                "contract_id": delivery["contract_id"],
                "principal": principal,
                "state": delivery["state"],
            },
        )

    def _effect_of_delivery(self, delivery: dict[str, Any]) -> str:
        if delivery["result"] is not None:
            return EFFECT_RECORDED
        if not delivery["attempts"]:
            return EFFECT_NOT_STARTED
        last = delivery["attempts"][-1]
        if last["state"] == ATTEMPT_ACTIVE:
            return EFFECT_UNKNOWN
        return last["end"]["effect"]

    def _summary_view(self, delivery: dict[str, Any]) -> dict[str, Any]:
        return {
            "delivery_id": delivery["delivery_id"],
            "state": delivery["state"],
            "contract_id": delivery["contract_id"],
            "contract_digest": delivery["contract_digest"],
            "requester": delivery["requester"],
            "business_task_ref": delivery["business_task_ref"],
            "task_revision": delivery["task_revision"],
            "created_at": delivery["created_at"],
            "cancel_requested": delivery["cancel"] is not None,
        }

    def _view(self, delivery: dict[str, Any], viewer: str) -> dict[str, Any]:
        now = self._now()
        attempts = []
        for attempt in delivery["attempts"]:
            item = {key: attempt[key] for key in (
                "attempt_ref", "fence", "state", "started_at", "lease_expires_at", "end", "result_id",
            )}
            item["lease_expired"] = (
                attempt["state"] == ATTEMPT_ACTIVE and datetime.fromisoformat(attempt["lease_expires_at"]) <= now
            )
            attempts.append(item)
        return {
            **self._summary_view(delivery),
            "viewer_role": "requester" if viewer == delivery["requester"] else "recipient",
            "recipient": delivery["recipient"],
            "workspace_id": delivery["workspace_id"],
            "authority_ref": delivery["authority_ref"],
            "fence": delivery["fence"],
            "attempts": attempts,
            "cancel": delivery["cancel"],
            "effect": self._effect_of_delivery(delivery),
            "result": delivery["result"],
            "events": delivery["events"],
            "business_acceptance": "NOT_DETERMINED_BY_UAM",
        }

    def _answer_result(self, delivery: dict[str, Any], principal: str, *, replayed: bool) -> dict[str, Any]:
        recorded = delivery["result"]
        return {
            "delivery": self._view(delivery, principal),
            "result_record": self.results.get(recorded["result_id"]),
            "replayed": replayed,
        }


def _stop_evidence(delivery: dict[str, Any]) -> str:
    """Whether anything confirms that work stopped. Cancel intent and a closed lease are not confirmation."""
    if delivery["result"] is not None:
        return "NOT_APPLICABLE_RESULT_RECORDED"
    if not delivery["attempts"]:
        return "NOT_APPLICABLE_NO_ATTEMPT"
    last = delivery["attempts"][-1]
    if last["state"] == ATTEMPT_ACTIVE:
        return "ATTEMPT_ACTIVE_NOT_CONFIRMED"
    return "CONFIRMED_BY_RECEIVER" if last["end"]["how"] == "REPORTED" else "NOT_CONFIRMED_LEASE_EXPIRED"


def _active(delivery: dict[str, Any]) -> dict[str, Any] | None:
    attempt = delivery["attempts"][-1] if delivery["attempts"] else None
    return attempt if attempt is not None and attempt["state"] == ATTEMPT_ACTIVE else None


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _dump(delivery: dict[str, Any]) -> str:
    return json.dumps(delivery, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
