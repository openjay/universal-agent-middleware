"""``ContinuityControl``: ``TaskControl`` plus the successor contract (candidate, not deployed).

A plain ``TaskControl`` keeps its version-1 behaviour and never reads or writes anything below. A
``ContinuityControl`` is a different class a host has to construct on purpose; it additionally keeps
version-2 deliveries (``uam-task-control-delivery-v2``) in their own directory, so a process that only
knows version 1 neither lists nor trips over them. Everything v1 does stays as it was for v1 deliveries.

What the successor adds, and what it still does not do:

* every authority question about a v2 delivery is a **version-2 request**: who hands what to whom, in which
  role and namespace, bound to which attempt, fence and data scope, with a ``binding_digest`` UAM computes
  and a verifier recomputes. A verifier that does not declare ``request_version >= 2`` is never asked and
  the effect is refused (``AUTHORITY_PORT_VERSION``). Default deny stays.
* an attempt records its **real executor**. Only that executor can submit its result or report that it
  stopped, also after a handover or a lease expiry (a *late* receipt or stop report). A successor cannot
  sign the former executor's work, and a former executor sees nothing but its own attempt.
* **late evidence is ingested deterministically**: whether the lease ran out, a handover closed the attempt,
  or someone read the delivery first changes how the evidence is labelled, never the outcome. Ingestion,
  UAM's independent read-back, business acceptance and permission for a new effect are four separate
  facts. A closed lease, a handover closure or a baseline that has not changed yet do **not** prove that
  the executor stopped; with an unconfirmed attempt in flight no new attempt may start for anybody.
* a **new contract for the same business task** inside one namespace (``endpoint_ref`` + ``owner_ref``)
  must name every earlier delivery whose effect is still open (``continues``); the evidence is handed to
  the authority port, and UAM does not become the task's state source.
* **one active attempt per task identity** (``endpoint_ref`` + ``owner_ref`` + ``business_task_ref``): the
  deliveries of one task may be created side by side, but ``start_attempt`` refuses a second start while a
  sibling's attempt is active, whether or not its lease ran out, and while a sibling that this delivery does not
  ``continue`` has an effect that is not settled. The check runs in the same critical section as the start
  gate, the authority question and the save, over the existing delivery index (bounded, fail-closed). It
  orders *records*; it does not stop an executor.
* the **legacy version-1 entry is closed by default**: a version-1 delivery has no namespace, so the
  guarantees above cannot cover it. ``legacy_deliver=True`` is an explicit, bounded legacy entry (creating and
  starting version-1 deliveries) that carries none of those guarantees; reading and finishing version-1
  records stay possible either way.
* a minimal **Context Package** (references and digests only) lets a successor locate all of that. Receiving
  it (``context_receive``) and reading content (``dereference``) are separately authorised.

Not done here, and never claimed: authenticating a principal or an owner, verifying a region, fencing an
effect (there is no Runner/PEP; ``effect_fencing`` stays ``NOT_PROVIDED``), a task ledger, a consensus step.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from . import statefile
from .contracts import ContractBinding, ContractStore, canonical_digest
from .errors import ContractError
from .results_v2 import ResultV2Store
from .task_continuity import (
    DELIVERY_SCHEMA_V2,
    EFFECT_CONTEXT_RECEIVE,
    EFFECT_CONTINUE_TASK,
    EFFECT_DEREFERENCE,
    EFFECT_HANDOVER,
    END_HANDED_OVER,
    MAX_HANDOVERS,
    ROLE_FORMER_RECIPIENT,
    ROLE_RECIPIENT,
    ROLE_REQUESTER,
    SCOPE_PREDECESSOR,
    SCOPE_SELF,
    SCOPE_WORKSPACE,
    UNCONFIRMED_ENDS,
    ContinuityRefusal,
    attempt_stop_evidence,
    build_context_package,
    coarse_observation,
    continuity_delivery_id,
    delivery_stop_evidence,
    derive_data_scope,
    evidence_ingestion,
    former_view,
    is_continuity,
    is_unresolved,
    make_request,
    new_effect_permission,
    pending_evidence_digest,
    predecessor_evidence,
    reason_code,
    region_claim,
    stop_blockers,
    validate_continues,
    validate_label,
    validate_region,
    validate_role,
    validate_task,
    withhold_content,
)
from .task_control import (
    ATTEMPT_ACTIVE,
    ATTEMPT_ENDED,
    ATTEMPT_RESULT,
    DEFAULT_LEASE_SECONDS,
    DELIVERY_SCHEMA,
    EFFECT_ATTEMPT_START,
    EFFECT_DELIVER,
    EFFECT_RESULT_SUBMIT,
    MAX_INBOX,
    MAX_SCAN,
    REPORTED_OUTCOMES,
    STATE_DELIVERED,
    STATE_RESULT_RECORDED,
    TERMINAL_STATES,
    AuditSink,
    AuthorityRequest,
    AuthorityVerifier,
    TaskControl,
    TaskControlError,
    _active,
    _attempt_ref,
    _delivery_id,
    _dump,
    _fence,
    _IDEMPOTENCY_KEY,
    _iso,
    _summary,
    _text,
    validate_principal,
)

_WORKSPACE_EVIDENCE_LIMIT = 50
_CONTINUITY_DIRECTORY = "continuity"
_SAME_TASK_ACTIVE = "SAME_TASK_ATTEMPT_ACTIVE"
_SAME_TASK_UNSETTLED = "SAME_TASK_UNRESOLVED_EFFECT"
_LATE_RECEIPT_CHECKS = (
    "EXECUTOR_IS_ATTEMPT_EXECUTOR",
    "LATEST_ATTEMPT_AND_FENCE",
    "RESULT_BINDING",
    "CONTRACT_STILL_READY",
    "AUTHORITY_CURRENT",
)


class ContinuityControl(TaskControl):
    """``TaskControl`` that also keeps version-2 deliveries.

    A version-1 delivery that already exists is read and finished exactly as before. The successor does not
    create or start *new* version-1 work unless ``legacy_deliver=True`` was passed on purpose (see below).
    """

    def __init__(
        self,
        state_dir: str | Path,
        *,
        contracts: ContractStore,
        results: ResultV2Store,
        authority: AuthorityVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        audit: AuditSink | None = None,
        endpoint_ref: str | None = None,
        legacy_deliver: bool = False,
    ):
        super().__init__(state_dir, contracts=contracts, results=results, authority=authority, clock=clock, audit=audit)
        self.endpoint_ref = validate_label(endpoint_ref, "endpoint_ref", optional=True)
        if not isinstance(legacy_deliver, bool):
            raise TaskControlError("INVALID_ARGUMENT", "legacy_deliver must be a boolean")
        # BOUNDED LEGACY ENTRY. True re-opens version-1 `deliver` and the start of version-1 deliveries on this
        # successor. A version-1 delivery has no namespace, so none of the successor's guarantees (single active
        # attempt per task, same-task guard, version-2 binding) covers it; a deployment that sets this does not
        # get the successor's PASS. The independent `task-control` profile is the home of version 1.
        self.legacy_deliver = legacy_deliver
        self._continuity_root = self.root / _CONTINUITY_DIRECTORY
        self._v2_deliveries = self._continuity_root / "deliveries"
        self._v2_deliveries.mkdir(parents=True, exist_ok=True)
        self._bind_endpoint()

    def _bind_endpoint(self) -> None:
        """One state directory is one endpoint: the first instance fixes ``endpoint_ref``, a different one is refused."""
        marker = self._continuity_root / "endpoint"
        wanted = (self.endpoint_ref or "") + "\n"
        try:
            statefile.write_new(marker, wanted)
        except FileExistsError:
            if marker.read_text(encoding="utf-8") != wanted:
                raise TaskControlError(
                    "ENDPOINT_MISMATCH", "this state directory already belongs to a different endpoint_ref",
                ) from None

    # -- the legacy surface ---------------------------------------------------------------------------------

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
        """The version-1 delivery, refused unless this successor was built with ``legacy_deliver=True`` on purpose.

        A version-1 delivery has no namespace, so the same-task guard, the single-active-attempt rule and the
        version-2 binding cannot cover it. The successor therefore takes new deliveries only through
        ``deliver_continuity``; the bounded legacy entry exists for a host that knowingly keeps version-1 work
        on this endpoint, and it carries none of those guarantees.
        """
        if not self.legacy_deliver:
            raise TaskControlError(
                "LEGACY_DELIVER_DISABLED",
                "this endpoint takes deliveries only through the continuity send; the version-1 `task-control` "
                "profile (or a deliberately legacy-enabled endpoint) serves version-1 deliveries",
            )
        return super().deliver(
            principal, contract_id=contract_id, contract_digest=contract_digest, recipient=recipient,
            authority_ref=authority_ref, idempotency_key=idempotency_key,
            business_task_ref=business_task_ref, task_revision=task_revision,
        )

    # -- requester: a delivery in a namespace, with its continuation --------------------------------------------

    def deliver_continuity(
        self,
        principal: str,
        *,
        contract_id: str,
        contract_digest: str,
        recipient: str,
        authority_ref: str,
        idempotency_key: str,
        owner_ref: str,
        business_task_ref: str,
        task_revision: int,
        data_scope_ref: str,
        declared_region: str | None = None,
        continues: list[str] | None = None,
    ) -> dict[str, Any]:
        """Address one contract inside a namespace, bound to a task revision and a data scope.

        Refused while another delivery of the same task (same ``endpoint_ref`` + ``owner_ref`` +
        ``business_task_ref``) has an effect that is still open and is not named in ``continues``. UAM only
        links and refuses here: the evidence goes to the authority port, and what to do about it stays with
        the task's owner.
        """
        principal = validate_principal(principal, "principal")
        recipient = validate_principal(recipient, "recipient")
        if recipient == principal:
            raise TaskControlError("INVALID_ARGUMENT", "recipient must differ from the requesting principal")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise TaskControlError("INVALID_ARGUMENT", f"idempotency_key must match {_IDEMPOTENCY_KEY.pattern}")
        authority_ref = _text(authority_ref, "authority_ref", limit=300)
        owner = validate_label(owner_ref, "owner_ref")
        task_ref, revision = validate_task(business_task_ref, task_revision)
        scope_ref = _text(data_scope_ref, "data_scope_ref", limit=300)
        region = validate_region(declared_region)
        predecessors = validate_continues(continues)
        binding = self._deliverable(contract_id, contract_digest)
        data_scope = derive_data_scope(binding, scope_ref, region)
        delivery_id = continuity_delivery_id(self.endpoint_ref, owner, principal, idempotency_key)
        payload_digest = canonical_digest({
            "schema": DELIVERY_SCHEMA_V2,
            "endpoint_ref": self.endpoint_ref,
            "owner_ref": owner,
            "contract_id": contract_id,
            "contract_digest": binding.digest,
            "requester": principal,
            "recipient": recipient,
            "business_task_ref": task_ref,
            "task_revision": revision,
            "authority_ref": authority_ref,
            "data_scope": data_scope,
            "continues": list(predecessors),
        })
        existing = self._read_optional(delivery_id)
        if existing is not None:
            return self._replay_continuity(existing, payload_digest, principal)
        with statefile.exclusive_lock(self._lock):
            existing = self._read_optional(delivery_id)
            if existing is not None:
                return self._replay_continuity(existing, payload_digest, principal)
            others = self._all_continuity()
            in_task = [
                item for item in others
                if item["owner_ref"] == owner and item["business_task_ref"] == task_ref
                and item["endpoint_ref"] == self.endpoint_ref
            ]
            task_ids = {item["delivery_id"] for item in in_task}
            self._check_continuation(principal, predecessors, in_task)
            workspace_evidence = self._workspace_evidence(others, binding.workspace_id, task_ids)
            common: dict[str, Any] = {
                "principal": principal, "authority_ref": authority_ref, "delivery_id": delivery_id,
                "contract_id": contract_id, "contract_digest": binding.digest, "workspace_id": binding.workspace_id,
                "endpoint_ref": self.endpoint_ref, "owner_ref": owner, "role": ROLE_REQUESTER, "requester": principal,
                "recipient": recipient, "business_task_ref": task_ref, "task_revision": revision,
                "data_scope": data_scope, "initiator": principal, "continues": predecessors,
            }
            self._decide(make_request(effect=EFFECT_DELIVER, pending_evidence=workspace_evidence, **common))
            evidence_digest = None
            if predecessors:
                evidence = [
                    predecessor_evidence(
                        item, scope=SCOPE_PREDECESSOR, effect=self._effect_of_delivery(item),
                    )
                    for item in in_task if item["delivery_id"] in predecessors
                ] + workspace_evidence
                self._decide(make_request(effect=EFFECT_CONTINUE_TASK, pending_evidence=evidence, **common))
                evidence_digest = pending_evidence_digest(evidence)
            self._claim_contract(contract_id, delivery_id)
            now = self._now()
            delivery: dict[str, Any] = {
                "schema": DELIVERY_SCHEMA_V2,
                "delivery_id": delivery_id,
                "payload_digest": payload_digest,
                "endpoint_ref": self.endpoint_ref,
                "owner_ref": owner,
                "contract_id": contract_id,
                "contract_digest": binding.digest,
                "workspace_id": binding.workspace_id,
                "requester": principal,
                "recipient": recipient,
                "origin_requester": principal,
                "origin_recipient": recipient,
                "business_task_ref": task_ref,
                "task_revision": revision,
                "authority_ref": authority_ref,
                "data_scope": data_scope,
                "continues": list(predecessors),
                "continuation_evidence_digest": evidence_digest,
                "handovers": [],
                "created_at": _iso(now),
                "state": STATE_DELIVERED,
                "fence": 0,
                "attempts": [],
                "cancel": None,
                "result": None,
                "events": [],
            }
            self._event(delivery, now, "DELIVERED", principal)
            statefile.write_new(self._v2_deliveries / f"{delivery_id}.json", _dump(delivery))
        self._record("deliver_continuity", delivery, "PASS", principal)
        return {**self._view(delivery, principal), "replayed": False}

    def _replay_continuity(self, delivery: dict[str, Any], payload_digest: str, principal: str) -> dict[str, Any]:
        if not is_continuity(delivery) or delivery["payload_digest"] != payload_digest:
            raise TaskControlError(
                "IDEMPOTENCY_CONFLICT", "this idempotency key was used for a different delivery payload",
            )
        if principal in (delivery["requester"], delivery["recipient"]):
            return {**self._view(delivery, principal), "replayed": True}
        # The requester role was handed over: the original requester learns only that this delivery exists.
        return {
            "delivery_id": delivery["delivery_id"], "state": delivery["state"],
            "viewer_role": "former_requester", "replayed": True,
        }

    def _check_continuation(
        self, principal: str, predecessors: tuple[str, ...], in_task: list[dict[str, Any]],
    ) -> None:
        by_id = {item["delivery_id"]: item for item in in_task}
        if any(predecessor not in by_id for predecessor in predecessors):
            raise TaskControlError("PREDECESSOR_NOT_FOUND", "continues names a delivery that is not part of this task")
        if any(by_id[predecessor]["state"] not in TERMINAL_STATES for predecessor in predecessors):
            raise TaskControlError(
                "PREDECESSOR_NOT_TERMINAL",
                "a delivery that is continued must be finished or cancelled first; its requester cancels it",
            )
        unlinked = [
            item for item in in_task if is_unresolved(item) and item["delivery_id"] not in predecessors
        ]
        if unlinked:
            mine = sorted(
                item["delivery_id"] for item in unlinked if principal in (item["requester"], item["recipient"])
            )
            raise ContinuityRefusal(
                "PRIOR_UNRESOLVED_EFFECT_UNLINKED",
                "this task has an earlier delivery whose effect is not settled; name every such delivery in `continues`",
                {"unresolved_unlinked": True, "your_predecessors": mine},
            )

    def _workspace_evidence(
        self, others: list[dict[str, Any]], workspace_id: str, excluded: set[str],
    ) -> list[dict[str, Any]]:
        """The open deliveries on one workspace that are *not* part of the task in question, as bounded evidence.

        Another owner label or task name is another identity to UAM, so it is never refused here; the authority is
        shown that the workspace has an effect that is not settled, and decides. More than one request can carry
        fails closed.
        """
        evidence = [
            predecessor_evidence(item, scope=SCOPE_WORKSPACE, effect=self._effect_of_delivery(item))
            for item in others
            if item["workspace_id"] == workspace_id and item["delivery_id"] not in excluded and is_unresolved(item)
        ]
        if len(evidence) > _WORKSPACE_EVIDENCE_LIMIT:
            raise TaskControlError(
                "TASK_INDEX_TRUNCATED", "this workspace has more open deliveries than one request can carry",
            )
        return evidence

    # -- both parties ---------------------------------------------------------------------------------------

    def get(self, principal: str, *, delivery_id: str, observe: bool = False) -> dict[str, Any]:
        """Version 1 as before. A version-2 delivery gives its content only if ``dereference`` is authorised."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        peeked = self._read_optional(delivery_id)
        if peeked is None or not is_continuity(peeked):
            return super().get(principal, delivery_id=delivery_id, observe=observe)
        delivery = self._load_for(principal, delivery_id, role="participant")
        view = self._view(delivery, principal)
        request = self._request(delivery, EFFECT_DEREFERENCE, principal, role=self._role_of(delivery, principal))
        refusal = self._verdict(request)
        if refusal is not None:
            view = withhold_content(view)
            view["content_withheld"] = {"code": "AUTHORITY_DENIED", "reason": reason_code(refusal[0])}
            if observe:
                view["baseline_observation"] = coarse_observation(self._observe(delivery))
            return view
        try:
            view["contract"] = self.contracts.get_record(delivery["contract_id"])
        except ContractError:
            view["contract"] = None
        result_contract = self._result_contract_for(delivery, principal)  # next to the contract: only where content is readable
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

    def context_package(self, principal: str, *, delivery_id: str) -> dict[str, Any]:
        """The minimal Context Package of one version-2 delivery. It changes no delivery state; receiving it is authorised and audited."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        delivery = self._load_for(principal, delivery_id, role="participant")
        if not is_continuity(delivery):
            raise TaskControlError("NOT_FOUND", "delivery not found")
        role = self._role_of(delivery, principal)
        self._decide(self._request(delivery, EFFECT_CONTEXT_RECEIVE, principal, role=role))
        return build_context_package(
            delivery, effect=self._effect_of_delivery(delivery), viewer=principal, viewer_role=role,
            generated_at=_iso(self._now()),
        )

    def deliveries_for_task(
        self, principal: str, *, owner_ref: str, business_task_ref: str, limit: int = 20,
    ) -> dict[str, Any]:
        """The version-2 deliveries of one task that the caller takes part in. A read of metadata: it writes nothing."""
        principal = validate_principal(principal, "principal")
        owner = validate_label(owner_ref, "owner_ref")
        task_ref = _text(business_task_ref, "business_task_ref", limit=200)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_INBOX:
            raise TaskControlError("INVALID_ARGUMENT", f"limit must be an integer from 1 to {MAX_INBOX}")
        items = []
        for delivery in self._all_continuity():
            if (
                delivery["owner_ref"] == owner and delivery["business_task_ref"] == task_ref
                and delivery["endpoint_ref"] == self.endpoint_ref
                and principal in (delivery["requester"], delivery["recipient"])
            ):
                items.append({
                    **self._summary_view(delivery),
                    "unresolved": is_unresolved(delivery),
                    "effect": self._effect_of_delivery(delivery),
                    "new_effect_permission": new_effect_permission(delivery),
                })
        items.sort(key=lambda item: (item["created_at"], item["delivery_id"]))
        return {
            "items": items[:limit], "truncated": len(items) > limit, "claims_nothing": True,
            "writes_nothing": True, "business_acceptance": "NOT_DETERMINED_BY_UAM",
        }

    # -- handover -----------------------------------------------------------------------------------------------

    def handover(
        self, principal: str, *, delivery_id: str, role: str, to_principal: str, authority_ref: str,
    ) -> dict[str, Any]:
        """Hand the requester or the recipient role to another principal, as one exactly bound transfer.

        The current holder pushes, or the successor pulls (for example when the previous coordinator is
        gone); both are the same transfer with the same authority question. ``authority_ref`` is the
        reference that covers *this* transfer: it replaces the delivery's reference, and holding the old one
        never carries over. An attempt that is active when the recipient changes is closed ``HANDED_OVER``,
        which says nothing about whether its executor stopped.
        """
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        role = validate_role(role)
        successor = validate_principal(to_principal, "to_principal")
        authority_ref = _text(authority_ref, "authority_ref", limit=300)
        with statefile.exclusive_lock(self._lock):
            stored = self._read_optional(delivery_id)
            if stored is None or not is_continuity(stored):
                raise TaskControlError("NOT_FOUND", "delivery not found")
            replay = self._handover_replay(stored, principal, role, successor, authority_ref)
            if replay is not None:
                return replay
            party = principal in (stored["requester"], stored["recipient"])
            holder = stored[role]

            def refuse(code: str, message: str) -> TaskControlError:
                self._audit_refusal(stored, principal, "handover", code)
                # Someone who takes no part in the delivery learns nothing but that it is not theirs to see.
                return TaskControlError(code, message) if party else TaskControlError("NOT_FOUND", "delivery not found")

            if principal not in (holder, successor):
                raise refuse("WRONG_ROLE", "only the current holder of the role, or the principal taking it over, may hand it over")
            if stored["state"] in TERMINAL_STATES or stored["cancel"] is not None:
                raise refuse("DELIVERY_TERMINAL", "a finished or cancelled delivery is not handed over")
            other = stored[ROLE_RECIPIENT if role == ROLE_REQUESTER else ROLE_REQUESTER]
            if successor in (holder, other):
                raise refuse("HANDOVER_INVALID", "the successor must be a principal that holds neither role")
            if len(stored["handovers"]) >= MAX_HANDOVERS:
                raise refuse("HANDOVER_LIMIT", "this delivery was handed over as often as it may be")
            now = self._now()
            delivery = copy.deepcopy(stored)  # nothing is written unless the authority allows the transfer
            latest = delivery["attempts"][-1] if delivery["attempts"] else None
            evidence = [predecessor_evidence(delivery, scope=SCOPE_SELF, effect=self._effect_of_delivery(delivery))]
            request = self._request(
                delivery, EFFECT_HANDOVER, principal, role=role, attempt=latest, authority_ref=authority_ref,
                from_principal=holder, to_principal=successor, pending=evidence,
            )
            try:
                self._decide(request)
            except TaskControlError:
                if not party:
                    raise TaskControlError("NOT_FOUND", "delivery not found") from None
                raise
            closed_ref = None
            active = _active(delivery)
            if role == ROLE_RECIPIENT and active is not None:
                self._close_attempt(delivery, active, now, how=END_HANDED_OVER)
                closed_ref = active["attempt_ref"]
            delivery[role] = successor
            delivery["authority_ref"] = authority_ref
            record = {
                "seq": len(delivery["handovers"]) + 1,
                "role": role,
                "from": holder,
                "to": successor,
                "initiator": principal,
                "at": _iso(now),
                "authority_ref": authority_ref,
                "binding_digest": request.binding_digest,
                "request_identity": canonical_digest({
                    "role": role, "from": holder, "to": successor, "initiator": principal, "authority_ref": authority_ref,
                }),
                "closed_attempt_ref": closed_ref,
                "stop_at_handover": delivery_stop_evidence(delivery),
            }
            delivery["handovers"].append(record)
            self._event(
                delivery, now, "HANDOVER", principal, seq=record["seq"], role=role, from_principal=holder,
                to=successor, closed_attempt_ref=closed_ref,
            )
            self._save(delivery)
        self._record("handover", delivery, "PASS", principal)
        return self._handover_answer(delivery, principal, role, record, replayed=False)

    def _handover_replay(
        self, delivery: dict[str, Any], principal: str, role: str, successor: str, authority_ref: str,
    ) -> dict[str, Any] | None:
        """The same caller repeating the last transfer (a lost answer) gets that record back and nothing else happens."""
        if not delivery["handovers"]:
            return None
        last = delivery["handovers"][-1]
        same = (
            last["role"] == role and last["to"] == successor and last["initiator"] == principal
            and last["authority_ref"] == authority_ref
        )
        return self._handover_answer(delivery, principal, role, last, replayed=True) if same else None

    def _handover_answer(
        self, delivery: dict[str, Any], principal: str, role: str, record: dict[str, Any], *, replayed: bool,
    ) -> dict[str, Any]:
        if principal in (delivery["requester"], delivery["recipient"]):
            shown: dict[str, Any] = self._view(delivery, principal)
        else:  # the role was handed away: the previous holder sees that it happened and nothing else
            shown = {
                "delivery_id": delivery["delivery_id"], "state": delivery["state"], "viewer_role": f"former_{role}",
            }
        return {"handover": record, "delivery": shown, "replayed": replayed}

    # -- recipient: results and stop reports, also late -----------------------------------------------------------

    def submit_result(
        self, principal: str, *, delivery_id: str, attempt_ref: str, fence: int, result: dict[str, Any],
    ) -> dict[str, Any]:
        """Version 1 as before. For a version-2 delivery only the attempt's own executor can submit, also late."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        attempt_ref = _attempt_ref(attempt_ref)
        fence = _fence(fence)
        peeked = self._read_optional(delivery_id)
        if peeked is None or not is_continuity(peeked):
            return super().submit_result(
                principal, delivery_id=delivery_id, attempt_ref=attempt_ref, fence=fence, result=result,
            )
        if not isinstance(result, dict):
            raise TaskControlError("INVALID_ARGUMENT", "result must be an object")
        try:
            digest = self.results.submission_digest(result)
        except ContractError as exc:
            raise TaskControlError("RESULT_INVALID", str(exc)) from exc
        with statefile.exclusive_lock(self._lock):
            delivery = self._read_required(delivery_id)
            try:
                answer = self._ingest_result(delivery, principal, attempt_ref, fence, result, digest)
            except TaskControlError as exc:
                self._audit_refusal(delivery, principal, "submit_result", exc.code)
                raise
        return answer

    def _ingest_result(
        self, delivery: dict[str, Any], principal: str, attempt_ref: str, fence: int, result: dict[str, Any],
        digest: str,
    ) -> dict[str, Any]:
        standing = self._executor_standing(delivery, principal)
        attempt = self._own_attempt(delivery, principal, standing, attempt_ref)
        now = self._now()
        if delivery["state"] == STATE_RESULT_RECORDED:
            if delivery["result"]["submission_digest"] != digest:
                raise TaskControlError("RESULT_ALREADY_RECORDED", "this delivery already has a different result")
            return self._answer_ingested(delivery, principal, standing, attempt, replayed=True)
        if attempt["fence"] != fence or delivery["fence"] != fence:
            raise TaskControlError("FENCE_MISMATCH", "this attempt was superseded by a later one")
        late_how: str | None = None
        if attempt["state"] == ATTEMPT_ENDED:
            if attempt["end"]["how"] not in UNCONFIRMED_ENDS:
                raise TaskControlError("ATTEMPT_NOT_ACTIVE", "this attempt already ended and its executor reported that it stopped")
            late_how = attempt["end"]["how"]
        elif attempt["state"] != ATTEMPT_ACTIVE:
            raise TaskControlError("ATTEMPT_NOT_ACTIVE", "this attempt has already ended")
        self._require_result_binding(delivery, attempt, principal, result)
        self._bound_contract(delivery)
        self._decide(self._request(
            delivery, EFFECT_RESULT_SUBMIT, principal, role=standing, attempt=attempt, late_how=late_how,
        ))
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
        if late_how is None:
            attempt["end"] = {"how": "RESULT", "ended_at": _iso(now)}
        else:  # the closure stays as it was recorded; the receipt is added beside it, never over it
            attempt["late_receipt"] = {
                "ingested_at": _iso(now), "after_end_how": late_how, "checks": list(_LATE_RECEIPT_CHECKS),
            }
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
            "late_after_attempt_end": late_how,
        }
        self._event(
            delivery, now, "RESULT_RECORDED", principal, result_id=result["result_id"],
            review=review["state"], after_cancel_request=after_cancel, late_after_attempt_end=late_how,
        )
        self._save(delivery)
        self._record("submit_result", delivery, review["state"], principal)
        return self._answer_ingested(delivery, principal, standing, attempt, replayed=False)

    def end_attempt(
        self, principal: str, *, delivery_id: str, attempt_ref: str, fence: int, outcome: str, note: str = "",
    ) -> dict[str, Any]:
        """Version 1 as before. For a version-2 delivery the executor can also report a stop after its lease ran out."""
        principal = validate_principal(principal, "principal")
        delivery_id = _delivery_id(delivery_id)
        attempt_ref = _attempt_ref(attempt_ref)
        fence = _fence(fence)
        peeked = self._read_optional(delivery_id)
        if peeked is None or not is_continuity(peeked):
            return super().end_attempt(
                principal, delivery_id=delivery_id, attempt_ref=attempt_ref, fence=fence, outcome=outcome, note=note,
            )
        if outcome not in REPORTED_OUTCOMES:
            raise TaskControlError("INVALID_ARGUMENT", f"outcome must be one of {', '.join(REPORTED_OUTCOMES)}")
        note = _text(note, "note", limit=500, required=False)
        with statefile.exclusive_lock(self._lock):
            delivery = self._read_required(delivery_id)
            try:
                answer = self._report_stop(delivery, principal, attempt_ref, fence, outcome, note)
            except TaskControlError as exc:
                self._audit_refusal(delivery, principal, "end_attempt", exc.code)
                raise
        return answer

    def _report_stop(
        self, delivery: dict[str, Any], principal: str, attempt_ref: str, fence: int, outcome: str, note: str,
    ) -> dict[str, Any]:
        standing = self._executor_standing(delivery, principal)
        attempt = self._own_attempt(delivery, principal, standing, attempt_ref)
        now = self._now()
        if attempt["state"] == ATTEMPT_ACTIVE:
            attempt = self._active_attempt(delivery, attempt_ref, fence)
            self._close_attempt(delivery, attempt, now, how="REPORTED", reported=outcome, note=note)
            self._save(delivery)
            self._record("end_attempt", delivery, attempt["end"]["effect"], principal)
            return self._answer_stop(delivery, principal, standing, attempt)
        if attempt["fence"] != fence or delivery["fence"] != fence:
            raise TaskControlError("FENCE_MISMATCH", "this attempt was superseded by a later one")
        if attempt["state"] != ATTEMPT_ENDED or attempt["end"]["how"] not in UNCONFIRMED_ENDS:
            raise TaskControlError("ATTEMPT_NOT_ACTIVE", "this attempt has already ended")
        earlier = attempt.get("late_stop_report")
        if earlier is not None:
            if earlier["outcome"] != outcome:
                raise TaskControlError("ATTEMPT_NOT_ACTIVE", "this attempt's stop was already reported differently")
            return self._answer_stop(delivery, principal, standing, attempt)
        # Evidence only: the closure and the effect UAM recorded then stay exactly as they were.
        attempt["late_stop_report"] = {"outcome": outcome, "reported_at": _iso(now), "note": note}
        self._event(
            delivery, now, "LATE_STOP_REPORTED", principal, attempt_ref=attempt_ref, outcome=outcome,
            after_end_how=attempt["end"]["how"],
        )
        self._save(delivery)
        self._record("end_attempt", delivery, "LATE_STOP_REPORT", principal)
        return self._answer_stop(delivery, principal, standing, attempt)

    # -- who may act on an attempt ----------------------------------------------------------------------------------

    @staticmethod
    def _role_of(delivery: dict[str, Any], principal: str) -> str:
        return ROLE_REQUESTER if principal == delivery["requester"] else ROLE_RECIPIENT

    @staticmethod
    def _executor_standing(delivery: dict[str, Any], principal: str) -> str:
        """The current recipient, or a replaced executor that still owns an attempt; nobody else has a standing."""
        if principal == delivery["recipient"]:
            return ROLE_RECIPIENT
        if any(item.get("executor") == principal for item in delivery["attempts"]):
            return ROLE_FORMER_RECIPIENT
        if principal == delivery["requester"]:
            raise TaskControlError("WRONG_ROLE", "only the recipient of a delivery may do this")
        raise TaskControlError("NOT_FOUND", "delivery not found")

    @staticmethod
    def _own_attempt(delivery: dict[str, Any], principal: str, standing: str, attempt_ref: str) -> dict[str, Any]:
        """The attempt, if ``principal`` is its executor. A replaced executor learns nothing about anybody else's."""
        attempt = next((item for item in delivery["attempts"] if item["attempt_ref"] == attempt_ref), None)
        if attempt is None or (standing == ROLE_FORMER_RECIPIENT and attempt["executor"] != principal):
            raise TaskControlError("NOT_FOUND", "attempt not found")
        if attempt["executor"] != principal:
            raise TaskControlError("NOT_ATTEMPT_EXECUTOR", "this attempt belongs to another executor")
        return attempt

    def _answer_ingested(
        self, delivery: dict[str, Any], principal: str, standing: str, attempt: dict[str, Any], *, replayed: bool,
    ) -> dict[str, Any]:
        if standing == ROLE_RECIPIENT:
            return self._answer_result(delivery, principal, replayed=replayed)
        return {
            "delivery": former_view(delivery, attempt, effect=self._effect_of_delivery(delivery)),
            "result_record": self.results.get(delivery["result"]["result_id"]),
            "replayed": replayed,
        }

    def _answer_stop(
        self, delivery: dict[str, Any], principal: str, standing: str, attempt: dict[str, Any],
    ) -> dict[str, Any]:
        if standing == ROLE_RECIPIENT:
            return self._view(delivery, principal)
        return former_view(delivery, attempt, effect=self._effect_of_delivery(delivery))

    # -- hooks of TaskControl ---------------------------------------------------------------------------------------

    def _path(self, delivery_id: str) -> Path:
        version_two = self._v2_deliveries / f"{delivery_id}.json"
        return version_two if version_two.exists() else super()._path(delivery_id)

    @staticmethod
    def _load_path(path: Path) -> dict[str, Any]:
        delivery = json.loads(path.read_text(encoding="utf-8"))
        in_continuity = path.parent.name == "deliveries" and path.parent.parent.name == _CONTINUITY_DIRECTORY
        if delivery.get("schema") != (DELIVERY_SCHEMA_V2 if in_continuity else DELIVERY_SCHEMA):
            raise TaskControlError("INTERNAL", "unsupported delivery record")
        return delivery

    def _delivery_paths(self) -> list[Path]:
        return super()._delivery_paths() + sorted(self._v2_deliveries.glob("dlv-*.json"))

    def _all_continuity(self) -> list[dict[str, Any]]:
        """Every version-2 record, or a refusal: an index that is too large or has an unreadable entry is never guessed at."""
        paths = sorted(self._v2_deliveries.glob("dlv-*.json"))
        if len(paths) > MAX_SCAN:
            raise TaskControlError("TASK_INDEX_TRUNCATED", "there are more deliveries than can be checked in one call")
        records = []
        for path in paths:
            try:
                records.append(self._load_path(path))
            except (OSError, ValueError):  # unreadable, not UTF-8 or not JSON
                raise TaskControlError("INTERNAL", "a delivery record cannot be read") from None
        return records

    @staticmethod
    def _task_identity(delivery: dict[str, Any]) -> tuple[Any, Any, Any]:
        """What makes two deliveries one task: the labels stored when the delivery was made, never the caller's."""
        try:
            return (delivery["endpoint_ref"], delivery["owner_ref"], delivery["business_task_ref"])
        except (KeyError, TypeError):  # a record that cannot say whose task it is must stop the check, not slip past it
            raise TaskControlError("INTERNAL", "a delivery record is incomplete") from None

    def _task_siblings(self, delivery: dict[str, Any]) -> list[dict[str, Any]]:
        identity = self._task_identity(delivery)
        return [
            item for item in self._all_continuity()
            if item["delivery_id"] != delivery["delivery_id"] and self._task_identity(item) == identity
        ]

    def _stop_of(self, delivery: dict[str, Any]) -> str:
        return delivery_stop_evidence(delivery) if is_continuity(delivery) else super()._stop_of(delivery)

    def start_attempt(
        self, principal: str, *, delivery_id: str, lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> dict[str, Any]:
        """Version 1 as before (only with the bounded legacy entry). A version-2 start also needs the task to be free.

        Everything runs inside the state lock the base class takes: the start gate (including the check of the
        task's other deliveries), the authority question and the save are one critical section, so two starts
        of one task cannot both pass the check. A refusal by the task guard is audited.
        """
        try:
            return super().start_attempt(principal, delivery_id=delivery_id, lease_seconds=lease_seconds)
        except ContinuityRefusal as refusal:
            if refusal.code in (_SAME_TASK_ACTIVE, _SAME_TASK_UNSETTLED):
                refused = self._read_optional(delivery_id)
                if refused is not None:
                    self._audit_refusal(refused, principal, "start_attempt", refusal.code)
            raise

    def _attempt_gate(self, delivery: dict[str, Any]) -> None:
        if not is_continuity(delivery):
            if not self.legacy_deliver:
                raise TaskControlError(
                    "LEGACY_DELIVER_DISABLED",
                    "this endpoint starts attempts only for deliveries made through the continuity send; a "
                    "version-1 delivery is finished (cancel, result, end) here but started by the version-1 "
                    "`task-control` profile or by a deliberately legacy-enabled endpoint",
                )
            return
        if stop_blockers(delivery):
            raise TaskControlError(
                "STOP_NOT_CONFIRMED",
                "an earlier attempt ended without its executor saying that it stopped, so nobody may start another; "
                "only that executor's own report lifts this, and nothing here fences it",
            )
        self._require_free_task(delivery)

    def _require_free_task(self, delivery: dict[str, Any]) -> None:
        """Refuse a start while another delivery of the same task has an attempt in flight or an effect not settled.

        Runs inside ``start_attempt``'s critical section, over the existing delivery index and the stored task
        identity. Two things block, and neither can be lifted by the passage of time or by a closure UAM wrote:

        * a sibling whose latest attempt is still ``ACTIVE``: a lease that ran out is not a stop, so the record stays
          open until its own executor reports, or until it is cancelled and a delivery that names it in ``continues``
          lets the authority decide with its current evidence (``SAME_TASK_ATTEMPT_ACTIVE``);
        * a sibling this delivery does not ``continue`` whose effect is partial or unknown, or whose executor never
          said it stopped, whether it was cancelled, handed over or lease-closed since
          (``SAME_TASK_UNRESOLVED_EFFECT``).

        A sibling that *is* named in ``continues`` does not block here: it was finished or cancelled before this
        delivery existed, and its current evidence goes to the authority at the enforcement point (see
        ``_authorize_attempt``). An index that cannot be read in full refuses; nothing is guessed. The refusal's
        ``details`` list only deliveries the starter takes part in.
        """
        try:
            siblings = self._task_siblings(delivery)
            linked = set(delivery["continues"])
            active = [item for item in siblings if _active(item) is not None]
            unsettled = [item for item in siblings if item["delivery_id"] not in linked and is_unresolved(item)]
            blocking = active or unsettled
            mine = sorted(
                item["delivery_id"] for item in blocking
                if delivery["recipient"] in (item["requester"], item["recipient"])
            )
        except (KeyError, TypeError):  # an incomplete record in the index: refuse, never skip it
            raise TaskControlError("INTERNAL", "a delivery record is incomplete") from None
        if not blocking:
            return
        if active:
            raise ContinuityRefusal(
                _SAME_TASK_ACTIVE,
                "another delivery of this task has an attempt that is still active; a lease that ran out does not "
                "show that its executor stopped, so the task stays blocked until that executor reports, or that delivery "
                "is cancelled and a new delivery names it in `continues`",
                {"same_task_attempt_active": True, "your_deliveries": mine},
            )
        raise ContinuityRefusal(
            _SAME_TASK_UNSETTLED,
            "another delivery of this task has an effect that is not settled and this delivery does not continue it; "
            "once it is finished or cancelled, a new delivery that names it in `continues` puts its evidence in front of the authority",
            {"same_task_effect_unresolved": True, "your_deliveries": mine},
        )

    def _stamp_attempt(self, delivery: dict[str, Any], attempt: dict[str, Any], principal: str) -> None:
        if is_continuity(delivery):
            attempt["executor"] = principal

    def _authorize_attempt(self, delivery: dict[str, Any], principal: str, binding: ContractBinding) -> None:
        if not is_continuity(delivery):
            super()._authorize_attempt(delivery, principal, binding)
            return
        fence = delivery["fence"] + 1
        upcoming = {
            "attempt_ref": f"att-{delivery['delivery_id'][4:]}.{fence}", "fence": fence, "executor": principal,
        }
        self._decide(self._request(
            delivery, EFFECT_ATTEMPT_START, principal, role=ROLE_RECIPIENT, attempt=upcoming,
            pending=self._continuation_evidence_now(delivery) + self._workspace_evidence_now(delivery),
        ))

    def _workspace_evidence_now(self, delivery: dict[str, Any]) -> list[dict[str, Any]]:
        """What the *other* tasks on this workspace say now: the question at the enforcement point is not the one at delivery.

        Another ``owner_ref`` or ``business_task_ref`` is another identity to UAM, so it can neither be refused nor
        merged here. It stays visible: a workspace whose other deliveries were fresh when this one was made can
        have an active attempt by now, and the authority, not a label, decides what that means.
        """
        others = self._all_continuity()
        try:
            identity = self._task_identity(delivery)
            excluded = {
                item["delivery_id"] for item in others
                if item["delivery_id"] == delivery["delivery_id"] or self._task_identity(item) == identity
            }
        except (KeyError, TypeError):
            raise TaskControlError("INTERNAL", "a delivery record is incomplete") from None
        return self._workspace_evidence(others, delivery["workspace_id"], excluded)

    def _continuation_evidence_now(self, delivery: dict[str, Any]) -> list[dict[str, Any]]:
        """What the delivered predecessors say *now*: the question at the enforcement point is not the one asked at delivery.

        A predecessor whose executor never said it stopped stays visible to the authority when the new attempt
        starts, and a later independent report changes the question. UAM does not decide what that evidence
        means; it does not let the link, the closure or the passage of time stand in for it.
        """
        evidence = []
        for predecessor_id in delivery["continues"]:
            predecessor = self._read_optional(predecessor_id)
            if predecessor is None or not is_continuity(predecessor):
                raise TaskControlError("INTERNAL", "a delivery that this one continues cannot be read")
            evidence.append(predecessor_evidence(
                predecessor, scope=SCOPE_PREDECESSOR, effect=self._effect_of_delivery(predecessor),
            ))
        return evidence

    def _closer_of(self, delivery: dict[str, Any], attempt: dict[str, Any], how: str) -> str:
        if not is_continuity(delivery):
            return super()._closer_of(delivery, attempt, how)
        return attempt["executor"] if how == "REPORTED" else "uam"

    def _summary_view(self, delivery: dict[str, Any]) -> dict[str, Any]:
        summary = super()._summary_view(delivery)
        if is_continuity(delivery):
            summary.update({
                "schema": delivery["schema"], "endpoint_ref": delivery["endpoint_ref"], "owner_ref": delivery["owner_ref"],
            })
        return summary

    def _view(self, delivery: dict[str, Any], viewer: str) -> dict[str, Any]:
        view = super()._view(delivery, viewer)
        if not is_continuity(delivery):
            return view
        for shown, stored in zip(view["attempts"], delivery["attempts"], strict=True):
            shown["executor"] = stored["executor"]
            shown["stop_evidence"] = attempt_stop_evidence(stored)
            if "late_receipt" in stored:
                shown["late_receipt"] = stored["late_receipt"]
            if "late_stop_report" in stored:
                shown["late_stop_report"] = stored["late_stop_report"]
        last_end = delivery["attempts"][-1]["end"] if delivery["attempts"] else None
        observed = last_end.get("observation") if isinstance(last_end, dict) else None
        view.update({
            "schema": delivery["schema"],
            "endpoint_ref": delivery["endpoint_ref"],
            "owner_ref": delivery["owner_ref"],
            "origin_requester": delivery["origin_requester"],
            "origin_recipient": delivery["origin_recipient"],
            "handover_seq": len(delivery["handovers"]),
            "handovers": delivery["handovers"],
            "continues": list(delivery["continues"]),
            "continuation_evidence_digest": delivery["continuation_evidence_digest"],
            "data_scope": {**delivery["data_scope"], **region_claim(delivery["data_scope"])},
            "stop_evidence": delivery_stop_evidence(delivery),
            # Four facts that are never merged: what was taken in, what UAM read back itself, whether the
            # owner accepts it (never decided here), and what the record alone says about a new effect.
            "evidence_ingestion": evidence_ingestion(delivery),
            "independent_readback": {
                "source": "UAM_OWN_OBSERVATION",
                "effect": view["effect"],
                "latest_observation": coarse_observation(observed) if isinstance(observed, dict) else None,
                "review_state": delivery["result"]["review_state"] if delivery["result"] is not None else None,
            },
            "new_effect_permission": new_effect_permission(delivery),
        })
        return view

    # -- requests and refusals ----------------------------------------------------------------------------------------

    def _request(
        self,
        delivery: dict[str, Any],
        effect: str,
        principal: str,
        *,
        role: str,
        attempt: dict[str, Any] | None = None,
        late_how: str | None = None,
        authority_ref: str | None = None,
        from_principal: str | None = None,
        to_principal: str | None = None,
        pending: list[dict[str, Any]] | None = None,
    ) -> AuthorityRequest:
        """The version-2 question about one transition of an existing delivery, filled from the record."""
        return make_request(
            effect=effect,
            principal=principal,
            authority_ref=authority_ref if authority_ref is not None else delivery["authority_ref"],
            delivery_id=delivery["delivery_id"],
            contract_id=delivery["contract_id"],
            contract_digest=delivery["contract_digest"],
            workspace_id=delivery["workspace_id"],
            endpoint_ref=delivery["endpoint_ref"],
            owner_ref=delivery["owner_ref"],
            role=role,
            requester=delivery["requester"],
            recipient=delivery["recipient"],
            business_task_ref=delivery["business_task_ref"],
            task_revision=delivery["task_revision"],
            data_scope=delivery["data_scope"],
            handover_seq=len(delivery["handovers"]),
            initiator=principal,
            from_principal=from_principal,
            to_principal=to_principal,
            attempt_ref=attempt["attempt_ref"] if attempt is not None else None,
            fence=attempt["fence"] if attempt is not None else None,
            original_executor=attempt["executor"] if attempt is not None else None,
            late_after_attempt_end=late_how,
            continues=delivery["continues"],
            pending_evidence=pending if pending is not None else (),
        )

    def _audit_refusal(self, delivery: dict[str, Any], principal: str, action: str, code: str) -> None:
        """A refused late or handed-over transition leaves evidence too (an authority denial already did)."""
        if self._audit is None or code == "AUTHORITY_DENIED":
            return
        self._audit.append(
            action=f"task_control.{action}",
            workspace_id=delivery["workspace_id"],
            outcome="DENY",
            details={
                "delivery_id": delivery["delivery_id"],
                "contract_id": delivery["contract_id"],
                "principal": principal,
                "reason": reason_code(code),
            },
        )

