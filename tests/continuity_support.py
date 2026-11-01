"""Test support for the successor contract of ``task_control`` (``task_continuity``): not a test module.

``PortAuthority`` is a stand-in that shows what the version-2 authority port *carries*: that a request has
enough fields to tell apart who hands what to whom, that its ``binding_digest`` can be recomputed, and what
a verifier may pin or refuse. It is not an issuer, holds no real grant, and proves nothing about one.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from universal_agent_middleware.task_continuity import compute_binding_digest
from universal_agent_middleware.task_continuity_control import ContinuityControl
from universal_agent_middleware.task_control import AuthorityDecision, AuthorityRequest, TaskControl, TaskControlError

from coordination_fixtures import contract_v2, document_result
from directory_fixtures import PLAIN_ID, WorldTestCase
from test_task_control import EXECUTOR, NEW_DOC, NEW_TEXT, REQUESTER, STRANGER, FakeClock, snapshot

__all__ = [
    "ALL_EFFECTS", "COORDINATOR_TWO", "ENDPOINT", "EXECUTOR", "NEW_DOC", "NEW_TEXT", "OWNER", "REQUESTER",
    "STRANGER", "SUCCESSOR", "TASK", "ContinuityWorld", "FakeClock", "PortAuthority", "snapshot",
]

SUCCESSOR = "executor-d"
COORDINATOR_TWO = "requester-e"
OWNER = "owner-x"
ENDPOINT = "endpoint-one"
TASK = "task-42"
ALL_EFFECTS = frozenset({
    "deliver", "continue_task", "attempt_start", "result_submit", "handover", "context_receive", "dereference",
})
_VERSION_ONE_EFFECTS = frozenset({"deliver", "attempt_start", "result_submit"})


class PortAuthority:
    """A version-2 verifier by port semantics only: it recomputes the digest, checks the reference and keeps a log."""

    request_version = 2

    def __init__(self) -> None:
        self.effects: set[str] = set(ALL_EFFECTS)
        self.valid_refs: set[str] | None = None
        self.pinned: dict[str, str] = {}
        self.rules: list[Callable[[AuthorityRequest], str | None]] = []
        self.requests: list[AuthorityRequest] = []

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        self.requests.append(request)
        if request.request_version == 1:
            allowed = request.effect in _VERSION_ONE_EFFECTS and request.effect in self.effects
            return AuthorityDecision(allowed, "GRANTED" if allowed else "REVOKED")
        if request.binding_digest != compute_binding_digest(request):
            return AuthorityDecision(False, "BINDING_NOT_VERIFIABLE")
        if self.valid_refs is not None and request.authority_ref not in self.valid_refs:
            return AuthorityDecision(False, "REFERENCE_NOT_VALID")
        if request.effect not in self.effects:
            return AuthorityDecision(False, "REVOKED")
        pinned = self.pinned.get(request.effect)
        if pinned is not None and pinned != request.binding_digest:
            return AuthorityDecision(False, "NOT_THE_APPROVED_TRANSFER")
        for rule in self.rules:
            reason = rule(request)
            if reason is not None:
                return AuthorityDecision(False, reason)
        return AuthorityDecision(True, "GRANTED")

    def asked(self, effect: str) -> list[AuthorityRequest]:
        return [request for request in self.requests if request.effect == effect]

    def forget(self) -> None:
        self.requests.clear()


class ContinuityWorld(WorldTestCase):
    """One gateway, one successor control object, two principals modelled by name (as in the first batch)."""

    def setUp(self) -> None:
        super().setUp()
        self.gw = self.world.gateway()
        self.clock = FakeClock()
        self.authority = PortAuthority()
        self.control = self.make_control()
        self.contract = self.new_contract("cont-task")

    def make_control(self, **overrides: Any) -> ContinuityControl:
        options: dict[str, Any] = {
            "contracts": self.gw.contracts, "results": self.gw.results_v2, "authority": self.authority,
            "clock": self.clock, "audit": self.gw.audit, "endpoint_ref": ENDPOINT,
        }
        options.update(overrides)
        return ContinuityControl(self.gw.state_dir, **options)

    def new_contract(self, contract_id: str, **overrides: Any) -> dict[str, Any]:
        options: dict[str, Any] = {"authoritative": ["README.md"], "allowed": [NEW_DOC]}
        options.update(overrides)
        return self.gw.create_contract(contract_v2(contract_id, PLAIN_ID, **options))

    def deliver(self, contract: dict[str, Any] | None = None, principal: str = REQUESTER, **overrides: Any) -> dict[str, Any]:
        contract = contract or self.contract
        arguments: dict[str, Any] = {
            "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": f"key-{contract['contract_id']}",
            "owner_ref": OWNER, "business_task_ref": TASK, "task_revision": 3, "data_scope_ref": "scope-ref-1",
        }
        arguments.update(overrides)
        return self.control.deliver_continuity(principal, **arguments)

    def start(self, delivery_id: str, principal: str = EXECUTOR, **overrides: Any) -> dict[str, Any]:
        return self.control.start_attempt(principal, delivery_id=delivery_id, **overrides)

    def legacy_control(self) -> ContinuityControl:
        """The successor with the bounded legacy entry deliberately re-opened (it is closed by default)."""
        return self.make_control(legacy_deliver=True)

    def v1_deliver(self, contract: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
        """A version-1 delivery made through the successor class with the bounded legacy entry re-opened."""
        contract = contract or self.contract
        arguments: dict[str, Any] = {
            "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": f"v1-{contract['contract_id']}",
            "business_task_ref": "task-v1", "task_revision": 1,
        }
        arguments.update(overrides)
        return self.legacy_control().deliver(REQUESTER, **arguments)

    def plain_control(self) -> TaskControl:
        """What a process that only knows version 1 would run over the same state directory."""
        return TaskControl(
            self.gw.state_dir, contracts=self.gw.contracts, results=self.gw.results_v2,
            authority=self.authority, clock=self.clock, audit=self.gw.audit,
        )

    def write_document(self, text: str = NEW_TEXT) -> None:
        (self.world.plain / NEW_DOC).write_text(text, encoding="utf-8")

    def result_for(
        self, delivery: dict[str, Any], attempt: dict[str, Any], *, executor: str = EXECUTOR,
        result_id: str = "cont-result-1", text: str = NEW_TEXT, **overrides: Any,
    ) -> dict[str, Any]:
        record = self.gw.contracts.get_record(delivery["contract_id"])
        payload = document_result(
            record, result_id, {NEW_DOC: text}, attempt_ref=attempt["attempt_ref"], executor=executor,
            business_task_ref=delivery["business_task_ref"], task_revision=delivery["task_revision"],
        )
        payload.update(overrides)
        return payload

    def submit(
        self, delivery: dict[str, Any], attempt: dict[str, Any], payload: dict[str, Any], principal: str = EXECUTOR,
    ) -> dict[str, Any]:
        return self.control.submit_result(
            principal, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )

    def end(
        self, delivery: dict[str, Any], attempt: dict[str, Any], principal: str = EXECUTOR,
        outcome: str = "STOPPED", note: str = "",
    ) -> dict[str, Any]:
        return self.control.end_attempt(
            principal, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome=outcome, note=note,
        )

    def hand_over(
        self, delivery: dict[str, Any], role: str, to: str, principal: str, authority_ref: str = "grant-handover-1",
    ) -> dict[str, Any]:
        return self.control.handover(
            principal, delivery_id=delivery["delivery_id"], role=role, to_principal=to, authority_ref=authority_ref,
        )

    def state_of(self, delivery_id: str, principal: str = REQUESTER) -> dict[str, Any]:
        return self.control.get(principal, delivery_id=delivery_id)

    @staticmethod
    def last_attempt(view: dict[str, Any]) -> dict[str, Any]:
        return view["attempts"][-1]

    def running_attempt(self, lease_seconds: int = 60) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """A delivery whose executor started an attempt and wrote the document: (delivery, attempt, result payload)."""
        delivery = self.deliver()
        attempt = self.last_attempt(self.start(delivery["delivery_id"], lease_seconds=lease_seconds))
        self.write_document()
        return delivery, attempt, self.result_for(delivery, attempt)

    def assertRefused(self, code: str, call: Callable[[], Any]) -> TaskControlError:
        with self.assertRaises(TaskControlError) as raised:
            call()
        self.assertEqual(raised.exception.code, code, str(raised.exception))
        return raised.exception

    def delivery_bytes(self, delivery_id: str) -> bytes:
        path = self.control._v2_deliveries / f"{delivery_id}.json"
        return path.read_bytes()

    def audit_entries(self) -> list[dict[str, Any]]:
        path = Path(self.gw.state_dir) / "audit.jsonl"
        lines = path.read_text("utf-8").splitlines() if path.exists() else []
        return [json.loads(line) for line in lines if line.strip()]

    def audit_outcomes(self, action: str) -> list[str]:
        return [
            entry["outcome"] for entry in self.audit_entries() if entry["action"] == f"task_control.{action}"
        ]
