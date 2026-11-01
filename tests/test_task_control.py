"""Addressed delivery of one contract between two principals: ``task_control.TaskControl``.

The module is a bounded active-receiver integration. These tests pin what it must never do (authorize on
its own, run an attempt twice, call a cancel a stop, let a receiver's report stand for UAM's observation,
re-execute after a reconnect) as much as what it does. Two independent parties are modelled by two
principal names against one control object, which is exactly the boundary the MCP adapter enforces by
binding the principal at launch; a real second client is outside what this file can show.
"""
from __future__ import annotations

import hashlib
import json
import threading
import unittest
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from universal_agent_middleware.errors import UAMError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_control import (
    AuthorityDecision,
    AuthorityRequest,
    DenyAllAuthority,
    TaskControl,
    TaskControlError,
)

from coordination_fixtures import contract_v2, document_result, file_state, patch_result, sha
from directory_fixtures import PLAIN_ID, WorldTestCase, derived_id

REQUESTER = "requester-a"
EXECUTOR = "executor-b"
STRANGER = "stranger-c"
EPOCH = datetime(2026, 10, 28, 9, 0, 0, tzinfo=timezone.utc)
NEW_DOC = "notes/new.md"
NEW_TEXT = "written by the executor\n"


class FakeClock:
    def __init__(self) -> None:
        self.now = EPOCH

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class ScriptedAuthority:
    """An authority port with a switchable policy that records every question it is asked."""

    def __init__(self, allow: set[str] | None = None) -> None:
        self.allowed = {"deliver", "attempt_start", "result_submit"} if allow is None else set(allow)
        self.requests: list[AuthorityRequest] = []

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        self.requests.append(request)
        if request.effect in self.allowed:
            return AuthorityDecision(True, "GRANTED")
        return AuthorityDecision(False, "REVOKED")

    def asked(self, effect: str) -> list[AuthorityRequest]:
        return [request for request in self.requests if request.effect == effect]


def snapshot(root: Path) -> dict[str, str]:
    """Every file under ``root`` with the digest of its bytes (the state a read must leave untouched)."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


class ControlWorld(WorldTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.gw = self.world.gateway()
        self.clock = FakeClock()
        self.authority = ScriptedAuthority()
        self.control = self.make_control()
        self.contract = self.new_contract("control-task")

    def make_control(self, **overrides: Any) -> TaskControl:
        options: dict[str, Any] = {
            "contracts": self.gw.contracts, "results": self.gw.results_v2,
            "authority": self.authority, "clock": self.clock, "audit": self.gw.audit,
        }
        options.update(overrides)
        return TaskControl(self.gw.state_dir, **options)

    def new_contract(self, contract_id: str, **overrides: Any) -> dict[str, Any]:
        options: dict[str, Any] = {"authoritative": ["README.md"], "allowed": [NEW_DOC]}
        options.update(overrides)
        return self.gw.create_contract(contract_v2(contract_id, PLAIN_ID, **options))

    def deliver(self, contract: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
        contract = contract or self.contract
        arguments: dict[str, Any] = {
            "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": f"key-{contract['contract_id']}",
            "business_task_ref": "task-42", "task_revision": 3,
        }
        arguments.update(overrides)
        return self.control.deliver(REQUESTER, **arguments)

    def start(self, delivery_id: str, **overrides: Any) -> dict[str, Any]:
        return self.control.start_attempt(EXECUTOR, delivery_id=delivery_id, **overrides)

    def write_document(self, text: str = NEW_TEXT) -> None:
        (self.world.plain / NEW_DOC).write_text(text, encoding="utf-8")

    def result_for(self, delivery: dict[str, Any], attempt: dict[str, Any], result_id: str = "ctl-result-1",
                   text: str = NEW_TEXT, **overrides: Any) -> dict[str, Any]:
        record = self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"])["contract"]
        payload = document_result(
            record, result_id, {NEW_DOC: text},
            attempt_ref=attempt["attempt_ref"], executor=EXECUTOR,
            business_task_ref=delivery["business_task_ref"], task_revision=delivery["task_revision"],
        )
        payload.update(overrides)
        return payload

    def submit(self, delivery: dict[str, Any], attempt: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return self.control.submit_result(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )

    def active_attempt(self, view: dict[str, Any]) -> dict[str, Any]:
        return view["attempts"][-1]

    def assertRefused(self, code: str, call: Callable[[], Any]) -> TaskControlError:
        with self.assertRaises(TaskControlError) as raised:
            call()
        self.assertEqual(raised.exception.code, code, str(raised.exception))
        return raised.exception

    def state_of(self, delivery_id: str, principal: str = REQUESTER) -> dict[str, Any]:
        return self.control.get(principal, delivery_id=delivery_id)


class TestDelivery(ControlWorld):
    def test_one_contract_is_addressed_to_one_recipient_after_the_authority_was_asked(self) -> None:
        delivery = self.deliver()
        self.assertEqual(
            (delivery["state"], delivery["effect"], delivery["requester"], delivery["recipient"]),
            ("DELIVERED", "NO_ATTEMPT_STARTED", REQUESTER, EXECUTOR),
        )
        self.assertEqual((delivery["business_task_ref"], delivery["task_revision"]), ("task-42", 3))
        self.assertFalse(delivery["replayed"])
        asked = self.authority.asked("deliver")
        self.assertEqual(len(asked), 1)
        self.assertEqual(
            (asked[0].principal, asked[0].authority_ref, asked[0].contract_digest, asked[0].workspace_id),
            (REQUESTER, "grant-0001", self.contract["contract_digest"], PLAIN_ID),
        )
        self.assertEqual([item["delivery_id"] for item in self.control.inbox(EXECUTOR)["items"]], [delivery["delivery_id"]])
        self.assertEqual(self.control.inbox(REQUESTER)["items"], [])
        self.assertEqual(delivery["business_acceptance"], "NOT_DETERMINED_BY_UAM")

    def test_the_same_key_and_payload_is_the_same_delivery_not_a_second_authorization(self) -> None:
        first = self.deliver()
        again = self.deliver()
        self.assertEqual((again["delivery_id"], again["replayed"]), (first["delivery_id"], True))
        self.assertEqual(len(self.authority.asked("deliver")), 1)
        self.assertEqual(len(list((self.control.root / "deliveries").glob("dlv-*.json"))), 1)

    def test_the_same_key_for_another_payload_is_refused(self) -> None:
        self.deliver()
        for label, change in (
            ("recipient", {"recipient": "another-exec"}),
            ("authority", {"authority_ref": "grant-9999"}),
            ("task revision", {"task_revision": 4}),
            ("task", {"business_task_ref": "task-43"}),
        ):
            with self.subTest(label):
                self.assertRefused("IDEMPOTENCY_CONFLICT", lambda: self.deliver(**change))

    def test_a_contract_is_delivered_once_whatever_the_key(self) -> None:
        self.deliver()
        self.assertRefused("CONTRACT_ALREADY_DELIVERED", lambda: self.deliver(idempotency_key="another-key-1"))

    def test_concurrent_deliveries_of_one_contract_create_exactly_one(self) -> None:
        outcomes: list[str] = []
        barrier = threading.Barrier(4)

        def attempt(index: int) -> None:
            barrier.wait()
            try:
                self.deliver(idempotency_key=f"racing-key-{index}")
                outcomes.append("ok")
            except TaskControlError as exc:
                outcomes.append(exc.code)

        threads = [threading.Thread(target=attempt, args=(index,)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(outcomes), ["CONTRACT_ALREADY_DELIVERED"] * 3 + ["ok"])
        self.assertEqual(len(list((self.control.root / "deliveries").glob("dlv-*.json"))), 1)

    def test_only_a_ready_contract_of_the_current_schema_with_the_right_digest_is_delivered(self) -> None:
        self.assertRefused("CONTRACT_MISMATCH", lambda: self.deliver(contract_digest=sha("another contract")))
        self.assertRefused("CONTRACT_MISSING", lambda: self.deliver(contract_id="no-such-contract"))
        held = self.new_contract("held-task", open_questions=["which heading?"])
        self.assertRefused("CONTRACT_NOT_READY", lambda: self.deliver(held))
        head = self.gw._git(derived_id("git-repo")).status()["head"]
        legacy = self.gw.create_contract({
            "profile": "repository-change-v1", "contract_id": "legacy-task", "workspace_id": derived_id("git-repo"),
            "base_revision": head, "objective": "legacy", "non_goals": [], "authoritative_paths": ["README.md"],
            "allowed_change_paths": ["docs/guide.md"], "constraints": [], "implementation_decision": "edit",
            "expected_changes": ["edited"], "acceptance_criteria": ["edited"], "verification_commands": ["true"],
            "risk_notes": [], "rollback": ["revert"], "open_questions": [],
        })
        legacy["contract_digest"] = self.gw.contracts.digest("legacy-task")
        self.assertRefused("CONTRACT_NOT_DELIVERABLE", lambda: self.deliver(legacy))
        self.assertEqual(self.authority.requests, [])

    def test_a_missing_or_failing_or_unclear_authority_delivers_nothing(self) -> None:
        for label, authority in (
            ("default", None),
            ("revoked", ScriptedAuthority(allow=set())),
            ("error", mock.Mock(verify=mock.Mock(side_effect=RuntimeError("issuer down /private/path")))),
            ("not a decision", mock.Mock(verify=mock.Mock(return_value=True))),
            ("truthy but not true", mock.Mock(verify=mock.Mock(return_value=AuthorityDecision("yes", "?")))),
        ):
            with self.subTest(label):
                control = TaskControl(
                    self.gw.state_dir, contracts=self.gw.contracts, results=self.gw.results_v2,
                    **({} if authority is None else {"authority": authority}),
                )
                error = self.assertRefused("AUTHORITY_DENIED", lambda: control.deliver(
                    REQUESTER, contract_id="control-task", contract_digest=self.contract["contract_digest"],
                    recipient=EXECUTOR, authority_ref="grant-0001", idempotency_key=f"key-{label.replace(' ', '-')}",
                ))
                self.assertNotIn("/private/path", str(error))
        self.assertEqual(list((self.control.root / "deliveries").glob("dlv-*.json")), [])
        self.assertEqual(list((self.control.root / "by-contract").iterdir()), [])
        self.assertEqual(DenyAllAuthority().verify(mock.Mock()).allowed, False)

    def test_arguments_are_validated_before_anything_is_asked_or_written(self) -> None:
        cases = {
            "uppercase principal": dict(principal="Requester"),
            "self delivery": dict(recipient=REQUESTER),
            "short key": dict(idempotency_key="short"),
            "blank authority": dict(authority_ref=" "),
            "revision without task": dict(business_task_ref=None, task_revision=3),
            "task without revision": dict(task_revision=None),
            "negative revision": dict(task_revision=-1),
            "boolean revision": dict(task_revision=True),
            "recipient shape": dict(recipient="../etc"),
        }
        for label, change in cases.items():
            with self.subTest(label):
                principal = change.pop("principal", REQUESTER)
                arguments: dict[str, Any] = {
                    "contract_id": "control-task", "contract_digest": self.contract["contract_digest"],
                    "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "valid-key-0001",
                    "business_task_ref": "task-42", "task_revision": 3, **change,
                }
                self.assertRefused("INVALID_ARGUMENT", lambda: self.control.deliver(principal, **arguments))
        self.assertEqual(self.authority.requests, [])

    def test_a_contract_only_delivery_needs_no_business_task(self) -> None:
        delivery = self.deliver(business_task_ref=None, task_revision=None)
        self.assertEqual((delivery["business_task_ref"], delivery["task_revision"]), (None, None))


class TestReadingIsNotClaiming(ControlWorld):
    def test_inbox_and_get_write_nothing_and_claim_nothing(self) -> None:
        delivery = self.deliver()
        before = snapshot(self.control.root)
        for _ in range(3):
            inbox = self.control.inbox(EXECUTOR)
            self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"])
            self.control.get(REQUESTER, delivery_id=delivery["delivery_id"], observe=True)
        self.assertEqual(snapshot(self.control.root), before)
        self.assertTrue(inbox["claims_nothing"])
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "DELIVERED")
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"], [])

    def test_only_the_two_parties_see_a_delivery_and_a_missing_one_looks_the_same(self) -> None:
        delivery = self.deliver()
        self.assertRefused("NOT_FOUND", lambda: self.control.get(STRANGER, delivery_id=delivery["delivery_id"]))
        self.assertRefused("NOT_FOUND", lambda: self.control.get(REQUESTER, delivery_id="dlv-" + "0" * 24))
        self.assertRefused("NOT_FOUND", lambda: self.control.start_attempt(STRANGER, delivery_id=delivery["delivery_id"]))
        self.assertEqual(self.control.inbox(STRANGER)["items"], [])
        self.assertRefused("INVALID_ARGUMENT", lambda: self.control.get(REQUESTER, delivery_id="../x"))

    def test_the_inbox_is_bounded_and_says_when_it_cut_the_list(self) -> None:
        for index in range(3):
            contract = self.new_contract(f"bulk-task-{index}")
            self.deliver(contract)
        listing = self.control.inbox(EXECUTOR, limit=2)
        self.assertEqual((len(listing["items"]), listing["truncated"]), (2, True))
        self.assertEqual(self.control.inbox(EXECUTOR, limit=10)["truncated"], False)
        for limit in (0, 51, True, "5"):
            with self.subTest(limit=limit):
                self.assertRefused("INVALID_ARGUMENT", lambda: self.control.inbox(EXECUTOR, limit=limit))

    def test_the_recipient_reads_the_contract_it_is_to_fulfil_and_the_requester_reads_the_result(self) -> None:
        delivery = self.deliver()
        view = self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"])
        self.assertEqual(view["viewer_role"], "recipient")
        self.assertEqual(view["contract"]["contract_digest"], self.contract["contract_digest"])
        self.assertIn(self.contract["contract_digest"], view["contract"]["executor_prompt"])
        self.assertEqual(self.state_of(delivery["delivery_id"])["viewer_role"], "requester")


class TestAttempts(ControlWorld):
    def test_one_attempt_at_a_time_with_a_fence_and_a_lease(self) -> None:
        delivery = self.deliver()
        started = self.start(delivery["delivery_id"], lease_seconds=120)
        attempt = self.active_attempt(started)
        self.assertEqual((started["state"], started["fence"], attempt["fence"]), ("ATTEMPT_ACTIVE", 1, 1))
        self.assertEqual(attempt["lease_expires_at"], (EPOCH + timedelta(seconds=120)).isoformat())
        self.assertEqual(attempt["state"], "ACTIVE")
        self.assertEqual(started["effect"], "EFFECT_UNKNOWN")
        self.assertEqual(len(self.authority.asked("attempt_start")), 1)
        self.assertRefused("ATTEMPT_ACTIVE", lambda: self.start(delivery["delivery_id"]))
        self.assertRefused("WRONG_ROLE", lambda: self.control.start_attempt(REQUESTER, delivery_id=delivery["delivery_id"]))
        self.assertEqual(self.state_of(delivery["delivery_id"])["fence"], 1)

    def test_two_claims_at_once_start_exactly_one_attempt(self) -> None:
        delivery = self.deliver()
        outcomes: list[str] = []
        barrier = threading.Barrier(4)

        def claim() -> None:
            barrier.wait()
            try:
                self.start(delivery["delivery_id"])
                outcomes.append("ok")
            except TaskControlError as exc:
                outcomes.append(exc.code)

        threads = [threading.Thread(target=claim) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(outcomes), ["ATTEMPT_ACTIVE"] * 3 + ["ok"])
        self.assertEqual(len(self.state_of(delivery["delivery_id"])["attempts"]), 1)
        self.assertEqual(len(self.authority.asked("attempt_start")), 1)

    def test_an_attempt_needs_the_authority_again_at_the_enforcement_point(self) -> None:
        delivery = self.deliver()
        self.authority.allowed.discard("attempt_start")
        self.assertRefused("AUTHORITY_DENIED", lambda: self.start(delivery["delivery_id"]))
        view = self.state_of(delivery["delivery_id"])
        self.assertEqual((view["state"], view["attempts"], view["fence"]), ("DELIVERED", [], 0))
        self.authority.allowed.add("attempt_start")
        self.assertEqual(self.start(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")

    def test_no_attempt_starts_from_a_workspace_that_is_not_observed_to_match_the_baseline(self) -> None:
        delivery = self.deliver()
        self.write_document("somebody else wrote this first\n")
        self.assertRefused("BASELINE_CHANGED", lambda: self.start(delivery["delivery_id"]))
        (self.world.plain / NEW_DOC).unlink()
        with mock.patch.object(self.gw, "file_digest", side_effect=RuntimeError("reader down")):
            self.assertRefused("BASELINE_UNOBSERVABLE", lambda: self.start(delivery["delivery_id"]))
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"], [])
        self.assertEqual(self.authority.asked("attempt_start"), [])
        self.assertEqual(self.start(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")

    def test_a_contract_that_was_altered_after_delivery_cannot_be_attempted(self) -> None:
        delivery = self.deliver()
        path = Path(self.gw.state_dir) / "contracts" / "control-task.json"
        stored = json.loads(path.read_text("utf-8"))
        stored["allowed_change_paths"].append("config.json")
        path.write_text(json.dumps(stored), encoding="utf-8")
        self.assertRefused("CONTRACT_MISMATCH", lambda: self.start(delivery["delivery_id"]))

    def test_the_lease_is_bounded(self) -> None:
        delivery = self.deliver()
        for lease in (0, 9, 3_601, 1.5, True, None):
            with self.subTest(lease=lease):
                self.assertRefused("INVALID_ARGUMENT", lambda: self.start(delivery["delivery_id"], lease_seconds=lease))

    def test_a_delivery_has_a_bounded_number_of_attempts(self) -> None:
        delivery = self.deliver()
        for _ in range(20):
            attempt = self.active_attempt(self.start(delivery["delivery_id"]))
            self.control.end_attempt(
                EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
                fence=attempt["fence"], outcome="FAILED_BEFORE_EFFECT",
            )
        self.assertRefused("ATTEMPT_LIMIT", lambda: self.start(delivery["delivery_id"]))


class TestResults(ControlWorld):
    def run_to_result(self, **overrides: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        payload = self.result_for(delivery, attempt, **overrides)
        return delivery, attempt, payload

    def test_a_result_is_observed_independently_and_read_back_by_the_original_requester(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        answer = self.submit(delivery, attempt, payload)
        self.assertFalse(answer["replayed"])
        self.assertEqual(answer["result_record"]["review"]["state"], "PASS")
        self.assertEqual(answer["delivery"]["state"], "RESULT_RECORDED")
        self.assertEqual(answer["delivery"]["effect"], "EFFECT_RECORDED_IN_RESULT")
        view = self.state_of(delivery["delivery_id"])
        self.assertEqual(view["viewer_role"], "requester")
        self.assertEqual(view["result"]["review_state"], "PASS")
        self.assertEqual(view["result"]["submitted_by"], EXECUTOR)
        self.assertEqual(view["result_record"]["review"]["readback"]["state"], "MATCH")
        self.assertEqual(view["result_record"]["review"]["business_acceptance"], "NOT_DETERMINED_BY_UAM")
        self.assertEqual(len(self.authority.asked("result_submit")), 1)
        self.assertEqual(self.control.inbox(EXECUTOR)["items"], [])

    def test_a_result_the_review_holds_is_recorded_and_shown_not_hidden(self) -> None:
        delivery, attempt, payload = self.run_to_result(text="what the executor says\n")
        # The executor claims content that is not on disk; the independent readback decides.
        (self.world.plain / NEW_DOC).write_text("something else\n", encoding="utf-8")
        answer = self.submit(delivery, attempt, payload)
        self.assertEqual(answer["result_record"]["review"]["state"], "HOLD")
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", answer["result_record"]["review"]["blockers"])
        view = self.state_of(delivery["delivery_id"])
        self.assertEqual((view["state"], view["result"]["review_state"]), ("RESULT_RECORDED", "HOLD"))
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", view["result"]["review_blockers"])

    def test_resending_the_same_result_after_a_lost_acknowledgement_changes_nothing(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        first = self.submit(delivery, attempt, payload)
        again = self.submit(delivery, attempt, payload)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["result_record"]["completed_at"], first["result_record"]["completed_at"])
        self.assertEqual(len(self.authority.asked("result_submit")), 1)
        self.assertEqual(len(list((Path(self.gw.state_dir) / "results-v2").glob("*.json"))), 1)
        different = self.result_for(delivery, attempt, result_id="ctl-result-2")
        self.assertRefused("RESULT_ALREADY_RECORDED", lambda: self.submit(delivery, attempt, different))
        changed = {**payload, "unresolved_risks": ["a late thought"]}
        self.assertRefused("RESULT_ALREADY_RECORDED", lambda: self.submit(delivery, attempt, changed))

    def test_a_result_stored_by_a_cut_off_call_is_adopted_not_duplicated_or_replaced(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        self.gw.results_v2.put(payload)  # the interrupted call stored it and never updated the delivery
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")
        answer = self.submit(delivery, attempt, payload)
        self.assertEqual(answer["delivery"]["state"], "RESULT_RECORDED")
        self.assertEqual(len(list((Path(self.gw.state_dir) / "results-v2").glob("*.json"))), 1)

    def test_a_result_id_that_already_holds_another_result_is_refused(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        other = {**payload, "unresolved_risks": ["different content under the same id"]}
        self.gw.results_v2.put(other)
        self.assertRefused("RESULT_ID_CONFLICT", lambda: self.submit(delivery, attempt, payload))
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")

    def test_a_result_that_does_not_belong_to_the_delivery_and_attempt_is_refused_before_it_is_stored(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        cases = {
            "attempt": {"attempt_ref": "attempt:somebody-else"},
            "contract": {"contract_id": "other-contract"},
            "digest": {"contract_digest": sha("other")},
            "executor": {"executor": STRANGER},
            "workspace": {"workspace_instance": derived_id("elsewhere")},
            "task": {"business_task_ref": "task-99"},
            "revision": {"task_revision": 9},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.assertRefused("RESULT_BINDING_MISMATCH", lambda: self.submit(delivery, attempt, {**payload, **change}))
        self.assertEqual(list((Path(self.gw.state_dir) / "results-v2").glob("*.json")), [])
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")

    def test_a_malformed_result_is_refused_and_leaves_the_attempt_open(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        self.assertRefused("RESULT_INVALID", lambda: self.submit(delivery, attempt, {**payload, "result_kind": "free-text"}))
        self.assertRefused("RESULT_INVALID", lambda: self.submit(delivery, attempt, {**payload, "surprise": 1}))
        self.assertRefused("INVALID_ARGUMENT", lambda: self.submit(delivery, attempt, "not an object"))
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"][-1]["state"], "ACTIVE")

    def test_the_authority_is_asked_again_when_the_result_is_submitted(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        self.authority.allowed.discard("result_submit")
        self.assertRefused("AUTHORITY_DENIED", lambda: self.submit(delivery, attempt, payload))
        self.assertEqual(list((Path(self.gw.state_dir) / "results-v2").glob("*.json")), [])
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"][-1]["state"], "ACTIVE")

    def test_only_the_recipient_submits_and_only_for_the_live_attempt_and_fence(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        self.assertRefused("WRONG_ROLE", lambda: self.control.submit_result(
            REQUESTER, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        ))
        self.assertRefused("FENCE_MISMATCH", lambda: self.control.submit_result(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"], fence=2, result=payload,
        ))
        self.assertRefused("NOT_FOUND", lambda: self.control.submit_result(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref="att-" + "0" * 24 + ".1",
            fence=1, result=payload,
        ))

    def test_a_superseded_attempt_cannot_deliver_a_result(self) -> None:
        delivery = self.deliver()
        stale = self.active_attempt(self.start(delivery["delivery_id"], lease_seconds=60))
        self.clock.advance(61)
        fresh = self.active_attempt(self.start(delivery["delivery_id"]))
        self.assertEqual((stale["fence"], fresh["fence"]), (1, 2))
        self.write_document()
        self.assertRefused("FENCE_MISMATCH", lambda: self.submit(delivery, stale, self.result_for(delivery, stale)))
        self.assertEqual(self.submit(delivery, fresh, self.result_for(delivery, fresh))["result_record"]["review"]["state"], "PASS")

    def test_a_patch_result_for_a_directory_contract_is_recorded_as_held(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        record = self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"])["contract"]
        payload = patch_result(record, "ctl-patch", "diff --git a/x b/x\n", {NEW_DOC: "x\n"},
                               attempt_ref=attempt["attempt_ref"], executor=EXECUTOR,
                               business_task_ref="task-42", task_revision=3)
        answer = self.submit(delivery, attempt, payload)
        self.assertEqual(answer["result_record"]["review"]["state"], "HOLD")
        self.assertIn("RESULT_KIND_NOT_APPLICABLE_TO_BASELINE", answer["result_record"]["review"]["blockers"])

    def test_after_a_result_there_is_no_further_attempt_and_no_blind_re_execution(self) -> None:
        delivery, attempt, payload = self.run_to_result()
        self.submit(delivery, attempt, payload)
        self.assertRefused("RESULT_ALREADY_RECORDED", lambda: self.start(delivery["delivery_id"]))
        self.assertRefused("ATTEMPT_NOT_ACTIVE", lambda: self.control.end_attempt(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="FAILED",
        ))


class TestEndingAnAttemptWithoutAResult(ControlWorld):
    def end(self, delivery: dict[str, Any], attempt: dict[str, Any], outcome: str = "FAILED_BEFORE_EFFECT") -> dict[str, Any]:
        return self.control.end_attempt(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome=outcome, note="could not continue",
        )

    def test_a_failure_before_any_effect_is_trusted_only_because_the_workspace_is_unchanged(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        ended = self.end(delivery, attempt)
        last = ended["attempts"][-1]
        self.assertEqual(last["end"]["effect"], "NO_EFFECT_OBSERVED")
        self.assertEqual(last["end"]["reported_outcome"], "FAILED_BEFORE_EFFECT")
        self.assertEqual(last["end"]["observation"]["state"], "UNCHANGED")
        self.assertEqual((ended["state"], ended["effect"]), ("DELIVERED", "NO_EFFECT_OBSERVED"))
        retry = self.active_attempt(self.start(delivery["delivery_id"]))
        self.assertEqual(retry["fence"], 2)

    def test_a_report_of_no_effect_does_not_outweigh_an_observed_change(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document("half done\n")
        ended = self.end(delivery, attempt)
        self.assertEqual(ended["attempts"][-1]["end"]["effect"], "PARTIAL_EFFECT_OBSERVED")
        self.assertEqual(ended["attempts"][-1]["end"]["reported_outcome"], "FAILED_BEFORE_EFFECT")
        self.assertEqual(ended["attempts"][-1]["end"]["observation"]["changed"], [NEW_DOC])
        self.assertEqual(ended["state"], "RECONCILIATION_REQUIRED")
        self.assertRefused("BASELINE_CHANGED", lambda: self.start(delivery["delivery_id"]))

    def test_an_effect_that_cannot_be_observed_is_unknown_and_blocks_the_next_attempt_until_it_can(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        with mock.patch.object(self.gw, "file_digest", side_effect=RuntimeError("reader down")):
            ended = self.end(delivery, attempt, "FAILED")
            self.assertEqual(ended["effect"], "EFFECT_UNKNOWN")
            self.assertEqual(ended["state"], "RECONCILIATION_REQUIRED")
            self.assertRefused("BASELINE_UNOBSERVABLE", lambda: self.start(delivery["delivery_id"]))
        retry = self.start(delivery["delivery_id"])
        self.assertEqual(self.active_attempt(retry)["fence"], 2)
        self.assertIn("RECONCILED_NO_EFFECT", [event["type"] for event in retry["events"]])

    def test_an_expired_lease_frees_the_delivery_without_claiming_that_nothing_happened(self) -> None:
        delivery = self.deliver()
        self.start(delivery["delivery_id"], lease_seconds=60)
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"][-1]["lease_expired"], False)
        self.clock.advance(61)
        self.assertEqual(self.state_of(delivery["delivery_id"])["attempts"][-1]["lease_expired"], True)
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "ATTEMPT_ACTIVE")  # reading closes nothing
        self.write_document("a stalled attempt left this behind\n")
        self.assertRefused("BASELINE_CHANGED", lambda: self.start(delivery["delivery_id"]))
        view = self.state_of(delivery["delivery_id"])
        first = view["attempts"][0]
        self.assertEqual((first["state"], first["end"]["how"], first["end"]["effect"]), ("ENDED", "LEASE_EXPIRED", "PARTIAL_EFFECT_OBSERVED"))
        self.assertEqual(view["state"], "RECONCILIATION_REQUIRED")

    def test_an_expired_lease_over_an_untouched_workspace_allows_exactly_one_new_attempt(self) -> None:
        delivery = self.deliver()
        self.start(delivery["delivery_id"], lease_seconds=60)
        self.clock.advance(61)
        retry = self.start(delivery["delivery_id"])
        self.assertEqual([item["state"] for item in retry["attempts"]], ["ENDED", "ACTIVE"])
        self.assertEqual(retry["attempts"][0]["end"]["effect"], "NO_EFFECT_OBSERVED")
        self.assertRefused("ATTEMPT_ACTIVE", lambda: self.start(delivery["delivery_id"]))

    def test_the_outcome_vocabulary_is_closed_and_the_attempt_must_be_the_live_one(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.assertRefused("INVALID_ARGUMENT", lambda: self.end(delivery, attempt, "SUCCEEDED"))
        self.assertRefused("FENCE_MISMATCH", lambda: self.control.end_attempt(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"], fence=7, outcome="FAILED",
        ))
        self.assertRefused("WRONG_ROLE", lambda: self.control.end_attempt(
            REQUESTER, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="FAILED",
        ))
        self.end(delivery, attempt)
        self.assertRefused("ATTEMPT_NOT_ACTIVE", lambda: self.end(delivery, attempt))


class TestCancel(ControlWorld):
    def cancel(self, delivery_id: str, principal: str = REQUESTER, reason: str = "no longer needed") -> dict[str, Any]:
        return self.control.cancel(principal, delivery_id=delivery_id, reason=reason)

    def test_cancelling_before_any_attempt_blocks_every_claim_and_says_nothing_was_started(self) -> None:
        delivery = self.deliver()
        answer = self.cancel(delivery["delivery_id"])
        self.assertEqual(answer["outcome"], "CANCELLED")
        self.assertEqual(answer["stop"], "NOT_APPLICABLE_NO_ATTEMPT")
        self.assertEqual(answer["rollback"], "NOT_PERFORMED_BY_UAM")
        self.assertEqual(answer["delivery"]["effect"], "NO_ATTEMPT_STARTED")
        self.assertEqual(answer["delivery"]["cancel"]["effect_evidence"]["state"], "UNCHANGED")
        self.assertRefused("CANCELLED", lambda: self.start(delivery["delivery_id"]))
        self.assertEqual(self.control.inbox(EXECUTOR)["items"], [])
        self.assertEqual(self.cancel(delivery["delivery_id"])["outcome"], "CANCEL_ALREADY_RECORDED")

    def test_cancelling_a_running_attempt_records_intent_and_confirms_nothing(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        answer = self.cancel(delivery["delivery_id"])
        self.assertEqual(answer["outcome"], "CANCEL_INTENT_RECORDED_ATTEMPT_ACTIVE")
        self.assertEqual((answer["intent"], answer["stop"]), ("RECORDED", "ATTEMPT_ACTIVE_NOT_CONFIRMED"))
        self.assertEqual(answer["delivery"]["state"], "ATTEMPT_ACTIVE")
        self.assertEqual(answer["delivery"]["effect"], "EFFECT_UNKNOWN")
        seen = self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"])
        self.assertEqual(seen["cancel"]["requested_by"], REQUESTER)
        ended = self.control.end_attempt(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="STOPPED",
        )
        self.assertEqual((ended["state"], ended["effect"]), ("CANCELLED", "NO_EFFECT_OBSERVED"))
        again = self.cancel(delivery["delivery_id"])
        self.assertEqual((again["outcome"], again["stop"]), ("CANCEL_ALREADY_RECORDED", "CONFIRMED_BY_RECEIVER"))

    def test_a_stop_report_over_a_changed_workspace_leaves_the_partial_effect_standing(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.cancel(delivery["delivery_id"])
        self.write_document("written before the stop\n")
        ended = self.control.end_attempt(
            EXECUTOR, delivery_id=delivery["delivery_id"], attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="STOPPED",
        )
        self.assertEqual((ended["state"], ended["effect"]), ("CANCELLED", "PARTIAL_EFFECT_OBSERVED"))

    def test_cancel_when_the_lease_has_run_out_is_finalized_but_not_taken_for_a_stop(self) -> None:
        delivery = self.deliver()
        self.start(delivery["delivery_id"], lease_seconds=60)
        self.clock.advance(61)
        answer = self.cancel(delivery["delivery_id"])
        self.assertEqual(answer["outcome"], "CANCELLED")
        self.assertEqual(answer["stop"], "NOT_CONFIRMED_LEASE_EXPIRED")
        self.assertEqual(answer["delivery"]["attempts"][0]["end"]["how"], "LEASE_EXPIRED")

    def test_when_the_result_wins_the_race_the_cancel_is_too_late_and_the_result_stands(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        self.submit(delivery, attempt, self.result_for(delivery, attempt))
        answer = self.cancel(delivery["delivery_id"])
        self.assertEqual(answer["outcome"], "TOO_LATE_RESULT_RECORDED")
        self.assertEqual(answer["intent"], "NOT_RECORDED")
        view = self.state_of(delivery["delivery_id"])
        self.assertEqual((view["state"], view["cancel"], view["result"]["review_state"]), ("RESULT_RECORDED", None, "PASS"))
        self.assertFalse(view["result"]["after_cancel_request"])

    def test_when_the_cancel_wins_the_race_a_result_that_still_arrives_is_kept_and_flagged(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.cancel(delivery["delivery_id"])
        self.write_document()
        answer = self.submit(delivery, attempt, self.result_for(delivery, attempt))
        self.assertEqual(answer["result_record"]["review"]["state"], "PASS")
        view = self.state_of(delivery["delivery_id"])
        self.assertEqual(view["state"], "RESULT_RECORDED")
        self.assertTrue(view["result"]["after_cancel_request"])
        self.assertEqual(view["cancel"]["requested_by"], REQUESTER)
        order = [event["type"] for event in view["events"]]
        self.assertEqual(order, ["DELIVERED", "ATTEMPT_STARTED", "CANCEL_INTENT", "RESULT_RECORDED"])

    def test_only_the_requester_cancels_and_a_stranger_learns_nothing(self) -> None:
        delivery = self.deliver()
        self.assertRefused("WRONG_ROLE", lambda: self.cancel(delivery["delivery_id"], principal=EXECUTOR))
        self.assertRefused("NOT_FOUND", lambda: self.cancel(delivery["delivery_id"], principal=STRANGER))
        self.assertRefused("INVALID_ARGUMENT", lambda: self.cancel(delivery["delivery_id"], reason="x" * 501))
        self.assertEqual(self.state_of(delivery["delivery_id"])["state"], "DELIVERED")

    def test_cancel_needs_no_authority_because_it_only_removes_effects(self) -> None:
        delivery = self.deliver()
        self.authority.allowed.clear()
        self.assertEqual(self.cancel(delivery["delivery_id"])["outcome"], "CANCELLED")


class TestReconnectAndAudit(ControlWorld):
    def test_every_party_reads_the_same_outcome_after_a_reconnect_of_the_server_and_the_gateway(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        self.submit(delivery, attempt, self.result_for(delivery, attempt))
        before = self.state_of(delivery["delivery_id"])
        gateway = MiddlewareGateway(str(self.world.registry_path), str(self.world.state))
        gateway.scopes.add_scope(self.world.scope())
        fresh = TaskControl(
            gateway.state_dir, contracts=gateway.contracts, results=gateway.results_v2,
            authority=self.authority, clock=self.clock, audit=gateway.audit,
        )
        after = fresh.get(REQUESTER, delivery_id=delivery["delivery_id"])
        self.assertEqual(after["result"], before["result"])
        self.assertEqual(after["events"], before["events"])
        self.assertEqual(after["result_record"]["review"]["state"], "PASS")
        self.assertEqual(fresh.get(EXECUTOR, delivery_id=delivery["delivery_id"])["state"], "RESULT_RECORDED")
        with self.assertRaises(TaskControlError) as refused:
            fresh.start_attempt(EXECUTOR, delivery_id=delivery["delivery_id"])
        self.assertEqual(refused.exception.code, "RESULT_ALREADY_RECORDED")

    def test_a_recipient_that_lost_its_attempt_reference_recovers_it_from_the_delivery(self) -> None:
        delivery = self.deliver()
        self.start(delivery["delivery_id"])
        self.assertRefused("ATTEMPT_ACTIVE", lambda: self.start(delivery["delivery_id"]))
        attempt = self.active_attempt(self.control.get(EXECUTOR, delivery_id=delivery["delivery_id"]))
        self.write_document()
        answer = self.submit(delivery, attempt, self.result_for(delivery, attempt))
        self.assertEqual(answer["result_record"]["review"]["state"], "PASS")

    def test_operations_are_audited_by_reference_without_authority_or_content(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        self.submit(delivery, attempt, self.result_for(delivery, attempt))
        audit = (Path(self.gw.state_dir) / "audit.jsonl").read_text("utf-8")
        entries = [json.loads(line) for line in audit.splitlines() if line.strip()]
        actions = [entry["action"] for entry in entries if entry["action"].startswith("task_control.")]
        self.assertEqual(actions, ["task_control.deliver", "task_control.start_attempt", "task_control.submit_result"])
        self.assertNotIn("grant-0001", audit)
        self.assertNotIn(NEW_TEXT.strip(), audit)
        self.assertNotIn(str(self.world.plain), audit)

    def test_a_denied_effect_is_audited_with_a_reason_code_and_never_the_verifiers_text_or_the_authority(self) -> None:
        def deliver(key: str) -> dict[str, Any]:
            return self.control.deliver(
                REQUESTER, contract_id="control-task", contract_digest=self.contract["contract_digest"],
                recipient=EXECUTOR, authority_ref="grant-0001", idempotency_key=key,
            )

        scenarios = (
            ("revoked", ScriptedAuthority(allow=set()), "REVOKED"),
            ("verifier failed", mock.Mock(verify=mock.Mock(side_effect=RuntimeError("issuer down /private/path"))), "VERIFIER_ERROR"),
            ("not a decision", mock.Mock(verify=mock.Mock(return_value=True)), "INVALID_DECISION"),
            ("free text reason", mock.Mock(verify=mock.Mock(return_value=AuthorityDecision(False, "not allowed: see /private/log"))), "UNSPECIFIED"),
        )
        for label, authority, expected in scenarios:
            with self.subTest(label):
                self.control = self.make_control(authority=authority)
                self.assertRefused("AUTHORITY_DENIED", lambda: deliver(f"denied-key-{label.replace(' ', '-')}"))
        audit = (Path(self.gw.state_dir) / "audit.jsonl").read_text("utf-8")
        entries = [json.loads(line) for line in audit.splitlines() if line.strip()]
        denials = [entry for entry in entries if entry["action"].startswith("task_control.")]
        self.assertEqual(
            [(entry["action"], entry["outcome"], entry["details"]["reason"]) for entry in denials],
            [("task_control.deliver", "DENY", expected) for _, _, expected in scenarios],
        )
        self.assertEqual({entry["details"]["principal"] for entry in denials}, {REQUESTER})
        self.assertEqual({entry["workspace_id"] for entry in denials}, {PLAIN_ID})
        for leaked in ("grant-0001", "/private/path", "/private/log", "issuer down"):
            self.assertNotIn(leaked, audit)

    def test_the_state_directory_holds_references_and_digests_not_content_or_secrets(self) -> None:
        delivery = self.deliver()
        attempt = self.active_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        self.submit(delivery, attempt, self.result_for(delivery, attempt))
        stored = "".join(path.read_text("utf-8") for path in self.control.root.rglob("*") if path.is_file())
        self.assertNotIn(NEW_TEXT.strip(), stored)
        self.assertNotIn(str(self.world.plain), stored)


class TestFailureAndClockHandling(ControlWorld):
    def test_a_naive_clock_is_refused_rather_than_guessed(self) -> None:
        control = self.make_control(clock=lambda: datetime(2026, 10, 28, 9, 0, 0))
        with self.assertRaises(UAMError):
            control.deliver(
                REQUESTER, contract_id="control-task", contract_digest=self.contract["contract_digest"],
                recipient=EXECUTOR, authority_ref="grant-0001", idempotency_key="naive-clock-key",
            )

    def test_a_foreign_file_in_the_state_directory_is_reported_not_skipped(self) -> None:
        self.deliver()
        (self.control.root / "deliveries" / ("dlv-" + "1" * 24 + ".json")).write_text('{"schema": "other"}', encoding="utf-8")
        self.assertRefused("INTERNAL", lambda: self.control.inbox(EXECUTOR))

    def test_the_default_construction_authorizes_nothing_at_all(self) -> None:
        control = TaskControl(self.gw.state_dir, contracts=self.gw.contracts, results=self.gw.results_v2)
        self.assertRefused("AUTHORITY_DENIED", lambda: control.deliver(
            REQUESTER, contract_id="control-task", contract_digest=self.contract["contract_digest"],
            recipient=EXECUTOR, authority_ref="grant-0001", idempotency_key="default-denied-1",
        ))

    def test_fixtures_are_consistent(self) -> None:
        self.assertEqual(file_state("x\n")["size_bytes"], 2)


if __name__ == "__main__":
    unittest.main()
