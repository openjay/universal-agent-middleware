"""What a receiver has to submit, written down where it reads the contract (``describe_result_contract``).

The result of an attempt is a free ``dict`` at the tool: ``uam_attempt_result`` says only 'a result object'. A receiver that
does not already know the versioned, kind-specific contract of ``uam-result-v2`` learned it by being refused, field by
field. The existing contract read (``uam_delivery_get`` / ``TaskControl.get``) now also gives the recipient a
``result_contract``: per applicable kind the required fields with their rules, and one template with every value the
delivery fixes already filled in and every other value an explicit ``<...>`` slot, listed in ``fill_in``.

This is a description and nothing else. These tests pin that it says what ``validate_submission`` and the review enforce
(not a second protocol, no relaxed rule), that an unfilled or altered template is refused exactly as before, that only the
recipient with the right to read content receives it, and that a result built from it is recorded through the real
entry points (the library and the SDK's own MCP client). The frozen tool surface is pinned elsewhere
(``test_mcp_task_continuity.py::TestSurface``): no tool, argument or description changes.
"""
from __future__ import annotations

import copy
import hashlib
import unittest
from typing import Any

from universal_agent_middleware.contracts import BASELINE_FILE_DIGESTS, BASELINE_GIT_HEAD, ContractBinding
from universal_agent_middleware.errors import ContractError
from universal_agent_middleware import results_v2
from universal_agent_middleware.results_v2 import KIND_DOCUMENT, KIND_NO_CHANGE, KIND_PATCH, RESULT_KINDS, validate_submission

from continuity_support import EXECUTOR, NEW_DOC, REQUESTER
from test_mcp_task_continuity import ContinuityAdapterWorld

FALLBACK_NOTE = "see results_v2.validate_submission"
DIRECTORY = {
    "kind": BASELINE_FILE_DIGESTS,
    "files": {"inputs/spec.md": {"sha256": "a" * 64, "size_bytes": 5}, "notes/new.md": {"absent": True}},
}
REPOSITORY = {"kind": BASELINE_GIT_HEAD, "revision": "b" * 40}
PATCH_TEXT = "diff --git a/notes/new.md b/notes/new.md\n"


def binding(baseline: dict[str, Any]) -> ContractBinding:
    return ContractBinding(
        contract_id="c-1", contract_version="uam-execution-contract-v2", profile="workspace-change-v2", workspace_id="ws-main",
        baseline=baseline, authoritative_paths=("inputs/spec.md",), allowed_change_paths=("notes/new.md",),
        verification_commands=("true", "make check"), readiness_state="READY", readiness_blockers=(), digest="d" * 64,
    )


def describe(baseline: dict[str, Any], **known: Any) -> dict[str, Any]:
    return results_v2.describe_result_contract(binding(baseline), business_task_ref="task-1", task_revision=3, executor="executor-c", **known)


def complete(
    description: dict[str, Any], kind: str, *, written: tuple[str, str, int] = ("notes/new.md", "c" * 64, 3),
) -> dict[str, Any]:
    """The template of ``kind`` with exactly the slots ``fill_in`` lists replaced by real values and nothing else touched.
    A slot name this table does not know is a ``KeyError``: the description would be naming something nobody can fill."""
    payload = copy.deepcopy(description["templates"][kind])
    path, sha256, size = written
    values: dict[str, Any] = {
        "result_id": "res-completed-1", "attempt_ref": "att-" + "b" * 24 + ".1", "rationale": "nothing was changed",
        "verification_receipts": [{**receipt, "exit_code": 0, "evidence": "ran"} for receipt in payload["verification_receipts"]],
        "artifacts": [{"path": path, "sha256": sha256, "size_bytes": size}],
        "patch": PATCH_TEXT, "patch_digest": hashlib.sha256(PATCH_TEXT.encode("utf-8")).hexdigest(),
        "changed_paths": [path], "post_image_digests": {path: {"sha256": sha256, "size_bytes": size}},
    }
    for name in description["fill_in"][kind]:
        payload[name] = values[name]
    return payload


class DescriptionAgainstTheValidatorTest(unittest.TestCase):
    def test_a_template_completed_as_described_is_a_submission_the_validator_accepts_for_every_kind(self) -> None:
        for label, baseline, kinds in (
            ("directory workspace", DIRECTORY, {KIND_DOCUMENT, KIND_NO_CHANGE}),
            ("git repository", REPOSITORY, {KIND_PATCH, KIND_NO_CHANGE}),
        ):
            with self.subTest(label):
                description = describe(baseline)
                self.assertEqual((set(description["templates"]), set(description["kinds"])), (kinds, kinds))
                self.assertEqual(set(description["not_applicable_kinds"]), set(RESULT_KINDS) - kinds)
                for kind in kinds:
                    self.assertEqual(validate_submission(complete(description, kind))["result_kind"], kind)

    def test_the_described_fields_are_exactly_the_fields_the_validator_requires(self) -> None:
        for baseline in (DIRECTORY, REPOSITORY):
            description = describe(baseline)
            for kind in description["templates"]:
                with self.subTest(f"{baseline['kind']} / {kind}"):
                    completed = complete(description, kind)
                    for field in completed:  # a field the validator did not need would not be refused when it is missing
                        without = {name: value for name, value in completed.items() if name != field}
                        refusal = "unsupported result_(version|kind)" if field in ("result_version", "result_kind") else "missing result fields"
                        with self.assertRaisesRegex(ContractError, refusal):
                            validate_submission(without)
                    with self.assertRaisesRegex(ContractError, "unknown result fields"):
                        validate_submission({**completed, "summary": "done"})
                    notes = {**description["common_fields"], **description["kinds"][kind]["fields"]}
                    self.assertEqual(set(notes), set(completed), "one note per field, none for a field that does not exist")
                    self.assertNotIn(FALLBACK_NOTE, notes.values(), "every field has a note of its own")

    def test_a_template_that_was_not_filled_in_is_never_a_valid_submission(self) -> None:
        for baseline in (DIRECTORY, REPOSITORY):
            description = describe(baseline)
            for kind, template in description["templates"].items():
                with self.subTest(f"{baseline['kind']} / {kind}"):
                    with self.assertRaises(ContractError):
                        validate_submission(template)

    def test_what_the_delivery_fixes_is_filled_in_and_only_the_rest_is_a_slot(self) -> None:
        before = describe(DIRECTORY)
        template = before["templates"][KIND_DOCUMENT]
        self.assertEqual(
            (template["result_version"], template["business_task_ref"], template["task_revision"], template["executor"]),
            ("uam-result-v2", "task-1", 3, "executor-c"),
        )
        self.assertEqual(
            (template["contract_id"], template["contract_digest"], template["workspace_instance"]), ("c-1", "d" * 64, "ws-main"),
        )
        self.assertEqual(template["source_digests"], {"inputs/spec.md": DIRECTORY["files"]["inputs/spec.md"]})
        self.assertEqual([item["command"] for item in template["verification_receipts"]], ["true", "make check"])
        self.assertEqual(before["fill_in"][KIND_DOCUMENT], ["artifacts", "attempt_ref", "result_id", "verification_receipts"])
        self.assertEqual(before["fill_in"][KIND_NO_CHANGE], ["attempt_ref", "rationale", "result_id", "verification_receipts"])
        self.assertEqual(before["templates"][KIND_NO_CHANGE]["baseline"], DIRECTORY)
        after = describe(DIRECTORY, attempt_ref="att-" + "e" * 24 + ".2", result_id="res-known-2")
        self.assertEqual(after["fill_in"][KIND_DOCUMENT], ["artifacts", "verification_receipts"])
        self.assertEqual(after["fill_in"][KIND_NO_CHANGE], ["rationale", "verification_receipts"])
        self.assertEqual((after["templates"][KIND_DOCUMENT]["attempt_ref"], after["templates"][KIND_DOCUMENT]["result_id"]), ("att-" + "e" * 24 + ".2", "res-known-2"))

    def test_the_description_shares_no_data_with_the_contract_it_was_read_from(self) -> None:
        baseline = copy.deepcopy(DIRECTORY)
        first = describe(baseline)
        first["templates"][KIND_NO_CHANGE]["baseline"]["files"].clear()
        first["templates"][KIND_DOCUMENT]["source_digests"].clear()
        self.assertEqual(baseline, DIRECTORY, "editing a template must not edit the contract's baseline")
        self.assertEqual(describe(baseline)["templates"][KIND_NO_CHANGE]["baseline"], DIRECTORY)


class ResultContractAtTheEntryTest(ContinuityAdapterWorld):
    def written(self) -> tuple[str, str, int]:
        data = (self.world.plain / NEW_DOC).read_bytes()
        return NEW_DOC, hashlib.sha256(data).hexdigest(), len(data)

    def test_only_the_recipient_reads_it_and_it_names_the_active_attempt_once_there_is_one(self) -> None:
        delivery_id = self.deliver()["delivery_id"]
        contract = self.state_of(delivery_id, EXECUTOR)["contract"]
        seen = self.state_of(delivery_id, EXECUTOR)["result_contract"]
        self.assertNotIn("result_contract", self.state_of(delivery_id, REQUESTER))
        self.assertEqual((set(seen["kinds"]), set(seen["not_applicable_kinds"])), ({KIND_DOCUMENT, KIND_NO_CHANGE}, {KIND_PATCH}))
        template = seen["templates"][KIND_DOCUMENT]
        self.assertEqual(
            (template["contract_id"], template["contract_digest"], template["workspace_instance"], template["executor"]),
            (contract["contract_id"], contract["contract_digest"], contract["workspace_id"], EXECUTOR),
        )
        self.assertTrue(template["attempt_ref"].startswith("<") and template["result_id"].startswith("<"), "no attempt yet: slots")
        attempt = self.last_attempt(self.start(delivery_id))
        started = self.state_of(delivery_id, EXECUTOR)["result_contract"]["templates"][KIND_DOCUMENT]
        self.assertEqual((started["attempt_ref"], started["result_id"]), (attempt["attempt_ref"], f"res-{delivery_id[4:]}-{attempt['fence']}"))

    def test_content_that_is_withheld_carries_no_result_contract_and_readable_content_does(self) -> None:
        delivery_id = self.deliver()["delivery_id"]
        self.authority.effects.discard("dereference")
        withheld = self.state_of(delivery_id, EXECUTOR)
        self.assertEqual(withheld["content_withheld"]["code"], "AUTHORITY_DENIED")
        self.assertTrue({"contract", "result_contract"}.isdisjoint(withheld))
        self.authority.effects.add("dereference")
        readable = self.state_of(delivery_id, EXECUTOR)
        self.assertTrue({"contract", "result_contract"}.issubset(readable))

    def test_a_document_result_built_from_the_description_is_recorded_and_passes_its_review(self) -> None:
        delivery = self.deliver()
        attempt = self.last_attempt(self.start(delivery["delivery_id"]))
        self.write_document()
        description = self.state_of(delivery["delivery_id"], EXECUTOR)["result_contract"]
        answer = self.submit(delivery, attempt, complete(description, KIND_DOCUMENT, written=self.written()))
        self.assertEqual(answer["result_record"]["review"]["state"], "PASS", answer["result_record"]["review"])
        self.assertEqual(self.state_of(delivery["delivery_id"], EXECUTOR)["state"], "RESULT_RECORDED")

    def test_a_no_change_result_built_from_the_description_is_recorded_and_passes_its_review(self) -> None:
        delivery = self.deliver()
        attempt = self.last_attempt(self.start(delivery["delivery_id"]))
        description = self.state_of(delivery["delivery_id"], EXECUTOR)["result_contract"]
        answer = self.submit(delivery, attempt, complete(description, KIND_NO_CHANGE))
        self.assertEqual(answer["result_record"]["review"]["state"], "PASS", answer["result_record"]["review"])
        self.assertEqual(answer["result_record"]["result_kind"], KIND_NO_CHANGE)

    def test_a_template_that_is_unfilled_or_altered_is_refused_as_before_and_the_attempt_stays_open(self) -> None:
        delivery = self.deliver()
        delivery_id = delivery["delivery_id"]
        attempt = self.last_attempt(self.start(delivery_id))
        self.write_document()
        description = self.state_of(delivery_id, EXECUTOR)["result_contract"]
        good = complete(description, KIND_DOCUMENT, written=self.written())
        refused: tuple[tuple[str, dict[str, Any], str], ...] = (
            ("the template as read", description["templates"][KIND_DOCUMENT], "RESULT_INVALID"),
            ("an unknown field", {**good, "summary": "done"}, "RESULT_INVALID"),
            ("a field of another kind", {**good, "rationale": "x"}, "RESULT_INVALID"),
            ("a missing field", {name: value for name, value in good.items() if name != "source_digests"}, "RESULT_INVALID"),
            ("an id that is not an id", {**good, "result_id": "x"}, "RESULT_INVALID"),
            ("another contract's digest", {**good, "contract_digest": "f" * 64}, "RESULT_BINDING_MISMATCH"),
        )
        for label, payload, code in refused:
            with self.subTest(label):
                self.assertRefused(code, lambda payload=payload: self.submit(delivery, attempt, payload))
                self.assertEqual(self.state_of(delivery_id, EXECUTOR)["state"], "ATTEMPT_ACTIVE")
        recorded = self.submit(delivery, attempt, good)  # nothing the refusals did used the attempt up
        self.assertEqual(recorded["result_record"]["review"]["state"], "PASS")

    def test_the_description_and_the_result_it_describes_travel_over_the_standard_protocol(self) -> None:
        delivery_id = self.delivered()
        read = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        self.assertFalse(read.is_error, read.text)
        self.assertEqual(read.body["result_contract"]["describes"], "uam-result-v2")
        self.assertNotIn("result_contract", self.call(self.requester, "uam_delivery_get", delivery_id=delivery_id).body)
        attempt = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id).body["attempts"][-1]
        self.write_document()
        description = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id).body["result_contract"]
        arguments = {"delivery_id": delivery_id, "attempt_ref": attempt["attempt_ref"], "fence": attempt["fence"]}
        unfilled = self.call(self.executor, "uam_attempt_result", result=description["templates"][KIND_DOCUMENT], **arguments)
        self.assertEqual((unfilled.is_error, unfilled.body["error_code"]), (True, "RESULT_INVALID"))
        recorded = self.call(self.executor, "uam_attempt_result", result=complete(description, KIND_DOCUMENT, written=self.written()), **arguments)
        self.assertFalse(recorded.is_error, recorded.text)
        self.assertEqual(recorded.body["result_record"]["review"]["state"], "PASS")


if __name__ == "__main__":
    unittest.main()
