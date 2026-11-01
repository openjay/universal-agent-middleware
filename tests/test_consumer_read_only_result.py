"""A read-only task, in UAM's own words: what the Consumer may send when nothing was meant to change.

Before this, every job that changed none of its allowed paths ended as ``FAILED / NO_ALLOWED_PATH_CHANGED`` and only
``document-artifact-v1`` could be built, so a legitimate read-only task (an audit, a review, a read-back) could never be
recorded. UAM already has the kind for it, ``no-change-v1`` (a rationale and the contract's own baseline), and it reads the
workspace back itself. The Consumer uses it only when the CONTRACT says so: ``expected_changes`` is exactly ``["none"]``.
Any other contract keeps the document-artifact rules, so ``no-change-v1`` is not a way around them, and a read-only task
that changed a file is failed, never reported as 'no change'.

The test worker (``consumer_worker.py``, mode ``noop``/``write``) is a stand-in executor. No model runs here.
"""
from __future__ import annotations

import json
import unittest
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from universal_agent_middleware import consumer as consumer_module
from universal_agent_middleware.harness_adapter import DONE, ExecutorHandle, HarnessJob, HarnessOutcome

from consumer_world import deliver, rule_for
from coordination_fixtures import contract_v2
from test_consumer import ConsumerCase

IDLE = {"idle": {"UAM_TEST_MODE": "noop"}}
SPEC = "inputs/spec.md"
NO_CHANGE = "no-change-v1"
# What the delivery fixes is already in the description a recipient reads; the rest is the receiver's to fill in.
FIXED_BY_THE_DELIVERY = (
    "result_version", "result_kind", "business_task_ref", "task_revision", "contract_id", "contract_digest",
    "workspace_instance", "executor", "baseline", "unresolved_risks",
)


class EditsTheWorkspace:
    """A stand-in executor that edits one workspace file the contract did not allow to change, and reports DONE."""

    name, is_agent, needs_session = "edits-workspace", False, False

    def __init__(self, action: str, relative: str = SPEC) -> None:
        self.action, self.relative = action, relative

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        target = Path(job.cwd) / self.relative
        if self.action == "delete":
            target.unlink()
        else:
            target.write_text("changed by the executor\n", encoding="utf-8")
        return HarnessOutcome(DONE, "STUB_DONE", "", True, self.name)


class ReadOnlyResultTest(ConsumerCase):
    def contract_task(self, name: str, expected: Sequence[str] | None = None) -> str:
        overrides = {} if expected is None else {"expected_changes": list(expected)}
        contract = self.world.gateway.create_contract(contract_v2(
            f"c-{name}", "ws-main", authoritative=[SPEC], allowed=[f"out/{name}.md"], verification=["true"], **overrides,
        ))
        return deliver(self.control, contract, task=name)["delivery_id"]

    def prepared(self, delivery_id: str) -> dict[str, Any]:
        return json.loads(next(self.work.glob(f"jobs/{delivery_id}/*/result.json")).read_text(encoding="utf-8"))

    def assertFailedWithoutResult(self, delivery_id: str, note: str, *, state: str = "DELIVERED") -> dict[str, Any]:
        view = self.view(delivery_id)
        attempt = view["attempts"][-1]
        self.assertEqual((view["state"], view["result"], attempt["state"], attempt["end"]["how"]), (state, None, "ENDED", "REPORTED"))
        ended = [record for record in self.records(delivery_id) if record["phase"] == "ATTEMPT_ENDED"]
        self.assertEqual([(record["reported_outcome"], record["note"]) for record in ended], [("FAILED", note)])
        self.assertTrue({"RESULT_PREPARED", "RESULT_SUBMITTED"}.isdisjoint(self.phases(delivery_id)))
        return view

    def test_a_task_that_expects_no_change_is_recorded_as_a_no_change_result_when_nothing_changed(self) -> None:
        delivery_id = self.contract_task("t-ro", ["none"])
        rules = [rule_for(self.world, "t-ro", "idle")]
        described = self.view(delivery_id)["result_contract"]["templates"][NO_CHANGE]  # what the recipient reads before it starts
        self.run_idle(self.consumer(rules, workers=IDLE))
        view = self.view(delivery_id)
        self.assertEqual((view["state"], view["result"]["review_state"], view["result"]["review_blockers"]), ("RESULT_RECORDED", "PASS", []))
        record = view["result_record"]
        self.assertEqual((record["result_kind"], record["baseline"]), (NO_CHANGE, view["contract"]["baseline"]))
        self.assertIn("Read-only task", record["rationale"])
        self.assertIn("not the executor's own conclusion", record["rationale"], "it says who observed what, and claims nothing more")
        self.assertEqual(record["readback"]["state"], "MATCH", "UAM read the workspace back itself")
        self.assertFalse((self.world.workspace() / "out/t-ro.md").exists())
        self.assertEqual(len(self.executions()), 1)
        self.assertNotIn("NO_ALLOWED_PATH_CHANGED", [record.get("note") for record in self.records(delivery_id)])
        sent = self.prepared(delivery_id)  # the bytes the Consumer sent have the fields UAM's own description lists
        self.assertEqual(set(sent), set(described))
        self.assertEqual({name: sent[name] for name in FIXED_BY_THE_DELIVERY}, {name: described[name] for name in FIXED_BY_THE_DELIVERY})
        self.assertEqual([item["command"] for item in sent["verification_receipts"]], [item["command"] for item in described["verification_receipts"]])

    def test_a_read_only_task_whose_files_changed_is_failed_and_sends_no_result(self) -> None:
        scenarios: tuple[tuple[str, dict[str, Any], list[str]], ...] = (
            ("an allowed path was written", {"workers": {"write": {}}}, ["out/t-ro-0.md"]),
            ("an authoritative file was changed", {"adapters": {"edits-workspace": EditsTheWorkspace("modify")}}, [SPEC]),
            ("an authoritative file was deleted", {"adapters": {"edits-workspace": EditsTheWorkspace("delete")}}, [SPEC]),
        )
        for number, (label, options, differing) in enumerate(scenarios):
            with self.subTest(label):
                name = f"t-ro-{number}"
                delivery_id = self.contract_task(name, ["none"])
                rule = rule_for(self.world, name, "write")
                rules = [{**rule, "adapter": "edits-workspace"} if "adapters" in options else rule]
                self.run_idle(self.consumer(rules, **options))
                # UAM's own reading of the same facts: the workspace is not the baseline, so the delivery needs reconciliation
                view = self.assertFailedWithoutResult(delivery_id, "READ_ONLY_TASK_CHANGED_FILES", state="RECONCILIATION_REQUIRED")
                self.assertEqual(view["effect"], "PARTIAL_EFFECT_OBSERVED")
                ended = next(record for record in self.records(delivery_id) if record["phase"] == "ATTEMPT_ENDED")
                self.assertEqual(ended["differing"], differing)

    def test_any_other_contract_keeps_the_document_artifact_rule_that_nothing_changed_is_a_failure(self) -> None:
        wordings: tuple[tuple[str, Sequence[str] | None], ...] = (
            ("the default contract of the fixtures", None),
            ("another wording of the same idea", ["no changes"]),
            ("none beside something else", ["none", "the allowed path holds a note"]),
            ("a declaration that names no change at all", []),
        )
        for number, (label, expected) in enumerate(wordings):
            with self.subTest(label):
                name = f"t-doc-{number}"
                delivery_id = self.contract_task(name, expected)
                self.run_idle(self.consumer([rule_for(self.world, name, "idle")], workers=IDLE))
                self.assertFailedWithoutResult(delivery_id, "NO_ALLOWED_PATH_CHANGED")

    def test_only_a_contract_that_says_none_and_nothing_else_is_read_only(self) -> None:
        for expected, read_only in (
            (["none"], True), ([" None "], True), (["NONE"], True),
            ([], False), (["none", "none"], False), (["none", "x"], False), (["nothing"], False), ([None], False), ("none", False),
        ):
            with self.subTest(str(expected)):
                self.assertIs(consumer_module.declares_no_change({"expected_changes": expected}), read_only)
        self.assertIs(consumer_module.declares_no_change({}), False)


if __name__ == "__main__":
    unittest.main()
