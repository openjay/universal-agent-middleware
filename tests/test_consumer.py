"""The resident Consumer, over the real Task / Inbox / Attempt / Result surface of UAM (``ContinuityControl``).

Authority here is a TEST STAND-IN (``consumer_authority_factory``): it checks what the port carries and nothing
else, so these tests show how the Consumer *uses* the surface (default deny, nothing guessed, UAM's gates kept, no
redo, targets locked, recovery from files), not that any real authority allows a real task. Executors are real
operating-system processes of the test worker; no model is involved and the local-command adapter is labelled as
no Agent. Crash and restart with real kills are run by the scenario scripts of this slice, not here.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from universal_agent_middleware.consumer import (
    Consumer,
    Journal,
    PolicySource,
    SingleInstance,
    TargetLocks,
)
from universal_agent_middleware.consumer_cli import main
from universal_agent_middleware.harness_adapter import (
    DONE,
    CommandSpec,
    ExecutorHandle,
    HarnessJob,
    HarnessOutcome,
    LocalCommandAdapter,
    cursor_cli_adapter,
    cursor_sdk_adapter,
)
from universal_agent_middleware.task_control import AuthorityDecision, AuthorityRequest

from consumer_authority_factory import StandInAuthority
from consumer_world import (
    CONSUMER,
    ENDPOINT,
    REQUESTER,
    WORKER_SCRIPT,
    build_world,
    create_contract,
    deliver,
    make_control,
    policy_document,
    rule_for,
    stand_in_control,
    worker_env,
    write_json_private,
)

AUTHORITY_FACTORY = Path(__file__).resolve().parent / "consumer_authority_factory.py"


class ScriptedInbox:
    """The control object with an inbox that fails or reports truncation on demand (everything else passes through)."""

    def __init__(self, real: Any, *, failures: int = 0, truncated: bool = False) -> None:
        self._real = real
        self.failures = failures
        self.truncated = truncated

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def inbox(self, *args: Any, **kwargs: Any) -> Any:
        if self.failures:
            self.failures -= 1
            raise OSError("the state directory is busy")
        answer = self._real.inbox(*args, **kwargs)
        return {**answer, "truncated": self.truncated or answer.get("truncated", False)}


class SessionAgent:
    """An agent-like adapter stub (needs a session) that only records that it was run."""

    name = "session-agent"
    is_agent = True
    needs_session = True

    def __init__(self) -> None:
        self.runs: list[HarnessJob] = []

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        self.runs.append(job)
        return HarnessOutcome("REFUSED", "STUB", "records the call only", True, self.name)


class BoundAgent:
    """An agent-like adapter stub that writes the one allowed file and reports the *actual* session it saw (as the Codex
    adapter does). The Consumer must carry that binding into its journal, the outcome file and the submitted record."""

    name = "bound-agent"
    is_agent = True
    needs_session = True

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        gone = subprocess.Popen(["/usr/bin/true"], start_new_session=True)  # a process group that no longer exists
        gone.wait()
        binding = {
            "adapter": self.name, "declared": {"session": job.session, "cwd": job.cwd},
            "observed": {"thread_id": "thr-actual", "turn_id": "turn-actual", "thread_cwd": job.cwd},
        }
        on_started(ExecutorHandle("stub", gone.pid, gone.pid, "now", binding={**binding, "observed": {"thread_id": "thr-actual"}}))
        target = Path(job.cwd) / job.allowed_change_paths[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("written by the stub\n", encoding="utf-8")
        return HarnessOutcome(DONE, "STUB_DONE", "", True, self.name, binding=binding)


class LeftBehind:
    """An adapter whose executor outlives the call: it reports a live process group and no stop."""

    name = "left-behind"
    is_agent = False
    needs_session = False

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        on_started(ExecutorHandle("process-group", self.process.pid, self.process.pid, "now"))
        return HarnessOutcome("UNKNOWN", "EXECUTOR_TIMEOUT", "it was not stopped", False, self.name)


class DenyStart(StandInAuthority):
    """A stand-in authority that has revoked the right to start an attempt (everything else as the stand-in)."""

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        if request.effect == "attempt_start":
            return AuthorityDecision(False, "REVOKED")
        return super().verify(request)


class ConsumerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="uam-consumer-")).resolve()
        if not os.environ.get("UAM_KEEP_TEST_WORLDS"):
            self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.world = build_world(self.root / "world")
        self.evidence = self.root / "evidence"
        self.authority_log = self.root / "authority.jsonl"
        self.control = stand_in_control(self.world, str(self.authority_log))
        self.work = self.root / "consumer-work"

    # -- builders ---------------------------------------------------------------------------------------------------

    def task(self, name: str, *, allowed: Sequence[str] | None = None, verification: Sequence[str] = ("true",)) -> str:
        contract = create_contract(self.world, f"c-{name}", allowed=allowed or [f"out/{name}.md"], verification=verification)
        return deliver(self.control, contract, task=name)["delivery_id"]

    def consumer(
        self, rules: Sequence[Mapping[str, Any]], *, workers: Mapping[str, Mapping[str, str]] | None = None,
        adapters: Mapping[str, Any] | None = None, authority: Any = False, **options: Any,
    ) -> Consumer:
        policy = write_json_private(self.root / "policy.json", policy_document(rules))
        local = LocalCommandAdapter({
            name: CommandSpec(argv=(sys.executable, str(WORKER_SCRIPT)), max_seconds=60, env=worker_env(self.evidence, **env))
            for name, env in (workers or {"write": {}}).items()
        })
        registered = {"local-command": local, "cursor-cli": cursor_cli_adapter(), "cursor-sdk": cursor_sdk_adapter(), **(adapters or {})}
        control = self.control if authority is False else make_control(self.world, authority)
        options.setdefault("backoff_seconds", 0.0)
        return Consumer(
            control=control, gateway=self.world.gateway, principal=CONSUMER, policy=PolicySource(policy),
            adapters=registered, work_dir=self.work, **options,
        )

    def run_idle(self, consumer: Consumer) -> None:
        consumer.run_until_idle(poll_seconds=0.02, max_seconds=60)

    def view(self, delivery_id: str) -> dict[str, Any]:
        return self.control.get(CONSUMER, delivery_id=delivery_id)

    def records(self, delivery_id: str | None = None) -> list[dict[str, Any]]:
        path = self.work / "journal.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
        return [record for record in lines if delivery_id is None or record.get("delivery_id") == delivery_id]

    def phases(self, delivery_id: str) -> list[str]:
        return [record["phase"] for record in self.records(delivery_id)]

    def codes(self, delivery_id: str) -> list[str]:
        return [str(record.get("code")) for record in self.records(delivery_id) if "code" in record]

    def executions(self) -> list[str]:
        log = self.evidence / "executions.log"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def authority_effects(self) -> list[tuple[str, bool]]:
        lines = self.authority_log.read_text(encoding="utf-8").splitlines() if self.authority_log.exists() else []
        return [(entry["effect"], entry["allowed"]) for entry in map(json.loads, lines)]

    @staticmethod
    def wait_until(predicate: Callable[[], bool], timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        raise AssertionError("condition not reached in time")

    def assertNeverStarted(self, delivery_id: str) -> None:
        self.assertEqual(self.view(delivery_id)["attempts"], [])
        self.assertNotIn("ATTEMPT_STARTED", self.phases(delivery_id))
        self.assertEqual(self.executions(), [])


class DefaultDenyTest(ConsumerCase):
    def test_a_delivery_without_a_rule_is_journalled_once_and_never_started(self) -> None:
        delivery_id = self.task("t-norule")
        self.run_idle(self.consumer([]))
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.view(delivery_id)["state"], "DELIVERED")
        self.assertEqual(self.phases(delivery_id), ["DENIED"])
        self.assertEqual(self.codes(delivery_id), ["NO_RULE"])
        self.assertFalse((self.world.workspace() / "out").exists())

    def test_a_rule_for_another_task_does_not_cover_this_one(self) -> None:
        delivery_id = self.task("t-mine")
        self.run_idle(self.consumer([rule_for(self.world, "t-someone-elses", "write")]))
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.codes(delivery_id), ["NO_RULE"])

    def test_cwd_is_required_absolute_and_the_workspace_root_never_guessed(self) -> None:
        for label, change, code in (
            ("missing", {"cwd": None}, "CWD_REQUIRED"),
            ("relative", {"cwd": "."}, "CWD_REQUIRED"),
            ("elsewhere", {"cwd": str(self.root)}, "CWD_MISMATCH"),
        ):
            with self.subTest(label):
                name = f"t-cwd-{label}"
                delivery_id = self.task(name)
                self.run_idle(self.consumer([{**rule_for(self.world, name, "write"), **change}]))
                self.assertNeverStarted(delivery_id)
                self.assertEqual(self.codes(delivery_id), [code])

    def test_an_adapter_that_needs_a_session_is_refused_without_one_and_runs_with_one(self) -> None:
        agent = SessionAgent()
        delivery_id = self.task("t-session")
        base = {**rule_for(self.world, "t-session", "write"), "adapter": "session-agent"}
        self.run_idle(self.consumer([base], adapters={"session-agent": agent}))
        self.assertEqual((self.codes(delivery_id), agent.runs), (["SESSION_REQUIRED"], []))
        self.assertEqual(self.view(delivery_id)["attempts"], [])
        self.run_idle(self.consumer([{**base, "session": "new"}], adapters={"session-agent": agent}))
        self.assertEqual(len(agent.runs), 1)
        self.assertEqual(agent.runs[0].session, "new")
        self.assertEqual(agent.runs[0].cwd, str(self.world.workspace().resolve()))

    def test_an_unavailable_agent_interface_holds_the_delivery_without_an_attempt(self) -> None:
        for adapter, code in (("cursor-cli", "UNSUPPORTED:CURSOR_CLI_UNAVAILABLE"), ("cursor-sdk", "AUTH_REQUIRED:CURSOR_SDK_NEEDS_NEW_AUTH")):
            with self.subTest(adapter):
                name = f"t-{adapter}"
                delivery_id = self.task(name)
                self.run_idle(self.consumer([{**rule_for(self.world, name, "write"), "adapter": adapter, "session": "new"}]))
                self.assertNeverStarted(delivery_id)
                self.assertEqual((self.phases(delivery_id), self.codes(delivery_id)), (["HOLD"], [code]))

    def test_a_verification_command_that_is_not_allow_listed_is_never_run(self) -> None:
        delivery_id = self.task("t-verify", verification=("true", "echo surprise"))
        self.run_idle(self.consumer([rule_for(self.world, "t-verify", "write")]))
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.codes(delivery_id), ["VERIFICATION_NOT_ALLOWLISTED"])

    def test_a_worker_that_is_not_registered_is_denied(self) -> None:
        delivery_id = self.task("t-worker")
        self.run_idle(self.consumer([rule_for(self.world, "t-worker", "ghost")]))
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.codes(delivery_id), ["WORKER_NOT_REGISTERED"])

    def test_without_an_authority_the_content_is_withheld_and_nothing_starts(self) -> None:
        delivery_id = self.task("t-noauth")
        self.run_idle(self.consumer([rule_for(self.world, "t-noauth", "write")], authority=None))
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.codes(delivery_id), ["CONTENT_WITHHELD"])

    def test_an_authority_that_refuses_the_start_leaves_no_attempt_and_no_executor_and_backs_off(self) -> None:
        delivery_id = self.task("t-revoked")
        consumer = self.consumer(
            [rule_for(self.world, "t-revoked", "write")], authority=DenyStart(), backoff_seconds=3600.0,
        )
        self.run_idle(consumer)
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.phases(delivery_id), ["ATTEMPT_INTENT", "INTENT_CLEARED", "BLOCKED"])
        self.assertEqual(self.codes(delivery_id), ["AUTHORITY_DENIED", "AUTHORITY_DENIED"])
        self.run_idle(consumer)  # inside the back-off window nothing is asked of UAM or journalled again
        self.assertEqual(len(self.phases(delivery_id)), 3)

    def test_a_version_1_delivery_is_not_a_continuity_task_and_is_denied(self) -> None:
        contract = create_contract(self.world, "c-v1", allowed=["out/v1.md"])
        legacy = make_control(self.world, StandInAuthority(), legacy_deliver=True)
        delivery = legacy.deliver(
            REQUESTER, contract_id=contract["contract_id"], contract_digest=contract["contract_digest"], recipient=CONSUMER,
            authority_ref="grant-0001", idempotency_key="v1-legacy-key-0001", business_task_ref="task-v1", task_revision=1,
        )
        self.run_idle(self.consumer([rule_for(self.world, "task-v1", "write")]))
        self.assertEqual(self.codes(delivery["delivery_id"]), ["NOT_CONTINUITY_V2"])
        self.assertEqual(self.executions(), [])


class PolicyFileTest(ConsumerCase):
    def test_a_policy_nobody_but_the_owner_may_write_denies_everything(self) -> None:
        delivery_id = self.task("t-open-policy")
        consumer = self.consumer([rule_for(self.world, "t-open-policy", "write")])
        os.chmod(self.root / "policy.json", 0o666)
        self.run_idle(consumer)
        self.assertNeverStarted(delivery_id)
        self.assertEqual(self.codes(delivery_id), ["NO_RULE"])
        self.assertEqual([r["code"] for r in self.records() if r["phase"] == "POLICY_INVALID"], ["INPUT_FILE_NOT_PRIVATE"])

    def test_malformed_rules_are_refused_not_interpreted(self) -> None:
        valid = rule_for(self.world, "t", "write")
        for label, rule, code in (
            ("no selector", {k: v for k, v in valid.items() if k not in ("business_task_ref", "owner_ref")}, "RULE_WITHOUT_SELECTOR"),
            ("unknown key", {**valid, "sudo": True}, "POLICY_RULE_SHAPE"),
            ("longer than the lease", {**valid, "lease_seconds": 30, "max_seconds": 30}, "RULE_MAX_SECONDS_EXCEEDS_LEASE"),
            ("lease out of range", {**valid, "lease_seconds": 5}, "RULE_LEASE_OUT_OF_RANGE"),
            ("allow-list not a list", {**valid, "verification_allowlist": "true"}, "POLICY_RULE_SHAPE"),
        ):
            with self.subTest(label):
                write_json_private(self.root / "bad.json", policy_document([rule]))
                source = PolicySource(self.root / "bad.json")
                self.assertEqual(len(source.get().rules), 0)
                self.assertEqual(source.last_error, code)

    def test_a_policy_change_is_picked_up_without_a_restart(self) -> None:
        delivery_id = self.task("t-live-policy")
        consumer = self.consumer([])
        self.run_idle(consumer)
        self.assertNeverStarted(delivery_id)
        time.sleep(0.01)
        write_json_private(self.root / "policy.json", policy_document([rule_for(self.world, "t-live-policy", "write")]))
        self.run_idle(consumer)
        self.assertEqual(self.view(delivery_id)["state"], "RESULT_RECORDED")


class RunAndRecoverTest(ConsumerCase):
    def test_a_delivery_is_picked_up_run_and_recorded_by_uam_with_every_effect_through_the_authority(self) -> None:
        delivery_id = self.task("t-happy")
        self.run_idle(self.consumer([rule_for(self.world, "t-happy", "write")]))
        view = self.view(delivery_id)
        self.assertEqual(view["state"], "RESULT_RECORDED")
        self.assertEqual((view["result"]["review_state"], view["result"]["review_blockers"]), ("PASS", []), view["result"])
        self.assertEqual(view["result"]["submitted_by"], CONSUMER)
        self.assertEqual((self.world.workspace() / "out/t-happy.md").read_text(encoding="utf-8"), "result of t-happy\n")
        self.assertEqual(len(self.executions()), 1)
        self.assertEqual(
            self.phases(delivery_id),
            ["ATTEMPT_INTENT", "ATTEMPT_STARTED", "EXECUTOR_STARTED", "EXECUTOR_ENDED", "RESULT_PREPARED", "RESULT_SUBMITTED"],
        )
        started = next(r for r in self.records(delivery_id) if r["phase"] == "ATTEMPT_STARTED")
        self.assertEqual(started["executor_kind"], "local-command-not-an-agent")
        effects = self.authority_effects()
        for effect in ("attempt_start", "result_submit", "dereference"):
            self.assertIn((effect, True), effects)
        self.assertFalse([entry for entry in effects if not entry[1]])
        self.assertEqual(view["business_acceptance"], "NOT_DETERMINED_BY_UAM")

    def test_the_executors_actual_session_binding_is_kept_with_the_attempt_and_the_result(self) -> None:
        delivery_id = self.task("t-bound")
        rule = {**rule_for(self.world, "t-bound", "write"), "adapter": "bound-agent", "session": "resume:thr-declared"}
        self.run_idle(self.consumer([rule], adapters={"bound-agent": BoundAgent()}))
        view = self.view(delivery_id)
        self.assertEqual((view["state"], view["result"]["review_state"]), ("RESULT_RECORDED", "PASS"), view["result"])
        records = {record["phase"]: record for record in self.records(delivery_id)}
        ended = records["EXECUTOR_ENDED"]["binding"]
        self.assertEqual(records["EXECUTOR_STARTED"]["handle"]["binding"]["observed"], {"thread_id": "thr-actual"})
        self.assertEqual(ended["observed"], {"thread_id": "thr-actual", "turn_id": "turn-actual", "thread_cwd": str(self.world.workspace().resolve())})
        self.assertEqual(records["RESULT_SUBMITTED"]["executor_binding"], ended)
        attempt_ref = records["ATTEMPT_STARTED"]["attempt_ref"]
        outcome_file = json.loads((self.work / "jobs" / delivery_id / attempt_ref / "outcome.json").read_text(encoding="utf-8"))
        self.assertEqual(outcome_file["binding"], ended)
        self.assertEqual(outcome_file["binding"]["declared"]["session"], "resume:thr-declared", "declared stays declared")

    def test_a_failed_worker_ends_the_attempt_and_the_delivery_is_never_run_again(self) -> None:
        delivery_id = self.task("t-fail")
        rules = [rule_for(self.world, "t-fail", "boom")]
        self.run_idle(self.consumer(rules, workers={"boom": {"UAM_TEST_MODE": "fail"}}))
        view = self.view(delivery_id)
        attempt = view["attempts"][-1]
        self.assertEqual((view["state"], attempt["state"], attempt["end"]["how"]), ("DELIVERED", "ENDED", "REPORTED"))
        self.assertEqual(view["effect"], "NO_EFFECT_OBSERVED")
        self.assertEqual(len(self.executions()), 1)
        self.run_idle(self.consumer(rules, workers={"boom": {"UAM_TEST_MODE": "fail"}}))  # a restarted Consumer, same journal
        self.assertEqual(len(self.executions()), 1)
        self.assertEqual(len(self.view(delivery_id)["attempts"]), 1)
        self.assertEqual(self.codes(delivery_id)[-1], "PRIOR_ATTEMPT_NO_AUTOMATIC_REDO")

    def test_a_worker_that_changes_nothing_cannot_produce_a_result(self) -> None:
        delivery_id = self.task("t-noop")
        self.run_idle(self.consumer([rule_for(self.world, "t-noop", "idle")], workers={"idle": {"UAM_TEST_MODE": "noop"}}))
        view = self.view(delivery_id)
        self.assertEqual((view["state"], view["attempts"][-1]["end"]["how"]), ("DELIVERED", "REPORTED"))
        self.assertIsNone(view["result"])
        self.assertIn("NO_ALLOWED_PATH_CHANGED", [r.get("note") for r in self.records(delivery_id)])

    def test_a_worker_that_crashes_without_an_outcome_is_reported_failed_not_done(self) -> None:
        delivery_id = self.task("t-crash")
        self.run_idle(self.consumer([rule_for(self.world, "t-crash", "die")], workers={"die": {"UAM_TEST_MODE": "crash"}}))
        view = self.view(delivery_id)
        self.assertIsNone(view["result"])
        self.assertEqual(view["attempts"][-1]["end"]["how"], "REPORTED")
        self.assertEqual(len(self.executions()), 1)

    def test_a_restarted_consumer_finishes_an_attempt_whose_executor_is_done_without_running_it_again(self) -> None:
        class CrashesBeforeSettling(Consumer):
            def _finalize(self, delivery_id: str, ledger: Any) -> None:
                raise RuntimeError("simulated crash after the executor ended")

        delivery_id = self.task("t-restart")
        rules = [rule_for(self.world, "t-restart", "write")]
        first = self.consumer(rules)
        crashing = CrashesBeforeSettling(
            control=first.control, gateway=first.gateway, principal=CONSUMER, policy=first.policy,
            adapters=first.adapters, work_dir=self.work, backoff_seconds=0.0,
        )
        self.run_idle(crashing)
        self.assertEqual(self.view(delivery_id)["state"], "ATTEMPT_ACTIVE")
        self.assertEqual(len(self.executions()), 1)
        self.assertIn("CONSUMER_ERROR", self.phases(delivery_id))
        self.run_idle(self.consumer(rules))
        self.assertEqual(self.view(delivery_id)["state"], "RESULT_RECORDED")
        self.assertEqual(len(self.executions()), 1, "the executor must not have run a second time")
        self.assertEqual(len(self.view(delivery_id)["attempts"]), 1)

    def test_a_resident_consumer_survives_failed_passes_and_says_so_once(self) -> None:
        delivery_id = self.task("t-flaky")
        first = self.consumer([rule_for(self.world, "t-flaky", "write")])
        flaky = ScriptedInbox(first.control, failures=3)
        consumer = Consumer(
            control=flaky, gateway=first.gateway, principal=CONSUMER, policy=first.policy,  # type: ignore[arg-type]
            adapters=first.adapters, work_dir=self.work, backoff_seconds=0.0,
        )
        stop = threading.Event()
        thread = threading.Thread(target=consumer.run, kwargs={"stop": stop, "poll_seconds": 0.02}, daemon=True)
        thread.start()
        try:
            self.wait_until(lambda: self.view(delivery_id)["state"] == "RESULT_RECORDED")
        finally:
            stop.set()
            thread.join(timeout=30)
        errors = [record for record in self.records() if record["phase"] == "CONSUMER_ERROR"]
        self.assertEqual([(record["code"], record["where"]) for record in errors], [("OSError", "poll")], "three failures, one record")
        self.assertEqual(len(self.executions()), 1)

    def test_a_truncated_inbox_is_reported_when_it_starts_and_when_it_ends(self) -> None:
        first = self.consumer([])
        inbox = ScriptedInbox(first.control, truncated=True)
        consumer = Consumer(
            control=inbox, gateway=first.gateway, principal=CONSUMER, policy=first.policy,  # type: ignore[arg-type]
            adapters=first.adapters, work_dir=self.work, backoff_seconds=0.0,
        )
        consumer.poll_once()
        consumer.poll_once()
        inbox.truncated = False
        consumer.poll_once()
        reports = [record["truncated"] for record in self.records() if record["phase"] == "INBOX_TRUNCATED"]
        self.assertEqual(reports, [True, False])

    def test_a_crash_between_preparing_and_submitting_replays_the_same_result_bytes(self) -> None:
        class DiesBeforeTheCall:
            """The control object of a Consumer life that dies on the way to ``submit_result`` (everything else passes through)."""

            def __init__(self, real: Any) -> None:
                self._real = real

            def __getattr__(self, name: str) -> Any:
                return getattr(self._real, name)

            def submit_result(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("the process died before the call reached UAM")

        delivery_id = self.task("t-replay")
        rules = [rule_for(self.world, "t-replay", "write")]
        first = self.consumer(rules, backoff_seconds=3600.0)
        dying = Consumer(
            control=DiesBeforeTheCall(first.control), gateway=first.gateway, principal=CONSUMER, policy=first.policy,  # type: ignore[arg-type]
            adapters=first.adapters, work_dir=self.work, backoff_seconds=3600.0,
        )
        self.run_idle(dying)
        self.assertEqual(self.view(delivery_id)["state"], "ATTEMPT_ACTIVE")
        prepared = next(self.work.glob(f"jobs/{delivery_id}/*/result.json"))
        before = prepared.read_bytes()
        self.assertEqual(len(self.executions()), 1)
        self.run_idle(self.consumer(rules))  # the next life: no executor, the stored bytes go to UAM
        view = self.view(delivery_id)
        self.assertEqual((view["state"], view["result"]["review_state"]), ("RESULT_RECORDED", "PASS"))
        self.assertEqual(prepared.read_bytes(), before, "the replay must send exactly the prepared result")
        self.assertEqual(len(self.executions()), 1)
        self.assertEqual(len([r for r in self.records(delivery_id) if r["phase"] == "RESULT_PREPARED"]), 1)

    def test_an_executor_that_is_still_running_is_waited_for_and_never_replaced(self) -> None:
        sleeper = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        delivery_id = self.task("t-orphan")
        rules = [{**rule_for(self.world, "t-orphan", "write"), "adapter": "left-behind"}]
        consumer = self.consumer(rules, adapters={"left-behind": LeftBehind(sleeper)})
        self.run_idle(consumer)
        self.assertEqual(self.view(delivery_id)["state"], "ATTEMPT_ACTIVE")
        self.assertEqual(self.phases(delivery_id)[-2:], ["EXECUTOR_ENDED", "WAITING_OLD_EXECUTOR"])
        self.run_idle(self.consumer(rules, adapters={"left-behind": LeftBehind(sleeper)}))
        self.assertEqual(len(self.view(delivery_id)["attempts"]), 1)
        self.assertEqual(self.phases(delivery_id).count("WAITING_OLD_EXECUTOR"), 1, "one advisory record, not one per poll")
        sleeper.kill()
        sleeper.wait()
        self.run_idle(self.consumer(rules, adapters={"left-behind": LeftBehind(sleeper)}))
        attempt = self.view(delivery_id)["attempts"][-1]
        self.assertEqual((attempt["state"], attempt["end"]["how"]), ("ENDED", "REPORTED"))
        ended = [record for record in self.records(delivery_id) if record["phase"] == "ATTEMPT_ENDED"]
        self.assertEqual([record["note"] for record in ended], ["EXECUTOR_GONE_NO_OUTCOME"])
        self.assertEqual(ended[0]["reported_outcome"], "STOPPED")
        self.assertEqual(self.codes(delivery_id)[-1], "PRIOR_ATTEMPT_NO_AUTOMATIC_REDO", "the open delivery is not started again")

    def test_an_intent_the_journal_never_saw_begin_is_cleared_or_adopted_never_guessed(self) -> None:
        cleared_id = self.task("t-cleared")
        adopted_id = self.task("t-adopted")
        journal = Journal(self.work / "journal.jsonl", "earlier-life")
        journal.append(cleared_id, "ATTEMPT_INTENT", lease_seconds=120)
        journal.append(adopted_id, "ATTEMPT_INTENT", lease_seconds=120)
        self.control.start_attempt(CONSUMER, delivery_id=adopted_id, lease_seconds=120)  # UAM saw it; the journal did not
        self.run_idle(self.consumer([rule_for(self.world, "t-cleared", "write"), rule_for(self.world, "t-adopted", "write")]))
        self.assertEqual(self.view(cleared_id)["state"], "RESULT_RECORDED")
        self.assertEqual(self.codes(cleared_id)[0], "NO_ATTEMPT_WAS_STARTED")
        adopted = self.view(adopted_id)
        self.assertEqual(len(adopted["attempts"]), 1)
        self.assertEqual(adopted["attempts"][-1]["end"]["how"], "REPORTED")
        self.assertTrue(next(r for r in self.records(adopted_id) if r["phase"] == "ATTEMPT_STARTED")["adopted"])
        self.assertEqual(len(self.executions()), 1, "only the cleared task ran; the adopted one was ended, not executed")


class TargetsAndConcurrencyTest(ConsumerCase):
    def test_independent_tasks_run_together_and_only_the_conflicting_target_is_blocked(self) -> None:
        hold = self.root / "release-x"
        workers = {"hold": {"UAM_TEST_HOLD_FILE": str(hold)}, "write": {}}
        slow = self.task("t-x", allowed=["out/shared.md"])
        free = self.task("t-y", allowed=["out/y.md"])
        rules = [rule_for(self.world, name, worker) for name, worker in (("t-x", "hold"), ("t-y", "write"), ("t-z", "write"))]
        consumer = self.consumer(rules, workers=workers, max_concurrency=4, backoff_seconds=0.3)
        stop = threading.Event()
        thread = threading.Thread(target=consumer.run, kwargs={"stop": stop, "poll_seconds": 0.02}, daemon=True)
        thread.start()
        try:
            self.wait_until(lambda: (self.evidence / "t-x.start.json").exists())  # the slow executor now holds out/shared.md
            self.wait_until(lambda: self.view(free)["state"] == "RESULT_RECORDED")
            rival = self.task("t-z", allowed=["out/shared.md"])  # arrives while that target is held
            self.wait_until(lambda: "TARGET_BUSY" in self.codes(rival))
            self.assertEqual(self.view(slow)["state"], "ATTEMPT_ACTIVE", "the slow task is still running while the free one finished")
            self.assertEqual(self.view(rival)["attempts"], [], "the rival never got an attempt")
            hold.write_text("go\n", encoding="utf-8")
            self.wait_until(lambda: self.view(slow)["state"] == "RESULT_RECORDED")
            self.wait_until(lambda: "BASELINE_CHANGED" in self.codes(rival))
        finally:
            stop.set()
            thread.join(timeout=30)
        self.assertEqual(self.view(rival)["attempts"], [])
        self.assertEqual(sorted(line.split()[0] for line in self.executions()), ["t-x", "t-y"])
        self.assertEqual((self.world.workspace() / "out/shared.md").read_text(encoding="utf-8"), "result of t-x\n")

    def test_the_concurrency_limit_is_a_cap_on_running_jobs_not_a_queue_of_its_own(self) -> None:
        barrier = self.root / "barrier"
        workers = {"meet": {"UAM_TEST_BARRIER_DIR": str(barrier), "UAM_TEST_BARRIER_N": "2", "UAM_TEST_MAX_SECONDS": "10"}}
        ids = [self.task(f"t-meet{index}") for index in range(2)]
        rules = [rule_for(self.world, f"t-meet{index}", "meet") for index in range(2)]
        self.run_idle(self.consumer(rules, workers=workers, max_concurrency=2))
        self.assertEqual([self.view(delivery_id)["state"] for delivery_id in ids], ["RESULT_RECORDED"] * 2)

        barrier_one = self.root / "barrier-one"
        workers = {"meet": {"UAM_TEST_BARRIER_DIR": str(barrier_one), "UAM_TEST_BARRIER_N": "2", "UAM_TEST_MAX_SECONDS": "2"}}
        serial = [self.task(f"t-serial{index}") for index in range(2)]
        rules = [rule_for(self.world, f"t-serial{index}", "meet") for index in range(2)]
        self.run_idle(self.consumer(rules, workers=workers, max_concurrency=1))
        states = [self.view(delivery_id)["state"] for delivery_id in serial]
        self.assertNotEqual(states, ["RESULT_RECORDED"] * 2, "with a limit of one the two cannot have met at the barrier")


class JournalAndLocksTest(ConsumerCase):
    def test_a_torn_last_line_does_not_swallow_the_next_record(self) -> None:
        journal = Journal(self.work / "journal.jsonl", "life-1")
        journal.append("dlv-" + "a" * 24, "DENIED", code="NO_RULE")
        with (self.work / "journal.jsonl").open("ab") as handle:
            handle.write(b'{"phase": "ATTEMPT_STARTED", "delivery_id": "dlv-' + b"a" * 12)  # a crash in the middle of a record
        second = Journal(self.work / "journal.jsonl", "life-2")
        second.append("dlv-" + "a" * 24, "BLOCKED", code="TARGET_BUSY")
        phases = [record["phase"] for record in Journal(self.work / "journal.jsonl", "life-3").records()]
        self.assertEqual(phases, ["DENIED", "BLOCKED"])

    def test_a_target_lock_held_by_an_executor_survives_the_parent_closing_its_descriptor(self) -> None:
        locks = TargetLocks(self.root / "locks")
        descriptors = locks.try_acquire("ws-main", ["out/a.md", "out/b.md"])
        assert descriptors is not None
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], pass_fds=tuple(descriptors))
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertIsNone(TargetLocks(self.root / "locks").try_acquire("ws-main", ["out/b.md"]), "held by us")
        TargetLocks.release(descriptors)
        self.assertIsNone(TargetLocks(self.root / "locks").try_acquire("ws-main", ["out/b.md"]), "still held by the child")
        self.assertIsNone(TargetLocks(self.root / "locks").try_acquire("ws-main", ["out/0-free.md", "out/a.md"]), "all or nothing")
        free = TargetLocks(self.root / "locks").try_acquire("ws-main", ["out/0-free.md"])
        self.assertIsNotNone(free, "the failed try took out/0-free.md first (sorted order) and must have given it back")
        TargetLocks.release(free or [])
        child.kill()
        child.wait()
        again = TargetLocks(self.root / "locks").try_acquire("ws-main", ["out/a.md", "out/b.md"])
        self.assertIsNotNone(again, "the lock ends with the process that held it")
        TargetLocks.release(again or [])


class CommandLineTest(ConsumerCase):
    def arguments(self, *extra: str, rules: Sequence[Mapping[str, Any]] = ()) -> list[str]:
        write_json_private(self.root / "policy.json", policy_document(rules))
        return [
            "run", "--registry", str(self.world.registry), "--state-dir", str(self.world.state), "--work-dir", str(self.work),
            "--principal", CONSUMER, "--endpoint-ref", ENDPOINT, "--policy", str(self.root / "policy.json"),
            "--once", "--max-seconds", "10", "--poll-seconds", "0.02", *extra,
        ]

    def test_a_second_instance_on_one_work_directory_refuses(self) -> None:
        first = SingleInstance(self.work / "consumer.lock")
        try:
            self.assertEqual(main(self.arguments()), 75)
        finally:
            first.close()
        self.assertEqual(main(self.arguments()), 0)

    def test_an_authority_factory_must_be_pinned_by_digest(self) -> None:
        digest = hashlib.sha256(AUTHORITY_FACTORY.read_bytes()).hexdigest()
        factory = f"{AUTHORITY_FACTORY}:stand_in_authority"
        self.assertEqual(main(self.arguments("--authority-factory", factory)), 2, "no digest")
        self.assertEqual(main(self.arguments("--authority-factory", factory, "--authority-factory-sha256", "0" * 64)), 2, "wrong digest")
        self.assertEqual(main(self.arguments("--authority-factory", f"{AUTHORITY_FACTORY}:missing", "--authority-factory-sha256", digest)), 2)
        self.assertEqual(main(self.arguments("--authority-factory", factory, "--authority-factory-sha256", digest)), 0)

    def test_no_authority_at_all_is_a_deny_all_consumer_not_a_failure(self) -> None:
        delivery_id = self.task("t-cli-noauth")
        arguments = self.arguments(rules=[rule_for(self.world, "t-cli-noauth", "write")])
        self.assertEqual(main(arguments), 0)
        self.assertEqual(self.view(delivery_id)["attempts"], [])
        self.assertEqual(self.codes(delivery_id), ["CONTENT_WITHHELD"])


if __name__ == "__main__":
    unittest.main()
