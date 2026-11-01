"""What may be settled as 'stopped', and what may not: negative controls for the stop evidence of an executor.

One defect family, four facts that must stay apart. The Consumer tells UAM that an executor stopped (``STOPPED``) only on
evidence, and every other case keeps the attempt open, so that UAM's lease, ``STOP_NOT_CONFIRMED`` and same-task gates keep
blocking a successor:

* an adapter that CONFIRMED the stop (a complete observation, a complete read-back, nothing left): settled as before;
* an adapter that could not call the executor stopped, with the identities it recorded: read back strictly, settled only
  when every one is gone (``STOP_RECONCILED``); a recorded PID that runs another command line is not shown gone (an ``exec``
  keeps the PID); a process table that cannot be read is not an empty one;
* an adapter that could not read the process table when it closed the executor: the identities are not all of them, so
  nothing later can lift it (``EXECUTOR_STOP_OBSERVATION_FAILED``);
* an Agent whose end record was never journalled (the Consumer died first): nothing was recorded about what it started
  (``EXECUTOR_END_NOT_RECORDED``). A local command keeps its declared meaning: its process group is the whole executor.

The Codex App Server is the real adapter over a FAKE server (``fake_codex_app_server.py``) that can leave a helper in a
session of its own; ``ps`` is made to fail by replacing ``subprocess.run`` for ``/bin/ps`` only, for the time of one block;
a child that execs is a real process. Nothing here is evidence about the real Codex or about a real model.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from universal_agent_middleware.consumer import Consumer
from universal_agent_middleware.harness_adapter import (
    UNKNOWN,
    CodexAppServerAdapter,
    CodexServerSpec,
    ExecutorHandle,
    HarnessJob,
    HarnessOutcome,
    group_alive,
    process_table,
    process_tree,
    still_running,
)
from universal_agent_middleware.task_control import TaskControlError

from consumer_world import CONSUMER, rule_for
from test_consumer import ConsumerCase

FAKE_SERVER = Path(__file__).resolve().parent / "fake_codex_app_server.py"
HELPER_COMMAND = "time.sleep(120)"
ADVISORY_PHASES = ("WAITING_OLD_EXECUTOR", "ATTEMPT_LEFT_OPEN")


def wait_until(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition not reached in time")


@contextmanager
def broken_ps(mode: str, *, after: int = 0) -> Iterator[list[int]]:
    """For the time of the block every ``/bin/ps`` call fails (the first ``after`` calls are real); any other
    ``subprocess.run`` is the real one. ``exit1``: ps exits 1 and prints nothing; ``missing``: it cannot be executed;
    ``timeout``: it does not answer in time. Yields the number of ps calls so far."""
    real, calls = subprocess.run, [0]

    def run(argv: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(argv, (list, tuple)) and argv and argv[0] == "/bin/ps":
            calls[0] += 1
            if calls[0] > after:
                if mode == "exit1":
                    return subprocess.CompletedProcess(argv, 1, stdout="", stderr="ps: simulated failure")
                if mode == "missing":
                    raise FileNotFoundError(2, "simulated: /bin/ps cannot be executed")
                raise subprocess.TimeoutExpired(argv, 15)
        return real(argv, *args, **kwargs)

    subprocess.run = run  # type: ignore[assignment]
    try:
        yield calls
    finally:
        subprocess.run = real  # type: ignore[assignment]


def fake_entries(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def helper_of(log: Path, server_pid: int) -> int:
    """The PID of the helper that the fake server with this PID started in a session of its own."""
    mine = False
    for entry in fake_entries(log):
        if "argv" in entry:
            mine = entry.get("pid") == server_pid
        elif mine and "orphan_pid" in entry:
            return int(entry["orphan_pid"])
    raise AssertionError("the fake server started no helper")


def kill_helper(pid: int) -> None:
    """SIGKILL a helper this test caused, only while that PID still runs the helper's command (a reused PID is left alone)."""
    if HELPER_COMMAND in process_table().get(pid, {}).get("command", ""):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def kill_helpers(log: Path) -> None:
    for entry in fake_entries(log):
        if "orphan_pid" in entry:
            kill_helper(int(entry["orphan_pid"]))


def is_there(pid: int) -> bool:
    return pid in process_table()


def start_child_that_execs() -> subprocess.Popen[bytes]:
    """A child in a session of its own that blocks on its stdin and, once that is closed, execs ``sleep``: the same PID
    under another command line, as a legitimate ``exec`` does. The caller records it first, then ``release``s it."""
    code = "import os, sys; sys.stdin.read(); os.execv('/bin/sleep', ['sleep', '60'])"
    return subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, start_new_session=True)


def release(child: subprocess.Popen[bytes]) -> None:
    assert child.stdin is not None
    child.stdin.close()
    wait_until(lambda: process_table().get(child.pid, {}).get("command", "").startswith("sleep"))


class FakeCodex:
    """Mixin: the real Codex adapter over the fake server, in a directory of this test (``self.root``)."""

    root: Path
    addCleanup: Callable[..., None]

    def codex(self, name: str = "codex", *, io_log: bool = False, **settings: Any) -> tuple[CodexAppServerAdapter, Path]:
        home, codex_home, log = self.root / name / "home", self.root / name / "codex-home", self.root / name / "requests.jsonl"
        home.mkdir(parents=True)
        codex_home.mkdir(parents=True)
        (codex_home / "fake.json").write_text(json.dumps({"log": str(log), **settings}), encoding="utf-8")
        self.addCleanup(kill_helpers, log)
        spec = CodexServerSpec(argv=(sys.executable, str(FAKE_SERVER)), codex_home=str(codex_home), home=str(home))
        return CodexAppServerAdapter(spec, io_log=(self.root / name / "io.jsonl") if io_log else None), log


# -- the adapter: what it may claim ---------------------------------------------------------------------------------------


class AdapterStopReportTest(FakeCodex, unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="uam-stop-")).resolve()
        if not os.environ.get("UAM_KEEP_TEST_WORLDS"):
            self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()

    def run_job(self, adapter: CodexAppServerAdapter) -> tuple[HarnessOutcome, list[ExecutorHandle]]:
        started: list[ExecutorHandle] = []
        job = HarnessJob(
            delivery_id="dlv-" + "a" * 24, attempt_ref="att-" + "a" * 24 + ".1", fence=1, contract_id="c-1", workspace_id="ws-main",
            business_task_ref="task-1", owner_ref="owner-x", cwd=str(self.cwd), session="new", worker="w", objective="write the file",
            authoritative_paths=("inputs/spec.md",), allowed_change_paths=("out/a.md",), verification_commands=("true",),
            job_dir=str(self.root / "job"), deadline_seconds=20.0,
        )
        return adapter.run(job, on_started=started.append, keep_fds=()), started

    def test_a_child_the_server_leaves_makes_the_outcome_unknown_and_names_every_process_seen(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        outcome, started = self.run_job(adapter)
        self.assertEqual((outcome.status, outcome.stopped), (UNKNOWN, False))
        assert outcome.binding is not None
        report = outcome.binding["observed"]["stop_report"]
        helper = helper_of(log, started[0].pid)
        self.assertEqual((report["observation"], report["readback"], report["confirmed"]), ("COMPLETE", "COMPLETE", False))
        seen = {item["pid"]: item["command"] for item in report["processes_seen"]}
        self.assertTrue(started[0].pid in seen and helper in seen, "identities (PID and command line) are kept, not a count")
        self.assertTrue(all(isinstance(command, str) and command for command in seen.values()))
        self.assertEqual((report["still_running"], report["command_changed"]), ([helper], []))

    def test_a_server_that_leaves_nothing_is_a_confirmed_stop_with_a_complete_report(self) -> None:
        adapter, _ = self.codex(account="chatgpt", turn="complete")
        outcome, started = self.run_job(adapter)
        self.assertEqual((outcome.status, outcome.code, outcome.stopped), ("DONE", "TURN_COMPLETED", True))
        assert outcome.binding is not None
        report = outcome.binding["observed"]["stop_report"]
        self.assertEqual((report["observation"], report["readback"], report["confirmed"]), ("COMPLETE", "COMPLETE", True))
        self.assertEqual(([item["pid"] for item in report["processes_seen"]], report["still_running"]), ([started[0].pid], []))

    def test_a_process_table_that_cannot_be_read_is_empty_by_default_and_an_error_when_strict(self) -> None:
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        seen = process_tree(process.pid)
        with broken_ps("exit1"):
            # the reading of r1, unchanged: fine for finding a process to record, and how a failed ps once read as 'stopped'
            self.assertEqual((process_table(), still_running(seen)), ({}, []))
            for decision in (
                lambda: process_table(strict=True), lambda: process_tree(process.pid, strict=True),
                lambda: still_running(seen, strict=True),
            ):
                with self.assertRaises(OSError):
                    decision()
        with broken_ps("timeout"), self.assertRaises(OSError):
            still_running(seen, strict=True)
        self.assertEqual([item["pid"] for item in still_running(seen, strict=True)], [process.pid])

    def test_a_recorded_pid_that_runs_another_command_is_not_shown_gone_by_the_strict_read_back(self) -> None:
        process = start_child_that_execs()
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        seen = process_tree(process.pid)  # recorded while it still runs the first program
        release(process)  # a legitimate exec: the PID is kept, the command line is another
        self.assertEqual(still_running(seen), [], "the default reading is unchanged: another command line is another process")
        strict = still_running(seen, strict=True)
        self.assertEqual([(item["pid"], item.get("command_changed")) for item in strict], [(process.pid, True)])
        self.assertEqual(strict[0]["command"], seen[0]["command"], "what the PID runs now is not copied into the answer")
        process.kill()
        process.wait()
        self.assertEqual(still_running(seen, strict=True), [], "gone is gone: no entry for the PID")

    def test_a_process_table_that_cannot_be_read_while_the_server_is_closed_is_not_a_stop(self) -> None:
        for mode in ("exit1", "missing", "timeout"):
            with self.subTest(mode):
                adapter, log = self.codex(f"codex-{mode}", io_log=True, account="chatgpt", turn="complete", orphan=True)
                with broken_ps(mode):
                    outcome, started = self.run_job(adapter)
                self.assertEqual((outcome.status, outcome.code, outcome.stopped), (UNKNOWN, "TURN_COMPLETED", False), "not SPAWN_FAILED: it was spawned")
                self.assertIn("process table could not be read", outcome.detail)
                assert outcome.binding is not None
                self.assertEqual(
                    (outcome.binding["observed"]["stop_report"]["observation"], outcome.binding["observed"]["stop_report"]["confirmed"]),
                    ("UNAVAILABLE", False),
                )
                self.assertFalse(group_alive(started[0].pgid), "the server is closed although the process table could not be read")
                self.assertTrue(is_there(helper_of(log, started[0].pid)), "the child that an empty table would have hidden is alive")
                spawn = next(json.loads(entry["line"]) for entry in map(json.loads, (self.root / f"codex-{mode}" / "io.jsonl").read_text().splitlines()) if entry["dir"] == "spawn")
                self.assertIn("command_unavailable", spawn, "an unreadable table is recorded as unreadable, not as 'no command'")

    def test_a_read_back_that_fails_after_a_complete_observation_is_not_a_confirmation(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        with broken_ps("exit1", after=1):  # the tree is read before the close; the read-back after it is not
            outcome, started = self.run_job(adapter)
        assert outcome.binding is not None
        report = outcome.binding["observed"]["stop_report"]
        self.assertEqual((outcome.stopped, report["observation"], report["readback"], report["confirmed"]), (False, "COMPLETE", "UNAVAILABLE", False))
        self.assertIn(helper_of(log, started[0].pid), [item["pid"] for item in report["processes_seen"]], "the identities are complete")


# -- the Consumer: what it may settle -------------------------------------------------------------------------------------


class WithBrokenPs:
    """The real adapter, with ``ps`` failing for exactly the time its ``run`` takes (start, turn and close)."""

    def __init__(self, inner: Any, mode: str, *, after: int = 0) -> None:
        self.inner, self.mode, self.after = inner, mode, after
        self.name, self.is_agent, self.needs_session = inner.name, inner.is_agent, inner.needs_session

    def preflight(self) -> tuple[str, str] | None:
        return self.inner.preflight()

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        with broken_ps(self.mode, after=self.after):
            return self.inner.run(job, on_started=on_started, keep_fds=keep_fds)


class WritesTheFile:
    """The real adapter, then the file the Agent was asked for (the fake server writes nothing itself)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.name, self.is_agent, self.needs_session = inner.name, inner.is_agent, inner.needs_session

    def preflight(self) -> tuple[str, str] | None:
        return self.inner.preflight()

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        outcome = self.inner.run(job, on_started=on_started, keep_fds=keep_fds)
        target = Path(job.cwd) / job.allowed_change_paths[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("written by the agent\n", encoding="utf-8")
        return outcome


class ExecedChild:
    """An Agent stand-in whose announced root is already gone and whose child, recorded under its first command line, execs."""

    name, is_agent, needs_session = "execed-child", True, True

    def __init__(self) -> None:
        self.child: subprocess.Popen[bytes] | None = None

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        root = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
        root.wait()
        self.child = start_child_that_execs()
        seen = process_tree(self.child.pid)  # recorded under the first command line
        on_started(ExecutorHandle("stub-agent", root.pid, root.pid, "now"))
        release(self.child)  # and only then does the child exec
        report = {"processes_seen": seen, "observation": "COMPLETE", "readback": "COMPLETE", "confirmed": False}
        return HarnessOutcome(
            UNKNOWN, "STUB_NOT_STOPPED", "its child is not confirmed stopped", False, self.name,
            binding={"adapter": self.name, "observed": {"stop_report": report}},
        )


class RaisesAfterAnnouncing:
    """An Agent stand-in whose adapter breaks after it announced a root that is already gone."""

    name, is_agent, needs_session = "breaks-after-announcing", True, True

    def preflight(self) -> tuple[str, str] | None:
        return None

    def run(self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = ()) -> HarnessOutcome:
        gone = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
        gone.wait()
        on_started(ExecutorHandle("stub-agent", gone.pid, gone.pid, "now"))
        raise RuntimeError("the adapter broke")


class DiesBeforeTheEndRecord(Consumer):
    """A Consumer life that ends between the adapter's return and the journal entry that records it, and settles nothing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        real_append = self.journal.append

        def append(delivery_id: str | None, phase: str, **details: Any) -> dict[str, Any]:
            if phase == "EXECUTOR_ENDED":
                raise RuntimeError("simulated death before the end record")
            return real_append(delivery_id, phase, **details)

        self.journal.append = append  # type: ignore[method-assign]

    def _finalize(self, delivery_id: str, ledger: Any) -> None:
        raise RuntimeError("simulated death: this life settles nothing")


class StopEvidenceThroughTheConsumerTest(FakeCodex, ConsumerCase):
    AGENT = "codex-app-server"

    def agent_task(self, name: str, adapter: str = AGENT) -> tuple[str, list[dict[str, Any]]]:
        return self.task(name), [{**rule_for(self.world, name, "write"), "adapter": adapter, "session": "new"}]

    def life(self, rules: list[dict[str, Any]], adapter: Any, name: str = AGENT) -> None:
        self.run_idle(self.consumer(rules, adapters={name: adapter}))

    def advisories(self, delivery_id: str) -> list[tuple[str, str]]:
        return [(record["phase"], record["code"]) for record in self.records(delivery_id) if record["phase"] in ADVISORY_PHASES]

    def ended(self, delivery_id: str) -> dict[str, Any]:
        return next(record for record in self.records(delivery_id) if record["phase"] == "EXECUTOR_ENDED")

    def assertStillOpen(self, delivery_id: str) -> None:
        """UAM has not been told anything: one attempt, active, no result, and its own gate still refuses a successor."""
        view = self.view(delivery_id)
        self.assertEqual((view["state"], len(view["attempts"]), view["attempts"][-1]["state"], view["result"]), ("ATTEMPT_ACTIVE", 1, "ACTIVE", None))
        self.assertTrue({"ATTEMPT_ENDED", "RESULT_SUBMITTED"}.isdisjoint(self.phases(delivery_id)))
        with self.assertRaises(TaskControlError) as refused:
            self.control.start_attempt(CONSUMER, delivery_id=delivery_id, lease_seconds=120)
        self.assertEqual(refused.exception.code, "ATTEMPT_ACTIVE")

    def assertSettledAsStopped(self, delivery_id: str) -> None:
        attempt = self.view(delivery_id)["attempts"][-1]
        self.assertEqual((attempt["state"], attempt["end"]["how"]), ("ENDED", "REPORTED"))
        ended = [record for record in self.records(delivery_id) if record["phase"] == "ATTEMPT_ENDED"]
        self.assertEqual([(record["reported_outcome"], record["note"]) for record in ended], [("STOPPED", "EXECUTOR_GONE_NO_OUTCOME")])

    def thread_starts(self, log: Path) -> int:
        return len([entry for entry in fake_entries(log) if entry.get("method") == "thread/start"])

    def test_an_executor_its_adapter_could_not_stop_stays_open_while_a_recorded_child_lives_and_is_settled_once_it_is_gone(self) -> None:
        for label, wrap in (("seen", lambda adapter: adapter), ("readback-failed", lambda adapter: WithBrokenPs(adapter, "exit1", after=1))):
            with self.subTest(label):
                adapter, log = self.codex(f"codex-{label}", account="chatgpt", turn="complete", orphan=True)
                registered = wrap(adapter)
                delivery_id, rules = self.agent_task(f"t-{label}")
                self.life(rules, registered)
                self.assertStillOpen(delivery_id)
                ended = self.ended(delivery_id)
                self.assertEqual((ended["status"], ended["stopped"]), (UNKNOWN, False))
                helper = helper_of(log, ended["binding"]["observed"]["spawn_pid"])
                self.assertTrue(is_there(helper))
                self.assertEqual(self.advisories(delivery_id), [("WAITING_OLD_EXECUTOR", "EXECUTOR_NOT_CONFIRMED_STOPPED")])
                self.life(rules, registered)  # another Consumer life: the same facts, one advisory record, no second execution
                self.assertEqual(self.advisories(delivery_id), [("WAITING_OLD_EXECUTOR", "EXECUTOR_NOT_CONFIRMED_STOPPED")])
                self.assertEqual(self.thread_starts(log), 1)
                self.assertStillOpen(delivery_id)
                kill_helper(helper)
                wait_until(lambda: not is_there(helper))
                self.life(rules, registered)  # a complete read-back now shows every recorded identity gone
                self.assertSettledAsStopped(delivery_id)
                self.assertEqual(self.phases(delivery_id).count("STOP_RECONCILED"), 1)
                self.assertLess(self.phases(delivery_id).index("STOP_RECONCILED"), self.phases(delivery_id).index("ATTEMPT_ENDED"))

    def test_a_close_stage_ps_failure_with_an_escaped_child_is_not_a_stop_the_consumer_settles_even_after_the_child_is_gone(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        delivery_id, rules = self.agent_task("t-psfail")
        self.life(rules, WithBrokenPs(adapter, "exit1"))
        self.assertStillOpen(delivery_id)
        ended = self.ended(delivery_id)
        self.assertEqual((ended["status"], ended["stopped"], ended["code"]), (UNKNOWN, False, "TURN_COMPLETED"))
        self.assertEqual(ended["binding"]["observed"]["stop_report"]["observation"], "UNAVAILABLE")
        helper = helper_of(log, ended["binding"]["observed"]["spawn_pid"])
        self.assertTrue(is_there(helper), "the escaped child is alive: the table that could not be read would have hidden it")
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_STOP_OBSERVATION_FAILED")])
        kill_helper(helper)
        wait_until(lambda: not is_there(helper))
        self.life(rules, adapter)  # a later life, ps healthy, the child gone: no PID was ever recorded, so nothing is proven
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_STOP_OBSERVATION_FAILED")])
        self.assertNotIn("STOP_RECONCILED", self.phases(delivery_id))
        self.assertEqual(self.thread_starts(log), 1)

    def test_a_consumer_that_died_before_the_end_record_does_not_settle_an_agent_whose_child_was_never_recorded(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        delivery_id, rules = self.agent_task("t-nolog")
        first = self.consumer(rules, adapters={self.AGENT: adapter})
        dying = DiesBeforeTheEndRecord(
            control=first.control, gateway=first.gateway, principal=CONSUMER, policy=first.policy, adapters=first.adapters,
            work_dir=self.work, backoff_seconds=0.0,
        )
        self.run_idle(dying)
        self.assertIn("CONSUMER_ERROR", self.phases(delivery_id))
        self.assertTrue({"EXECUTOR_STARTED"}.issubset(self.phases(delivery_id)) and "EXECUTOR_ENDED" not in self.phases(delivery_id))
        handle = next(record for record in self.records(delivery_id) if record["phase"] == "EXECUTOR_STARTED")["handle"]
        helper = helper_of(log, handle["pid"])
        self.assertFalse(group_alive(handle["pgid"]), "the root group is gone: the adapter closed the server")
        self.assertTrue(is_there(helper), "and a child it started in a session of its own is not")
        self.life(rules, adapter)  # the next life finds a gone root group and no end record
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_END_NOT_RECORDED")])
        kill_helper(helper)
        wait_until(lambda: not is_there(helper))
        self.life(rules, adapter)  # no child PID is guessed, so even a gone child proves nothing
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_END_NOT_RECORDED")])
        self.assertEqual(self.thread_starts(log), 1)

    def test_a_local_command_whose_consumer_died_before_the_end_record_keeps_its_declared_process_group_meaning(self) -> None:
        delivery_id = self.task("t-local")
        rules = [rule_for(self.world, "t-local", "die")]
        workers = {"die": {"UAM_TEST_MODE": "crash"}}  # exits without an outcome: its group is the whole executor and is gone
        first = self.consumer(rules, workers=workers)
        dying = DiesBeforeTheEndRecord(
            control=first.control, gateway=first.gateway, principal=CONSUMER, policy=first.policy, adapters=first.adapters,
            work_dir=self.work, backoff_seconds=0.0,
        )
        self.run_idle(dying)
        self.assertNotIn("EXECUTOR_ENDED", self.phases(delivery_id))
        self.run_idle(self.consumer(rules, workers=workers))
        self.assertSettledAsStopped(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [])

    def test_a_recorded_pid_that_execed_keeps_the_attempt_open_until_it_is_really_gone(self) -> None:
        stand_in = ExecedChild()
        delivery_id, rules = self.agent_task("t-exec", "execed-child")
        self.life(rules, stand_in, "execed-child")
        assert stand_in.child is not None
        self.addCleanup(stand_in.child.wait)
        self.addCleanup(stand_in.child.kill)
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [("WAITING_OLD_EXECUTOR", "EXECUTOR_PID_IDENTITY_CHANGED")])
        advisory = next(record for record in self.records(delivery_id) if record["phase"] == "WAITING_OLD_EXECUTOR")
        self.assertEqual(advisory["command_changed_pids"], [stand_in.child.pid])
        self.assertEqual([key for key in advisory if "command" in key], ["command_changed_pids"], "no command line of the PID's present is journalled")
        self.life(rules, stand_in, "execed-child")
        self.assertEqual(len(self.advisories(delivery_id)), 1)
        stand_in.child.kill()
        stand_in.child.wait()
        self.life(rules, stand_in, "execed-child")
        self.assertSettledAsStopped(delivery_id)

    def test_an_adapter_that_raised_leaves_nothing_to_prove_a_stop_by(self) -> None:
        delivery_id, rules = self.agent_task("t-raised", "breaks-after-announcing")
        self.life(rules, RaisesAfterAnnouncing(), "breaks-after-announcing")
        self.assertStillOpen(delivery_id)
        self.assertEqual((self.ended(delivery_id)["code"], self.ended(delivery_id)["stopped"]), ("ADAPTER_RAISED", False))
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_STOP_UNPROVABLE")])

    def test_the_consumers_own_unreadable_process_table_leaves_the_attempt_open_and_a_later_read_settles_it(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        delivery_id, rules = self.agent_task("t-unreadable")
        self.life(rules, adapter)
        ended = self.ended(delivery_id)
        helper = helper_of(log, ended["binding"]["observed"]["spawn_pid"])
        kill_helper(helper)
        wait_until(lambda: not is_there(helper))  # in truth every recorded process is gone now
        with broken_ps("exit1"):  # but this Consumer cannot read the table: absence is not shown
            self.life(rules, adapter)
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id)[-1], ("ATTEMPT_LEFT_OPEN", "EXECUTOR_STOP_READBACK_UNAVAILABLE"))
        self.assertNotIn("STOP_RECONCILED", self.phases(delivery_id))
        self.life(rules, adapter)
        self.assertSettledAsStopped(delivery_id)

    def test_a_stop_the_adapter_confirmed_is_settled_as_before(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete")
        delivery_id, rules = self.agent_task("t-confirmed")
        self.life(rules, WritesTheFile(adapter))
        view = self.view(delivery_id)
        self.assertEqual((view["state"], view["result"]["review_state"]), ("RESULT_RECORDED", "PASS"))
        ended = self.ended(delivery_id)
        self.assertEqual((ended["status"], ended["stopped"]), ("DONE", True))
        self.assertEqual(self.advisories(delivery_id), [])
        self.assertNotIn("STOP_RECONCILED", self.phases(delivery_id))
        self.assertEqual(self.thread_starts(log), 1)


if __name__ == "__main__":
    unittest.main()
