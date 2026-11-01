"""A server found exited right after its adapter read the process tree is not a confirmed stop.

The defect (P1 of the r2 audit, ``A-R2-P1-SERVER-EXIT-BEFORE-OBSERVATION``). ``CodexAppServerClient.close_and_report`` reads
the process tree ONCE, right before it closes the server, and finds what the server started by parent PID. When the server
has already exited by then (it crashed, or ended by itself after the turn) a child that escaped into a session of its own
has been reparented to PID 1 and is not in the tree, although ``ps`` itself works. r2 called both shapes of this a confirmed
stop: the dead root is listed until somebody waits for it (a zombie, ``<defunct>``) and the tree is that one process, or it
was waited for already and the tree is empty. A read-back of either finds nothing, so the Consumer skipped its UNKNOWN
protection and could settle the attempt as stopped while the child still ran.

What is held here:

* the adapter: a server found exited after the read is NOT a confirmed stop, whichever way it ended and whether or not it
  had been waited for, and also when it dies while ``ps`` is answering; it is closed all the same and the report names the
  reason. The escaped child is alive in every case: that is what a confirmation would have hidden;
* the opposite controls: a server that still runs when its tree is read is a confirmed stop as before, and a report that
  is covered but finds a survivor is still not a confirmation;
* the Consumer: such an attempt stays open as ``EXECUTOR_EXITED_BEFORE_OBSERVATION``, and neither a later complete read of
  the dead root nor the death of the child settles it (a table read after the fact is not a proof of what was never
  recorded).

The server is the FAKE one (``fake_codex_app_server.py``; its ``orphan`` setting starts the helper in a session of its own),
ended with SIGKILL the way a crash ends it. Nothing here is evidence about the real Codex.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from universal_agent_middleware.harness_adapter import (
    UNKNOWN,
    CodexAppServerClient,
    CodexServerSpec,
    StopReport,
    process_table,
    process_tree,
)
from universal_agent_middleware.task_control import TaskControlError

from consumer_world import CONSUMER, rule_for
from escaped_helper import adopting_orphans, end_helper, is_there
from test_consumer import ConsumerCase
from test_consumer_unconfirmed_stop import FAKE_SERVER, FakeCodex, helper_of, kill_helpers, wait_until

ADVISORY_PHASES = ("WAITING_OLD_EXECUTOR", "ATTEMPT_LEFT_OPEN")


def wait_until_a_zombie(pid: int, run: Callable[..., Any] = subprocess.run, timeout: float = 15.0) -> None:
    """Dead but not waited for: ``ps`` shows the state ``Z``. SIGKILL is not instantaneous, so the tests wait for this state
    instead of assuming it. ``run`` is the real ``subprocess.run`` unless a caller passes another."""

    def state() -> str:
        done = run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False, timeout=15)
        return str(done.stdout).strip()

    wait_until(lambda: state().startswith("Z"), timeout)


@contextmanager
def server_dies_when_ps_answers(pid: int) -> Iterator[None]:
    """For the time of the block the first ``/bin/ps`` read is answered truthfully and the server dies right after it: the
    table was read while the server ran, or just before it died, and the caller cannot tell which."""
    real, fired = subprocess.run, [False]

    def run(argv: Any, *args: Any, **kwargs: Any) -> Any:
        answer = real(argv, *args, **kwargs)
        if not fired[0] and isinstance(argv, (list, tuple)) and argv and argv[0] == "/bin/ps":
            fired[0] = True
            os.kill(pid, signal.SIGKILL)
            wait_until_a_zombie(pid, real)
        return answer

    subprocess.run = run  # type: ignore[assignment]
    try:
        yield
    finally:
        subprocess.run = real  # type: ignore[assignment]


@contextmanager
def server_has_exited_when_its_adapter_closes_it() -> Iterator[None]:
    """For the time of the block every ``CodexAppServerClient`` finds its server dead (SIGKILL, not waited for) at the moment
    ``close_and_report`` starts: what a crash after the turn looks like, with nothing recorded of what it started."""
    real = CodexAppServerClient.close_and_report

    def close_and_report(client: CodexAppServerClient) -> StopReport:
        os.kill(client.pid, signal.SIGKILL)
        wait_until_a_zombie(client.pid)
        return real(client)

    CodexAppServerClient.close_and_report = close_and_report  # type: ignore[method-assign]
    try:
        yield
    finally:
        CodexAppServerClient.close_and_report = real  # type: ignore[method-assign]


class ServerThatHasExitedTest(unittest.TestCase):
    """The adapter's client, over the FAKE server, ended the way a crash ends it."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="uam-exit-")).resolve()
        if not os.environ.get("UAM_KEEP_TEST_WORLDS"):
            self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()

    def server(self, name: str, **settings: Any) -> tuple[CodexAppServerClient, Path]:
        """A started FAKE server that has answered ``initialize`` (so the helper it starts, if any, exists)."""
        home, codex_home, log = self.root / name / "home", self.root / name / "codex-home", self.root / name / "requests.jsonl"
        home.mkdir(parents=True)
        codex_home.mkdir(parents=True)
        (codex_home / "fake.json").write_text(json.dumps({"log": str(log), **settings}), encoding="utf-8")
        spec = CodexServerSpec(argv=(sys.executable, str(FAKE_SERVER)), codex_home=str(codex_home), home=str(home))
        client = CodexAppServerClient(spec, cwd=str(self.cwd))
        self.enterContext(adopting_orphans())  # entered first, left last: the cleanups below still find this process the adopter
        self.addCleanup(kill_helpers, log)
        self.addCleanup(client.close)
        client.start()
        client.initialize()
        return client, log

    def assertNotConfirmedBecauseUncovered(self, stop: StopReport, helper: int | None = None) -> dict[str, Any]:
        self.assertFalse(stop.confirmed, "a read not shown to have been made while the server ran says nothing about what it started")
        report = stop.public()
        self.assertEqual((report["observation"], report["readback"], report["coverage"]), ("COMPLETE", "COMPLETE", "UNCOVERED"))
        self.assertIn("exited", report["coverage_failure"])
        self.assertEqual((report["close_returned_stopped"], report["group_alive"]), (True, False), "the server was closed all the same")
        self.assertEqual(report["still_running"], [], "no recorded process is there: the read-back is clean, and proves nothing")
        if helper is not None:
            self.assertTrue(is_there(helper), "the child that escaped into its own session is alive: the table could not show it")
        return report

    def test_a_server_that_died_and_was_not_waited_for_is_not_a_confirmed_stop_although_its_dead_root_is_in_the_tree(self) -> None:
        client, log = self.server("zombie", account="chatgpt", orphan=True)
        helper = helper_of(log, client.pid)
        os.kill(client.pid, signal.SIGKILL)
        wait_until_a_zombie(client.pid)
        self.assertEqual([item["pid"] for item in process_tree(client.pid)], [client.pid], "premise: ps lists the dead root, alone")
        self.assertIn(client.pid, process_table(), "premise: the tree 'contains the root', which is no proof that the server ran")
        stop = client.close_and_report()
        report = self.assertNotConfirmedBecauseUncovered(stop, helper)
        self.assertEqual([item["pid"] for item in report["processes_seen"]], [client.pid], "the dead root is all that was recorded")

    def test_a_server_that_died_and_was_waited_for_before_its_tree_was_read_is_not_a_confirmed_stop(self) -> None:
        client, log = self.server("reaped", account="chatgpt", orphan=True)
        helper = helper_of(log, client.pid)
        os.kill(client.pid, signal.SIGKILL)
        os.waitpid(client.pid, 0)  # waited for behind the client's back: no zombie, no row, and Popen finds no child
        self.assertNotIn(client.pid, process_table(), "premise: nothing is listed for the server any more")
        stop = client.close_and_report()
        report = self.assertNotConfirmedBecauseUncovered(stop, helper)
        self.assertEqual(report["processes_seen"], [], "an empty tree")

    def test_a_server_that_dies_while_the_table_is_being_read_is_not_a_confirmed_stop(self) -> None:
        client, _ = self.server("during", account="chatgpt")
        with server_dies_when_ps_answers(client.pid):
            stop = client.close_and_report()
        report = self.assertNotConfirmedBecauseUncovered(stop)
        # ``ps`` and the death cannot be put in order, so the read is not shown to have been made while the server ran,
        # although this table did list it as running: the conservative answer, not a finding about anything it started.
        self.assertEqual([item["pid"] for item in report["processes_seen"]], [client.pid])

    def test_a_server_that_still_runs_when_its_tree_is_read_is_a_confirmed_stop_as_before(self) -> None:
        client, _ = self.server("alive", account="chatgpt")
        stop = client.close_and_report()
        self.assertTrue(stop.confirmed)
        self.assertEqual((stop.close_returned_stopped, stop.group_alive, stop.still_running), (True, False, ()))
        self.assertEqual([item["pid"] for item in stop.processes_seen], [client.pid])

    def test_a_report_made_while_the_server_ran_says_so_and_a_survivor_still_makes_it_unconfirmed(self) -> None:
        clean, _ = self.server("alive", account="chatgpt")
        report = clean.close_and_report().public()
        self.assertEqual((report["coverage"], report["observation"], report["readback"], report["confirmed"]), ("COVERED", "COMPLETE", "COMPLETE", True))
        self.assertNotIn("coverage_failure", report)
        left, left_log = self.server("alive-with-helper", account="chatgpt", orphan=True)
        helper = helper_of(left_log, left.pid)
        survivor = left.close_and_report()
        self.assertFalse(survivor.confirmed, "a live server's child that closing the group does not reach is still found")
        report = survivor.public()
        self.assertEqual((report["coverage"], report["still_running"]), ("COVERED", [helper]))


class ServerThatHasExitedThroughTheConsumerTest(FakeCodex, ConsumerCase):
    """The real adapter and the real Consumer: what may be settled when the server was found exited after its tree was read."""

    AGENT = "codex-app-server"

    def agent_task(self, name: str) -> tuple[str, list[dict[str, Any]]]:
        return self.task(name), [{**rule_for(self.world, name, "write"), "adapter": self.AGENT, "session": "new"}]

    def life(self, rules: list[dict[str, Any]], adapter: Any) -> None:
        self.run_idle(self.consumer(rules, adapters={self.AGENT: adapter}))

    def advisories(self, delivery_id: str) -> list[tuple[str, str]]:
        return [(record["phase"], record["code"]) for record in self.records(delivery_id) if record["phase"] in ADVISORY_PHASES]

    def thread_starts(self, log: Path) -> int:
        entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
        return len([entry for entry in entries if entry.get("method") == "thread/start"])

    def assertStillOpen(self, delivery_id: str) -> None:
        """UAM has been told nothing: one attempt, active, no result, and its own gate still refuses a successor."""
        view = self.view(delivery_id)
        self.assertEqual((view["state"], len(view["attempts"]), view["attempts"][-1]["state"], view["result"]), ("ATTEMPT_ACTIVE", 1, "ACTIVE", None))
        self.assertTrue({"ATTEMPT_ENDED", "RESULT_SUBMITTED"}.isdisjoint(self.phases(delivery_id)))
        with self.assertRaises(TaskControlError) as refused:
            self.control.start_attempt(CONSUMER, delivery_id=delivery_id, lease_seconds=120)
        self.assertEqual(refused.exception.code, "ATTEMPT_ACTIVE")

    def test_an_attempt_whose_server_had_exited_stays_open_and_neither_the_dead_root_nor_the_childs_death_settles_it(self) -> None:
        adapter, log = self.codex(account="chatgpt", turn="complete", orphan=True)
        delivery_id, rules = self.agent_task("t-exited")
        with server_has_exited_when_its_adapter_closes_it():
            self.life(rules, adapter)
        self.assertStillOpen(delivery_id)
        ended = next(record for record in self.records(delivery_id) if record["phase"] == "EXECUTOR_ENDED")
        self.assertEqual((ended["status"], ended["code"], ended["stopped"]), (UNKNOWN, "TURN_COMPLETED", False))
        report = ended["binding"]["observed"]["stop_report"]
        spawn_pid = ended["binding"]["observed"]["spawn_pid"]
        self.assertEqual((report["coverage"], report["observation"], report["readback"], report["confirmed"]), ("UNCOVERED", "COMPLETE", "COMPLETE", False))
        self.assertEqual([item["pid"] for item in report["processes_seen"]], [spawn_pid], "the dead root is all that was recorded")
        helper = helper_of(log, spawn_pid)
        self.assertTrue(is_there(helper), "the child that escaped into its own session is alive")
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_EXITED_BEFORE_OBSERVATION")])
        end_helper(helper)
        self.life(rules, adapter)  # a later life with a healthy ps: every recorded identity is gone, which proves nothing
        self.assertStillOpen(delivery_id)
        self.assertEqual(self.advisories(delivery_id), [("ATTEMPT_LEFT_OPEN", "EXECUTOR_EXITED_BEFORE_OBSERVATION")])
        self.assertNotIn("STOP_RECONCILED", self.phases(delivery_id))
        self.assertEqual(self.thread_starts(log), 1, "no second execution")


if __name__ == "__main__":
    unittest.main()
