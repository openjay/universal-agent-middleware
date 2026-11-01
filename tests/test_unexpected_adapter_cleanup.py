"""An exception nobody planned for inside the App Server conversation still closes the server.

The defect (D5 of the r2 audit, ``A-R2-D5-UNEXPECTED-CONVERSATION-CLEANUP``). ``CodexAppServerAdapter.run`` closed a started
server only after the conversation had answered or raised one of ``OSError``, ``TimeoutError``, ``JsonRpcError`` and
``KeyError``. Any other exception (here: an answer whose shape the client does not expect) propagated out of ``run`` with the
server still running, and so did an ``on_started`` callback that raised. The Consumer then recorded ``ADAPTER_RAISED`` with no
stop report: a server that nothing was going to close, and an attempt that could never be proven stopped.

What is held here:

* the server is closed on every way out, and the facts of that stop are kept: an unexpected exception is ``UNKNOWN`` (only
  the exception's type is kept of it) and ``stopped`` is what the observation says, so a child the server left makes it False;
* the opposite controls: a known protocol error is still a FAILED job with its own code, and an exception of the callback is
  still an exception (the server is closed first, then it propagates; it is not turned into an outcome);
* the Consumer settles such a job as a failed attempt whose server is closed, not as an adapter that raised.

The server is a small STAND-IN that the test writes (it answers with a result of the wrong shape, or refuses, and may leave a
helper in a session of its own). It is neither the fake Codex server nor the real one.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from universal_agent_middleware.harness_adapter import (
    FAILED,
    UNKNOWN,
    CodexAppServerAdapter,
    CodexServerSpec,
    ExecutorHandle,
    HarnessJob,
    HarnessOutcome,
    group_alive,
    process_table,
)

from consumer_world import rule_for
from test_consumer import ConsumerCase
from test_consumer_unconfirmed_stop import is_there

AGENT = "codex-app-server"
HELPER_COMMAND = "time.sleep(120)"
SERVER_COMMAND = "stand_in_server.py"

STAND_IN = '''\
"""STAND-IN server for tests, not Codex: JSON lines over stdio, one answer per request; settings in $CODEX_HOME/stand-in.json."""
import json
import os
import subprocess
import sys
from pathlib import Path

SETTINGS = json.loads((Path(os.environ["CODEX_HOME"]) / "stand-in.json").read_text())


def log(entry):
    with open(SETTINGS["log"], "a") as handle:
        handle.write(json.dumps(entry) + "\\n")


log({"pid": os.getpid()})
if SETTINGS.get("helper"):
    helper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    log({"helper_pid": helper.pid})
for raw in sys.stdin:
    message = json.loads(raw)
    if message.get("id") is None:
        continue
    method = message["method"]
    if method == "initialize":
        reply = {"result": {"userAgent": "stand-in/0"}}
    elif method == "account/read":
        reply = {"result": {"account": {"type": "chatgpt"}, "requiresOpenaiAuth": False}}
    elif SETTINGS["thread_start"] == "refuse":
        reply = {"error": {"code": -32000, "message": "refused"}}
    else:
        reply = {"result": []}
    sys.stdout.write(json.dumps({"id": message["id"], **reply}) + "\\n")
    sys.stdout.flush()
'''


def logged(log: Path, key: str) -> list[int]:
    lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return [entry[key] for entry in map(json.loads, lines) if key in entry]


def kill_stand_ins(log: Path) -> None:
    """SIGKILL the stand-in servers and helpers this test started, only while the PID still runs what the test started."""
    for key, marker in (("pid", SERVER_COMMAND), ("helper_pid", HELPER_COMMAND)):
        for pid in logged(log, key):
            if marker in process_table().get(pid, {}).get("command", ""):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class StandIns:
    """Mixin: the real Codex adapter over the stand-in server, in a directory of this test (``self.root``)."""

    root: Path
    addCleanup: Callable[..., None]

    def stand_in(self, name: str, *, thread_start: str, helper: bool = False) -> tuple[CodexAppServerAdapter, Path]:
        """``thread_start``: ``malformed`` answers ``thread/start`` with a list, ``refuse`` with a JSON-RPC error."""
        home, codex_home, log = self.root / name / "home", self.root / name / "codex-home", self.root / name / "stand-in.jsonl"
        home.mkdir(parents=True)
        codex_home.mkdir(parents=True)
        script = self.root / name / SERVER_COMMAND
        script.write_text(STAND_IN, encoding="utf-8")
        (codex_home / "stand-in.json").write_text(
            json.dumps({"log": str(log), "thread_start": thread_start, "helper": helper}), encoding="utf-8",
        )
        self.addCleanup(kill_stand_ins, log)
        spec = CodexServerSpec(argv=(sys.executable, str(script)), codex_home=str(codex_home), home=str(home))
        return CodexAppServerAdapter(spec), log


class UnexpectedExceptionInTheConversationTest(StandIns, unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="uam-unexpected-")).resolve()
        if not os.environ.get("UAM_KEEP_TEST_WORLDS"):
            self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()

    def run_job(
        self, adapter: CodexAppServerAdapter, on_started: Callable[[ExecutorHandle], None] | None = None,
    ) -> tuple[HarnessOutcome, list[ExecutorHandle]]:
        started: list[ExecutorHandle] = []

        def record(handle: ExecutorHandle) -> None:
            started.append(handle)
            if on_started is not None:
                on_started(handle)

        job = HarnessJob(
            delivery_id="dlv-" + "a" * 24, attempt_ref="att-" + "a" * 24 + ".1", fence=1, contract_id="c-1", workspace_id="ws-main",
            business_task_ref="task-1", owner_ref="owner-x", cwd=str(self.cwd), session="new", worker="w", objective="write the file",
            authoritative_paths=("inputs/spec.md",), allowed_change_paths=("out/a.md",), verification_commands=("true",),
            job_dir=str(self.root / "job"), deadline_seconds=20.0,
        )
        return adapter.run(job, on_started=record, keep_fds=()), started

    def test_an_exception_nobody_planned_for_closes_the_server_and_leaves_an_unknown_outcome_with_the_stop_facts(self) -> None:
        for helper in (False, True):
            with self.subTest(helper=helper):
                adapter, log = self.stand_in(f"unexpected-{helper}", thread_start="malformed", helper=helper)
                outcome, started = self.run_job(adapter)
                self.assertEqual((outcome.status, outcome.code), (UNKNOWN, "APP_SERVER_UNEXPECTED_ERROR"))
                self.assertTrue(outcome.detail.startswith("AttributeError"), "only the type of the exception is kept")
                self.assertNotIn("list", outcome.detail, "not its message")
                self.assertFalse(outcome.nothing_ran, "a server was started and a thread requested")
                self.assertFalse(group_alive(started[0].pgid), "the server is closed")
                self.assertFalse(is_there(started[0].pid))
                assert outcome.binding is not None
                report = outcome.binding["observed"]["stop_report"]
                self.assertEqual(outcome.binding["observed"]["spawn_pid"], started[0].pid)
                self.assertEqual((report["observation"], report["readback"], report["coverage"]), ("COMPLETE", "COMPLETE", "COVERED"))
                self.assertEqual((outcome.stopped, report["confirmed"]), (not helper, not helper))
                self.assertEqual(report["still_running"], logged(log, "helper_pid") if helper else [])
                if helper:
                    self.assertIn("not confirmed stopped", outcome.detail)
                    self.assertTrue(is_there(logged(log, "helper_pid")[0]), "the child that closing the group does not reach is alive")

    def test_a_known_protocol_error_is_still_a_failed_job_with_its_own_code(self) -> None:
        adapter, _ = self.stand_in("refused", thread_start="refuse")
        outcome, started = self.run_job(adapter)
        self.assertEqual((outcome.status, outcome.code, outcome.detail, outcome.stopped), (FAILED, "APP_SERVER_PROTOCOL_ERROR", "JsonRpcError", True))
        self.assertFalse(is_there(started[0].pid))

    def test_a_failing_started_callback_closes_the_server_and_is_not_turned_into_an_outcome(self) -> None:
        adapter, _ = self.stand_in("callback", thread_start="malformed")
        seen: list[int] = []

        def refuse(handle: ExecutorHandle) -> None:
            seen.append(handle.pid)
            raise RuntimeError("the callback broke")

        with self.assertRaises(RuntimeError):
            self.run_job(adapter, on_started=refuse)
        self.assertEqual(len(seen), 1, "the conversation never began")
        self.assertFalse(is_there(seen[0]), "the server the callback was told about is closed")
        self.assertFalse(group_alive(seen[0]))


class UnexpectedExceptionThroughTheConsumerTest(StandIns, ConsumerCase):
    def test_the_consumer_settles_it_as_a_failed_attempt_whose_server_is_closed_and_not_as_an_adapter_that_raised(self) -> None:
        adapter, _ = self.stand_in("consumer", thread_start="malformed")
        delivery_id = self.task("t-unexpected")
        rules: list[dict[str, Any]] = [{**rule_for(self.world, "t-unexpected", "write"), "adapter": AGENT, "session": "new"}]
        self.run_idle(self.consumer(rules, adapters={AGENT: adapter}))
        ended = next(record for record in self.records(delivery_id) if record["phase"] == "EXECUTOR_ENDED")
        self.assertEqual((ended["status"], ended["code"], ended["stopped"]), (UNKNOWN, "APP_SERVER_UNEXPECTED_ERROR", True))
        self.assertFalse(is_there(ended["binding"]["observed"]["spawn_pid"]), "its server is closed")
        attempt = self.view(delivery_id)["attempts"][-1]
        self.assertEqual((attempt["state"], attempt["end"]["how"]), ("ENDED", "REPORTED"))
        settled = [record for record in self.records(delivery_id) if record["phase"] == "ATTEMPT_ENDED"]
        self.assertEqual([(record["reported_outcome"], record["note"]) for record in settled], [("FAILED", "APP_SERVER_UNEXPECTED_ERROR")])
        self.assertEqual([record for record in self.records(delivery_id) if record["phase"] in ("WAITING_OLD_EXECUTOR", "ATTEMPT_LEFT_OPEN")], [])


if __name__ == "__main__":
    unittest.main()
