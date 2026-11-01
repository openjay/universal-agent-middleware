"""How a test ends the helper the fake server leaves behind: what it signals, what it says, and how it learns that the helper is gone.

Negative controls for ``escaped_helper``, which the Consumer's stop-evidence tests use to end that helper and then read the process
table. On Linux, in the first public CI run, the old way never sent a signal and said nothing: it looked for the helper's command line
in a table whose ``ps`` had cut the line short, so the helper kept running and every wait for it ran out. What is held here:

* a PID is signalled only while it runs the helper's command, read in full, whatever width ``ps`` would pick for itself;
* a command line that was cut short, a PID that runs another command and a ``ps`` that does not work are each a result or a failure
  that says so, never a silent no-op, and nothing is sent to a PID that is not the helper;
* a killed helper that nobody has waited for stays listed, and when this process is its adopter it waits for exactly that PID: never for
  another one (``waitpid(-1)``), and the helper keeps the place the tests observe it in (the server's child, a session of its own);
* the child-subreaper flag is given back as it was found.

The server is a small stand-in that starts the same helper the fake Codex server does. Nothing here is evidence about Codex.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import unittest
from collections.abc import Callable
from typing import Any
from unittest import mock

from escaped_helper import (
    ALREADY_DEAD,
    HELPER_COMMAND,
    NOT_LISTED,
    NOT_THE_HELPER,
    REAPED,
    SIGNALLED,
    adopting_orphans,
    child_subreaper,
    describe,
    drop_helper,
    end_helper,
    gone_within,
    is_there,
    kill_helper,
    listed_as,
    reap_once,
    set_child_subreaper,
)

LINUX = sys.platform.startswith("linux")
SERVER = """\
import subprocess, sys
pad = "x" * int(sys.argv[1])
helper = subprocess.Popen([sys.executable, "-c", f"pad = {pad!r}; import time; time.sleep(120)"], start_new_session=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(helper.pid, flush=True)
sys.stdin.read()
"""


def parent_of(pid: int) -> int:
    done = subprocess.run(["/bin/ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL)
    return int(done.stdout)


def wait_until(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition not reached in time")


def with_columns_80(argv: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """A ``ps`` started with the ``COLUMNS=80`` that ``readline`` leaves in the C environment under pytest. It is given as the child's ``env``: set in
    ``os.environ`` it would be unset again on the way out, for the C environment too, and every later test would run without it."""
    return subprocess.run(argv, *args, **{**kwargs, "env": {**os.environ, "COLUMNS": "80"}})


def cut_short(argv: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """A ``ps`` that, whatever it is asked, ends every row ten characters early, so the helper's marker is never there."""
    done = subprocess.run(argv, *args, **kwargs)
    return subprocess.CompletedProcess(argv, done.returncode, "".join(row[:-10] + "\n" for row in done.stdout.splitlines()), done.stderr)


def answer(code: int, text: str = "") -> Callable[..., subprocess.CompletedProcess[str]]:
    return lambda argv, *args, **kwargs: subprocess.CompletedProcess(argv, code, text, "ps: simulated")


class EndingTheHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.enterContext(adopting_orphans())  # entered first, left last, as the tests that own a fake server do

    def stand_in_server(self, pad: int = 0) -> tuple[subprocess.Popen[str], int]:
        """A server that has started its helper and waits for its stdin to close; the helper's PID. ``pad`` characters go in front of the
        helper's marker, so that its command line is as long as the test needs it to be: the interpreter's own path decides that otherwise."""
        server = subprocess.Popen([sys.executable, "-c", SERVER, str(pad)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert server.stdin is not None and server.stdout is not None
        self.addCleanup(server.wait)
        self.addCleanup(server.kill)
        self.addCleanup(server.stdout.close)
        helper = int(server.stdout.readline())
        self.addCleanup(drop_helper, helper)
        return server, helper

    def orphaned_helper(self, pad: int = 0) -> int:
        """The helper of a server that has exited: what the tests end."""
        server, helper = self.stand_in_server(pad)
        assert server.stdin is not None
        server.stdin.close()
        server.wait()
        return helper

    def test_the_helper_is_found_and_ended_whatever_width_ps_would_pick_for_itself(self) -> None:
        helper = self.orphaned_helper(pad=120)  # a command line longer than any width below, the marker at its very end
        if LINUX:  # procps takes the width COLUMNS names, and readline leaves COLUMNS=80 in the C environment of a pytest process
            narrow = with_columns_80(["/bin/ps", "-o", "stat=,command=", "-p", str(helper)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertNotIn(HELPER_COMMAND, narrow.stdout, "premise: a ps that takes that width cuts the row before the marker")
        self.assertEqual(kill_helper(helper, with_columns_80), SIGNALLED)
        self.assertTrue(gone_within(helper, 15.0))
        self.assertFalse(is_there(helper))

    def test_a_command_line_cut_short_is_not_taken_for_the_helper_and_nothing_is_sent(self) -> None:
        helper = self.orphaned_helper()
        with mock.patch("escaped_helper.os.kill") as sent:
            self.assertEqual(kill_helper(helper, cut_short), NOT_THE_HELPER)
        sent.assert_not_called()
        state, command = listed_as(helper) or ("Z", "")
        self.assertTrue(not state.startswith("Z") and HELPER_COMMAND in command, f"the helper is untouched: {describe(helper)}")
        self.assertEqual(kill_helper(helper), SIGNALLED, "read in full, the same PID is the helper")
        self.assertTrue(gone_within(helper, 15.0), "and it is waited for here, not left to whichever cleanup finds it first")

    def test_a_pid_that_runs_another_command_is_never_signalled_or_waited_for_and_end_helper_says_so(self) -> None:
        other = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        with mock.patch("escaped_helper.os.kill") as sent, mock.patch("escaped_helper.reap_once") as waited:
            self.assertEqual(kill_helper(other.pid), NOT_THE_HELPER)
            self.assertEqual(drop_helper(other.pid), NOT_THE_HELPER, "the cleanup leaves it alone as well")
            with self.assertRaises(AssertionError) as raised:
                end_helper(other.pid)
        sent.assert_not_called()
        waited.assert_not_called()
        self.assertIsNone(other.poll(), "and it still runs")
        self.assertIn(f"no signal was sent, PID {other.pid} is not the helper", str(raised.exception))
        self.assertIn("sleep", str(raised.exception), "the message carries what the PID runs")

    @unittest.skipUnless(LINUX, "a killed process nobody waits for stays listed on every machine, but only here is this process its parent")
    def test_a_helper_nobody_waits_for_fails_the_wait_with_its_state_and_its_parent(self) -> None:
        if child_subreaper() != 1:
            self.skipTest("the kernel refused the subreaper flag: whoever adopts the helper decides whether it stays listed")
        helper = self.orphaned_helper()
        with mock.patch("escaped_helper.reap_once", return_value="STILL_ALIVE"), self.assertRaises(AssertionError) as raised:
            end_helper(helper, timeout=0.5)  # killed, and this process, its parent, never waits for it
        self.assertIn(f"PID {helper} is still listed 0.5s after SIGNALLED", str(raised.exception))
        self.assertIn(f"{os.getpid()} Z", str(raised.exception), "the message has its parent and its state: killed, not waited for")
        self.assertEqual(reap_once(helper), REAPED, "the premise holds: it was this process's zombie")

    def test_what_ps_cannot_say_is_an_error_and_an_answer_of_no_such_process_is_an_absence(self) -> None:
        self.assertEqual(kill_helper(4_000_000, answer(1)), NOT_LISTED)
        for broken in (answer(2), answer(0), answer(0, "S a\nS b\n"), answer(1, "S what\n")):
            with self.assertRaises(AssertionError) as raised:
                kill_helper(4_000_000, broken)
            self.assertIn("ps could not tell what PID 4000000 is", str(raised.exception))

    def test_a_killed_helper_stays_listed_until_its_parent_waits_and_exactly_that_pid_is_waited_for(self) -> None:
        first_server, first = self.stand_in_server()
        second_server, second = self.stand_in_server()
        for server, helper in ((first_server, first), (second_server, second)):
            self.assertEqual(parent_of(helper), server.pid, "the helper is the server's child while the server runs")
            self.assertNotEqual(os.getsid(helper), os.getsid(0), "and has a session of its own")
            self.assertEqual(os.getsid(helper), helper)
        for server in (first_server, second_server):
            assert server.stdin is not None
            server.stdin.close()
            server.wait()
        adopter = parent_of(first)
        self.assertNotEqual(adopter, first_server.pid)
        mine = child_subreaper() == 1
        if mine:
            self.assertEqual((adopter, parent_of(second)), (os.getpid(), os.getpid()), "this process is the subreaper, so it adopts them")
        self.assertEqual(kill_helper(first), SIGNALLED)
        os.kill(second, signal.SIGKILL)  # behind the fixture's back: it is not the helper the test is ending
        if mine:
            wait_until(lambda: all((listed_as(pid) or ("", ""))[0].startswith("Z") for pid in (first, second)))
            self.assertTrue(is_there(first), "premise: killed, yet listed until its parent waits for it")
            self.assertEqual(kill_helper(first), ALREADY_DEAD, "a zombie is not signalled again")
            self.assertEqual(drop_helper(first), ALREADY_DEAD, "and the cleanup of a helper killed before waits for it all the same")
            self.assertFalse(is_there(first), "it is reaped: the zombie is not left to outlive the test")
        self.assertTrue(gone_within(first, 15.0))
        if mine:
            self.assertEqual((listed_as(second) or ("", ""))[0][:1], "Z", "exactly that PID was waited for, not every child")
            self.assertEqual(reap_once(second), REAPED)
        self.assertTrue(gone_within(second, 15.0))


class AdoptingOrphansTest(unittest.TestCase):
    @unittest.skipUnless(LINUX, "the child-subreaper flag is Linux's")
    def test_the_flag_found_is_the_flag_restored_and_nested_uses_share_one_setting(self) -> None:
        before = child_subreaper()
        self.assertIn(before, (0, 1))
        self.addCleanup(set_child_subreaper, bool(before))
        with adopting_orphans():
            self.assertEqual(child_subreaper(), 1)
            with adopting_orphans():
                self.assertEqual(child_subreaper(), 1)
            self.assertEqual(child_subreaper(), 1, "the inner use does not give the flag up under the outer one")
        self.assertEqual(child_subreaper(), before)

    @unittest.skipUnless(LINUX, "the child-subreaper flag is Linux's")
    def test_a_flag_somebody_else_had_set_is_left_set(self) -> None:
        before = child_subreaper()
        self.addCleanup(set_child_subreaper, bool(before))
        set_child_subreaper(True)
        with adopting_orphans():
            self.assertEqual(child_subreaper(), 1)
        self.assertEqual(child_subreaper(), 1)

    @unittest.skipIf(LINUX, "where there is no flag nothing is set")
    def test_where_there_is_no_flag_the_block_changes_nothing(self) -> None:
        with adopting_orphans():
            self.assertIsNone(child_subreaper())


if __name__ == "__main__":
    unittest.main()
