"""Ending the helper that the FAKE Codex server leaves in a session of its own, and learning that it is gone.

``fake_codex_app_server.py`` (setting ``orphan``) starts ``python -c "import time; time.sleep(120)"`` in a session of its own and does
not wait for it, so once the adapter has closed the server the helper's parent is whatever adopts orphans on the machine. A test that
needs that helper gone (a Consumer life must then read every recorded process as absent) ends it itself, and this is how. It exists
because ending it the old way never sent a signal on Linux, and nothing said so:

* Identity. A PID is signalled only while it still runs the helper's command, and that command is read in full (``ps -ww``). It used to
  be read from the product's ``process_table()``, whose ``ps`` takes its width from ``COLUMNS``. pytest imports ``readline`` at
  start-up (``_pytest.capture._readline_workaround``) and ``readline`` exports ``LINES`` and ``COLUMNS`` into the C environment without
  touching ``os.environ``, so a child started without an ``env`` (as ``process_table()`` does) inherits ``COLUMNS=80``. procps ``ps``
  obeys it: the command column ended before the marker, the guard refused a process that was the helper, no signal was sent, and the
  wait for the PID to disappear ran out with the helper still sleeping. BSD ``ps`` does not cut, which is why macOS never showed it.
* Results, not silence. ``kill_helper`` says what it did; ``end_helper`` fails, naming the PID, its state, its parent and its command,
  when no signal was sent or the PID is still listed afterwards.
* Reaping. A killed process stays listed as ``Z`` until its parent waits for it, and the adopter of orphans on a machine (PID 1 of a
  container started without ``--init``, for one) may never do so. While a test owns a helper this process is the child subreaper
  (Linux ``prctl``) and waits for exactly that PID, never ``waitpid(-1)``. What the tests observe is unchanged: the helper is the server's
  child while the server runs, it has a session of its own, and the product reads the PID and the command line of a process the server
  no longer owns, not its parent.
"""
from __future__ import annotations

import contextlib
import ctypes
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any

from universal_agent_middleware.harness_adapter import process_table

HELPER_COMMAND = "time.sleep(120)"

SIGNALLED = "SIGNALLED"  # the PID ran the helper's command: SIGKILL was sent
NOT_LISTED = "NOT_LISTED"  # nothing is listed under the PID: nothing was sent
ALREADY_DEAD = "ALREADY_DEAD"  # listed as a zombie, killed before and waiting for its parent: nothing was sent
NOT_THE_HELPER = "NOT_THE_HELPER"  # listed and running another command: nothing was sent (a reused PID is never touched)

REAPED, STILL_ALIVE, NOT_MINE = "REAPED", "STILL_ALIVE", "NOT_MINE"

_PR_SET_CHILD_SUBREAPER, _PR_GET_CHILD_SUBREAPER = 36, 37  # <linux/prctl.h>


def is_there(pid: int) -> bool:
    """Whether the PID is a row of the table the Consumer reads, a zombie included."""
    return pid in process_table()


def listed_as(pid: int, run: Callable[..., Any] = subprocess.run) -> tuple[str, str] | None:
    """``(state, whole command line)`` of the PID, or ``None`` when nothing is listed under it. A ``ps`` that fails, or answers
    with anything but one row, raises: what a PID is is never guessed from a read that did not work."""
    done = run(
        ["/bin/ps", "-ww", "-o", "stat=,command=", "-p", str(pid)],
        capture_output=True, text=True, check=False, timeout=15, stdin=subprocess.DEVNULL,
    )
    rows = [row for row in str(done.stdout).splitlines() if row.strip()]
    if not rows and done.returncode == 1:  # procps and BSD ps: no process with that PID
        return None
    if done.returncode != 0 or len(rows) != 1:
        raise AssertionError(f"ps could not tell what PID {pid} is: exit {done.returncode}, {len(rows)} rows, stderr {str(done.stderr).strip()!r}")
    state, _, command = rows[0].strip().partition(" ")
    return state, command.strip()


def describe(pid: int, run: Callable[..., Any] = subprocess.run) -> str:
    """What is known of the PID for a failure message: PID, parent, state and the end of the command line."""
    done = run(
        ["/bin/ps", "-ww", "-o", "pid=,ppid=,stat=,command=", "-p", str(pid)],
        capture_output=True, text=True, check=False, timeout=15, stdin=subprocess.DEVNULL,
    )
    row = " ".join(str(done.stdout).split())
    return f"[pid ppid state command] {row if len(row) <= 140 else '...' + row[-137:]}" if row else "no process is listed under it"


def kill_helper(pid: int, run: Callable[..., Any] = subprocess.run) -> str:
    """SIGKILL a helper this test caused, only while that PID still runs the helper's command, and say what was done."""
    listed = listed_as(pid, run)
    if listed is None:
        return NOT_LISTED
    state, command = listed
    if state.startswith("Z"):
        return ALREADY_DEAD
    if HELPER_COMMAND not in command:
        return NOT_THE_HELPER
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return NOT_LISTED
    return SIGNALLED


def reap_once(pid: int) -> str:
    """``waitpid`` for exactly this PID, without blocking. ``REAPED``: it was a child of this process and had died. ``STILL_ALIVE``: a
    child, not dead yet. ``NOT_MINE``: not a child of this process, so whoever its parent is reaps it."""
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return NOT_MINE
    return REAPED if done == pid else STILL_ALIVE


def gone_within(pid: int, timeout: float) -> bool:
    """Whether the PID leaves the process table in time, reaping it when this process is its parent. A table that cannot be read is an
    error, not an absence. After a reap the PID is not waited for again: it may belong to another process by then."""
    deadline = time.monotonic() + timeout
    reaped = False
    while True:
        reaped = reaped or reap_once(pid) == REAPED
        if pid not in process_table(strict=True):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def end_helper(pid: int, timeout: float = 15.0) -> None:
    """Kill the helper and wait until it is gone, for a test that goes on to read the table. Fails, with the facts of the PID, when no signal
    was sent because the PID is not the helper, or when it is still listed after the signal."""
    receipt = kill_helper(pid)
    if receipt == NOT_THE_HELPER:
        raise AssertionError(f"no signal was sent, PID {pid} is not the helper: {describe(pid)}")
    if not gone_within(pid, timeout):
        raise AssertionError(f"PID {pid} is still listed {timeout:g}s after {receipt}: {describe(pid)}")


def drop_helper(pid: int, timeout: float = 2.0) -> str:
    """Cleanup: ``kill_helper``, then a bounded wait for it to be gone (a helper the test killed itself is waited for too). What it finds is
    returned, not raised: a PID that is not the helper is left alone."""
    receipt = kill_helper(pid)
    if receipt in (SIGNALLED, ALREADY_DEAD):
        gone_within(pid, timeout)
    return receipt


def child_subreaper() -> int | None:
    """The kernel's child-subreaper flag of this process (0 or 1), ``None`` where there is none (macOS: launchd reaps) or it cannot be read."""
    if not sys.platform.startswith("linux"):
        return None
    flag = ctypes.c_int(0)
    refused = ctypes.CDLL(None, use_errno=True).prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(flag), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    return None if refused else flag.value


def set_child_subreaper(on: bool) -> None:
    """Set the flag (Linux only); a kernel that refuses leaves it as it was."""
    ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(int(on)), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))


class _Adopting:
    """The flag belongs to the process, so nested uses share one setting; the last one out restores what the first one found."""

    uses = 0
    found: int | None = None


@contextlib.contextmanager
def adopting_orphans() -> Iterator[None]:
    """Linux: for the time of the block this process adopts the orphans of its descendants (child subreaper), so that it can wait for a
    helper it killed instead of leaving that to the machine's PID 1. Nothing is reaped by this alone, and elsewhere it does nothing. If the
    kernel refuses, nothing changes and ``end_helper`` reports a helper that stays listed, with its state and parent."""
    if not sys.platform.startswith("linux"):
        yield
        return
    if _Adopting.uses == 0:
        _Adopting.found = child_subreaper()
        set_child_subreaper(True)
    _Adopting.uses += 1
    try:
        yield
    finally:
        _Adopting.uses -= 1
        if _Adopting.uses == 0 and _Adopting.found == 0:
            set_child_subreaper(False)
