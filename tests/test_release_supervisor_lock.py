"""A release holds the Supervisor off while it switches the install.

The Supervisor validates the release and restarts a tunnel it finds down. Run in the middle of a
switch it would meet a service that is stopped on purpose, or a runtime manifest and a ``current``
that disagree for a moment, and could restart or freeze the install. The two exclude each other
through the Supervisor's cycle lock.
"""
from __future__ import annotations

import fcntl
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from test_release_guardrails import (  # noqa: F401  (pytest fixture imports)
    OK, doctor_run, host_state, make_host, ready_host, run_release, step,
)

from universal_agent_middleware import release
from universal_agent_middleware.runtime import SUPERVISOR_LOCK_NAME


def lock_path(runtime) -> Path:
    return Path(runtime["recovery_root"]) / SUPERVISOR_LOCK_NAME


def lock_is_held(runtime) -> bool:
    with lock_path(runtime).open("a+b") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


@contextmanager
def supervisor_cycle(runtime):
    """What a running Supervisor cycle does: hold the lock until it is finished."""
    with lock_path(runtime).open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield lock


def test_the_lock_is_held_from_before_the_service_stops_until_the_verdict_is_in(ready_host):
    runtime = ready_host.runtime
    held_during: dict[str, bool] = {}

    def observing(label):
        def call(*args, **kwargs):
            held_during[label] = lock_is_held(runtime)
            return OK
        return call

    def doctor(manifest):
        held_during["doctor"] = lock_is_held(runtime)
        return doctor_run(ready_host.report)

    result, _ = run_release(ready_host, stop=observing("stop"), tunnel=observing("start"), reports=doctor)

    assert result["overall"] == "READY"
    assert held_during == {"stop": True, "start": True, "doctor": True}
    assert not lock_is_held(runtime)
    names = [item["name"] for item in result["steps"]]
    assert names.index("supervisor_quiesce") < names.index("freeze_guard_pre_activate") < names.index("tunnel_stop")
    assert step(result, "supervisor_quiesce")["status"] == "OK"


def test_a_supervisor_cycle_that_keeps_the_lock_blocks_the_release_before_anything_changes(ready_host):
    before = host_state(ready_host)
    original = release._hold_supervisor_lock
    with supervisor_cycle(ready_host.runtime), \
         patch.object(release, "_hold_supervisor_lock",
                      side_effect=lambda runtime: original(runtime, wait_seconds=0.3, poll_seconds=0.01)):
        result, calls = run_release(ready_host)

    assert (result["overall"], result["failure_stage"]) == ("FAILED", "supervisor_quiesce")
    assert "nothing was changed" in step(result, "supervisor_quiesce")["reason"]
    assert result["activation"]["performed"] is False
    assert host_state(ready_host) == before
    for untouched in (calls.stop, calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def test_a_freeze_that_appears_while_the_lock_is_awaited_still_stops_the_release(ready_host):
    before = host_state(ready_host)
    original = release._hold_supervisor_lock

    def freezing_supervisor(runtime):
        held = original(runtime)
        (Path(runtime["recovery_root"]) / "FROZEN.json").write_text('{"reason": "frozen while waiting"}')
        return held

    with patch.object(release, "_hold_supervisor_lock", side_effect=freezing_supervisor):
        result, calls = run_release(ready_host)

    assert result["failure_stage"] == "freeze_guard_pre_activate"
    assert host_state(ready_host) == before
    calls.stop.assert_not_called()
    assert not lock_is_held(ready_host.runtime)


def test_the_lock_is_released_when_the_switch_fails(ready_host):
    refused = release.StepResult(False, "launchctl bootout timed out")
    result, _ = run_release(ready_host, stop=refused)
    assert result["failure_stage"] == "tunnel_stop"
    assert not lock_is_held(ready_host.runtime)


def test_a_dry_run_never_touches_the_lock(ready_host):
    with supervisor_cycle(ready_host.runtime):
        result, _ = run_release(ready_host, dry_run=True)
    assert result["overall"] == "DRY_RUN"
    assert "supervisor_quiesce" not in [item["name"] for item in result["steps"]]


def test_the_lock_is_exclusive_and_closing_the_handle_releases_it(ready_host):
    lock, outcome = release._hold_supervisor_lock(ready_host.runtime)
    assert outcome.ok and lock is not None
    assert lock_is_held(ready_host.runtime)
    lock.close()
    assert not lock_is_held(ready_host.runtime)


def test_a_running_cycle_is_waited_for_and_then_the_lock_is_taken(ready_host):
    with lock_path(ready_host.runtime).open("a+b") as cycle:
        fcntl.flock(cycle, fcntl.LOCK_EX)
        finishing = threading.Timer(0.3, lambda: fcntl.flock(cycle, fcntl.LOCK_UN))
        finishing.start()
        started = time.monotonic()
        lock, outcome = release._hold_supervisor_lock(ready_host.runtime, wait_seconds=30, poll_seconds=0.01)
        waited = time.monotonic() - started
        finishing.join()
    assert outcome.ok and lock is not None
    assert waited >= 0.25
    lock.close()


def test_giving_up_says_that_nothing_was_changed(ready_host):
    with supervisor_cycle(ready_host.runtime):
        lock, outcome = release._hold_supervisor_lock(ready_host.runtime, wait_seconds=0.2, poll_seconds=0.01)
    assert lock is None and not outcome.ok
    assert "still holds" in outcome.reason and "nothing was changed" in outcome.reason


def test_a_lock_that_cannot_be_opened_is_a_failed_step_not_an_exception(ready_host, tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    lock, outcome = release._hold_supervisor_lock({**ready_host.runtime, "recovery_root": str(blocker)})
    assert lock is None and not outcome.ok
    assert "cannot open" in outcome.reason
