"""E (v0.6.1): a sealed activation that fails keeps the install isolated and never restarts the old release.

Before this, a failed switch after the service was stopped started the *previous* release again
(``tunnel_restore``), and every other failure after the stop left the Supervisor free to restart a
tunnel it found down. For a secure recovery the previous release may be exactly the one that had to
be taken out of service. A sealed run now fails closed: no step starts the previous release, and any
failure after the stop stops whatever may be running and writes the FROZEN.json latch (which the
service and the Supervisor honour). Runs without ``--expect-seal`` are unchanged.

Every case runs the real orchestrator, the real ``_stage_candidate`` and the real ``_switch_and_judge``;
only the collaborators that touch the host (the LaunchAgent, the index refresh, Doctor) are replaced.
"""
from __future__ import annotations

import copy
import json
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from test_release_activation_guard import world  # noqa: F401  (pytest fixture import)
from test_release_guardrails import (  # noqa: F401  (pytest fixture imports)
    OK, doctor_run, host_state, make_host, ready_host, replacing, step,
)

from universal_agent_middleware import release
from universal_agent_middleware import supervisor as sup
from universal_agent_middleware.release import StepResult


def run_sealed_with(world, *, stop: StepResult = OK, tunnel: StepResult = OK, index: StepResult = OK,
                    reports: list[Any] | None = None, activate: Any = None, update_runtime: Any = None,
                    verify: Any = None, lock: Any = None) -> tuple[dict[str, Any], SimpleNamespace]:
    """The real sealed orchestrator; ``activate``, ``update_runtime`` and ``verify`` inject a failure."""
    host = world.host
    reports = [doctor_run(host.report)] if reports is None else reports
    with ExitStack() as stack:
        stack.enter_context(patch.object(release, "_locate_source", return_value=(world.repo, "module")))
        stack.enter_context(patch.object(release, "_pre_activation_gates", side_effect=lambda *a, **k: True))
        stack.enter_context(patch.object(release, "_build_release", side_effect=AssertionError("must not build")))
        stopped = stack.enter_context(replacing("_stop_tunnel", stop))
        started = stack.enter_context(replacing("_start_tunnel", tunnel))
        refresh = stack.enter_context(patch.object(release, "_refresh_index", return_value=index))
        doctor = stack.enter_context(patch.object(release, "_run_doctor", side_effect=reports))
        stack.enter_context(patch.object(release.time, "sleep"))
        for name, failure in (("_activate", activate), ("_update_global_runtime", update_runtime),
                              ("_verify_activation", verify), ("_hold_supervisor_lock", lock)):
            if failure is not None:
                stack.enter_context(patch.object(release, name, side_effect=failure)
                                    if isinstance(failure, BaseException) or callable(failure)
                                    else patch.object(release, name, return_value=failure))
        result = release.build_and_activate(str(host.canonical), seal_path=str(world.seal_path))
    return result, SimpleNamespace(stop=stopped, start=started, refresh=refresh, doctor=doctor)


def latch_of(world) -> Path:
    return Path(world.host.runtime["recovery_root"]) / "FROZEN.json"


def outcomes(result: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["name"], item["status"]) for item in result["steps"]]


def names(result: dict[str, Any]) -> list[str]:
    return [item["name"] for item in result["steps"]]


def failed_check(world) -> dict[str, Any]:
    report = copy.deepcopy(world.host.report)
    report["checks"]["mcp"]["status"] = "FAIL"
    return report


# (what is injected, the first failing step, did this run start the service, did `current` switch)
FAILURES: dict[str, tuple[dict[str, Any], str, bool, bool]] = {
    "the switch raises OSError": ({"activate": OSError("read-only file system")}, "activate", False, False),
    "a freeze appears and the switch refuses": (
        {"activate": release.ReleaseError("FROZEN.json present; refusing to switch current")},
        "activate", False, False),
    "the manifest update raises OSError": (
        {"update_runtime": OSError("read-only file system")}, "update_runtime", False, True),
    "the service does not start": ({"tunnel": StepResult(False, "bootstrap failed (rc=5)")},
                                   "tunnel_start", True, True),
    "the index refresh fails": ({"index": StepResult(False, "index refresh failed (rc=3)")},
                                "index_refresh", True, True),
    "Doctor reports a failed check": ({"reports": "failed_check"}, "acceptance", True, True),
}


def inject(world, kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: ([doctor_run(failed_check(world))] if value == "failed_check" else value)
            for key, value in kwargs.items()}


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_a_failed_sealed_activation_never_restarts_the_previous_release_and_isolates_the_install(world, name):
    kwargs, first_failure, started, switched = FAILURES[name]
    result, calls = run_sealed_with(world, **inject(world, kwargs))

    assert (result["accepted"], result["exit_code"], result["failure_stage"]) == (False, 1, first_failure)
    assert "tunnel_restore" not in names(result)  # the previous release is never started again
    assert result["activation"]["performed"] is switched
    if started:
        order = names(result)
        assert order.index("activate") < order.index("tunnel_start")
        calls.start.assert_called_once()  # only the candidate, only after the switch
        assert calls.stop.call_count == 2 and step(result, "isolation_stop")["status"] == "OK"
    else:
        calls.start.assert_not_called()  # nothing at all was started
        calls.stop.assert_called_once()  # the stop that preceded the switch; there is nothing to stop again
        assert step(result, "isolation_stop")["status"] == "SKIP"

    latch = json.loads(latch_of(world).read_text())
    assert (latch["overall"], latch["severity"], latch["failure_class"]) == ("FROZEN", "P0", "sealed_activation_failed")
    assert first_failure in latch["evidence"]["failed_steps"]
    assert latch["evidence"]["candidate"] == world.release_dir.name
    assert step(result, "isolation_latch")["latch"] == "written"
    assert result["isolation"] == {"failure_class": "sealed_activation_failed", "latch": True,
                                   "reason": result["isolation"]["reason"], "service_may_have_run": started}
    assert names(result)[-2:] == ["isolation_stop", "isolation_latch"]
    json.dumps(result)


def test_an_accepted_sealed_activation_is_not_isolated(world):
    result, calls = run_sealed_with(world)
    assert (result["overall"], result["accepted"]) == ("READY", True), result["steps"]
    assert not latch_of(world).exists() and "isolation" not in result
    assert not [name for name in names(result) if name.startswith("isolation")]
    calls.stop.assert_called_once()
    calls.start.assert_called_once()


def test_an_unexpected_error_after_the_stop_isolates_and_is_still_a_complete_receipt(world):
    result, calls = run_sealed_with(world, verify=RuntimeError("probe exploded"))
    assert result["failure_stage"] == "unexpected_error" and "probe exploded" in step(result, "unexpected_error")["reason"]
    assert json.loads(latch_of(world).read_text())["failure_class"] == "sealed_activation_interrupted"
    assert calls.stop.call_count == 2 and step(result, "isolation_stop")["status"] == "OK"
    assert result["activation"]["performed"] is True
    json.dumps(result)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_an_interruption_after_the_stop_isolates_and_still_propagates(world, interruption):
    with pytest.raises(interruption):
        run_sealed_with(world, verify=interruption())
    latch = json.loads(latch_of(world).read_text())
    assert latch["failure_class"] == "sealed_activation_interrupted"
    assert latch["evidence"]["reason"].startswith(interruption.__name__)


def test_a_failure_while_isolating_never_masks_the_original_failure(world):
    with patch.object(release, "_isolate", side_effect=RuntimeError("isolation exploded")):
        with pytest.raises(KeyboardInterrupt):
            run_sealed_with(world, verify=KeyboardInterrupt())


def test_an_existing_latch_is_never_replaced(world):
    original = '{"reason": "operator resolution required", "evidence": "keep"}'

    def appears_and_refuses(runtime, release_dir):
        latch_of(world).write_text(original)
        raise release.ReleaseError("FROZEN.json present; refusing to switch current")

    result, calls = run_sealed_with(world, activate=appears_and_refuses)
    assert latch_of(world).read_text() == original
    assert step(result, "isolation_latch")["latch"] == "already_present" and step(result, "isolation_latch")["status"] == "OK"
    assert result["failure_stage"] == "activate"
    calls.start.assert_not_called()


def test_a_latch_that_cannot_be_written_is_a_failed_step_never_an_exception(world):
    with patch.object(release.os, "link", side_effect=OSError("no space left on device")):
        result, calls = run_sealed_with(world, activate=OSError("read-only file system"))
    assert not latch_of(world).exists()
    assert outcomes(result)[-1] == ("isolation_latch", "FAIL") and "cannot create the freeze latch" in result["steps"][-1]["reason"]
    assert result["isolation"]["latch"] is False and result["failure_stage"] == "activate"
    assert not [path for path in latch_of(world).parent.iterdir() if path.name.startswith(".FROZEN-")]
    calls.start.assert_not_called()


def test_a_latch_that_is_already_present_while_the_service_ran_is_not_stopped_again(world):
    def starts_and_freezes(runtime, **kwargs):
        latch_of(world).write_text('{"overall": "FROZEN", "failure_class": "runtime_path_failure"}')
        return StepResult(False, "FROZEN.json present; tunnel start refused", {"frozen": {"path": "x"}})

    result, calls = run_sealed_with(world, tunnel=starts_and_freezes)
    assert calls.stop.call_count == 1  # a service under a freeze exits by itself; stopping it is refused anyway
    assert step(result, "isolation_stop")["status"] == "SKIP" and step(result, "isolation_latch")["latch"] == "already_present"
    assert json.loads(latch_of(world).read_text())["failure_class"] == "runtime_path_failure"


def test_a_service_that_cannot_be_stopped_is_never_started_and_nothing_is_switched(world):
    before = host_state(world.host)
    result, calls = run_sealed_with(world, stop=StepResult(False, "still loaded 30s after bootout"))
    assert result["failure_stage"] == "tunnel_stop" and result["activation"]["performed"] is False
    assert host_state(world.host) == before and not latch_of(world).exists()
    for untouched in (calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()
    assert "tunnel_restore" not in names(result) and "isolation_latch" not in names(result)


def test_a_busy_supervisor_lock_changes_nothing(world):
    before = host_state(world.host)
    busy = (None, StepResult(False, "a Supervisor cycle still holds the lock after 300s; nothing was changed"))
    result, calls = run_sealed_with(world, lock=busy)
    assert result["failure_stage"] == "supervisor_quiesce" and host_state(world.host) == before
    for untouched in (calls.stop, calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()
    assert not latch_of(world).exists()


def test_the_supervisor_leaves_an_isolated_install_alone(world):
    """The latch is what keeps the Supervisor from starting a tunnel it finds down."""
    result, _ = run_sealed_with(world, activate=OSError("read-only file system"))
    written = latch_of(world).read_bytes()
    runtime = world.host.runtime
    with patch.object(sup, "doctor_process", side_effect=AssertionError("Doctor must not run under a freeze")), \
         patch.object(sup.subprocess, "run", side_effect=AssertionError("launchctl must not run under a freeze")):
        cycle = sup.run_cycle(str(world.host.canonical))
    assert cycle["overall"] == "FROZEN" and "latch" in cycle["reason"]
    assert latch_of(world).read_bytes() == written
    assert json.loads((Path(runtime["recovery_root"]) / "health_status.json").read_text())["overall"] == "FROZEN"
    assert result["failure_stage"] == "activate"


def test_without_a_seal_the_service_that_was_serving_is_still_started_again(ready_host):
    """Unsealed behaviour is unchanged: only a sealed run is a secure recovery."""
    with patch.object(release, "_activate", side_effect=OSError("read-only file system")), \
         patch.object(release, "_stage_candidate", side_effect=lambda run, runtime: ready_host.candidate), \
         replacing("_stop_tunnel", OK), replacing("_start_tunnel", OK) as started, \
         patch.object(release, "_refresh_index", return_value=OK), \
         patch.object(release, "_run_doctor", side_effect=[doctor_run(ready_host.report)]), \
         patch.object(release.time, "sleep"):
        result = release.build_and_activate(str(ready_host.canonical))
    assert outcomes(result)[-3:] == [("tunnel_stop", "OK"), ("activate", "FAIL"), ("tunnel_restore", "OK")]
    started.assert_called_once()
    assert not ready_host.latch.exists() and "isolation" not in result
