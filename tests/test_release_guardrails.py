"""Release guardrails: a freeze is never cleared by the pipeline, acceptance is exact, and every
failure leaves a complete receipt.

Child processes are real (tiny shell scripts), so the bytes/str hazards of `subprocess` timeouts
are exercised rather than mocked away. Nothing here addresses the user's LaunchAgent: launchctl
is always a script under ``tmp_path`` with a throw-away label.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from release_fixtures import (
    STALE, canonical_manifest, doctor_report, executable, next_release, production_shaped,
    write_declaration,
)
from synthetic_fixtures import init_git_repo
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)

from universal_agent_middleware import release
from universal_agent_middleware.cli import main
from universal_agent_middleware.release import StepResult
from universal_agent_middleware.release_process import ProcessOutcome, run_bounded

OK = StepResult(True)


@dataclass
class Host:
    runtime: dict[str, Any]
    canonical: Path
    candidate: release._Candidate
    report: dict[str, Any]
    old_release: Path

    @property
    def uam(self) -> Path:
        return Path(self.runtime["uam_home"])

    @property
    def latch(self) -> Path:
        return Path(self.runtime["recovery_root"]) / "FROZEN.json"


@pytest.fixture
def make_host(runtime_fixture, tmp_path):
    def build(stale: tuple[str, ...]) -> Host:
        r, manifest, _ = runtime_fixture
        updated = production_shaped(r, manifest, tmp_path, stale=stale)
        report = doctor_report(updated, manifest)
        new = next_release(updated)
        report["instance"]["release_id"] = new.name
        return Host(updated, canonical_manifest(updated), release._Candidate(new, new.name), report,
                    Path(updated["current_release"]))
    return build


@pytest.fixture
def ready_host(make_host):
    return make_host(())


@pytest.fixture
def degraded_host(make_host):
    return make_host(STALE)


def doctor_run(report: dict[str, Any]) -> release._DoctorRun:
    return release._DoctorRun(report, None, "")


def replacing(name: str, outcome: Any):
    """Replace a collaborator by a fixed StepResult, or by a callable that is run instead."""
    return patch.object(release, name, **({"side_effect": outcome} if callable(outcome) else {"return_value": outcome}))


def run_release(host: Host, *, dry_run: bool = False, acceptance_path: str | None = None,
                stop: StepResult = OK, tunnel: StepResult = OK, index: StepResult = OK,
                reports: Any = None, stage: Any = None) -> tuple[dict[str, Any], SimpleNamespace]:
    """Run the real orchestrator with the host-touching collaborators replaced.

    ``reports`` is the sequence (or callable) of Doctor runs the replaced `_run_doctor` returns;
    ``stop`` and ``tunnel`` are the outcomes of stopping and starting the service.
    """
    reports = [doctor_run(host.report)] if reports is None else reports
    with patch.object(release, "_stage_candidate", side_effect=stage or (lambda run, runtime: host.candidate)) as staged, \
         replacing("_stop_tunnel", stop) as stopped, \
         replacing("_start_tunnel", tunnel) as started, \
         patch.object(release, "_refresh_index", return_value=index) as refresh, \
         patch.object(release, "_run_doctor", side_effect=reports) as doctor, \
         patch.object(release.time, "sleep"):
        result = release.build_and_activate(str(host.canonical), dry_run=dry_run, acceptance_path=acceptance_path)
    return result, SimpleNamespace(stage=staged, stop=stopped, start=started, refresh=refresh, doctor=doctor)


def step(result: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in result["steps"] if item["name"] == name)


def host_state(host: Host) -> dict[str, Any]:
    return {"current": os.readlink(host.uam / "current"), "global_manifest": host.canonical.read_bytes()}


def freeze(host: Host) -> Path:
    host.latch.write_text('{"reason": "operator resolution required", "evidence": "keep"}')
    return host.latch


# --- P1: the pipeline never clears or bypasses a freeze ---------------------------------------

@pytest.mark.parametrize("dry_run", [False, True])
def test_a_freeze_refuses_the_release_before_any_host_effect(ready_host, dry_run):
    latch = freeze(ready_host)
    original, mtime = latch.read_bytes(), latch.stat().st_mtime_ns
    before = host_state(ready_host)
    result, calls = run_release(ready_host, dry_run=dry_run)
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("FAILED", False, 1)
    assert result["failure_stage"] == "freeze_guard"
    assert step(result, "freeze_guard")["frozen"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert latch.read_bytes() == original and latch.stat().st_mtime_ns == mtime
    assert host_state(ready_host) == before
    assert result["activation"] == {"performed": False, "previous_release": ready_host.old_release.name,
                                    "active_release": {"release_id": ready_host.old_release.name,
                                                       "target": str(ready_host.old_release.resolve())}}
    for untouched in (calls.stage, calls.stop, calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def test_a_freeze_that_appears_while_staging_blocks_the_switch(ready_host):
    before = host_state(ready_host)

    def stage(run, runtime):
        freeze(ready_host)
        return ready_host.candidate

    result, calls = run_release(ready_host, stage=stage)
    assert result["failure_stage"] == "freeze_guard_pre_activate" and result["overall"] == "FAILED"
    assert host_state(ready_host) == before
    assert result["activation"]["performed"] is False
    calls.stop.assert_not_called()
    calls.start.assert_not_called()
    calls.refresh.assert_not_called()


def test_activate_refuses_under_a_freeze_and_leaves_everything_alone(ready_host):
    latch = freeze(ready_host)
    original = latch.read_bytes()
    before = host_state(ready_host)
    with pytest.raises(release.ReleaseError, match="FROZEN.json"):
        release._activate(ready_host.runtime, ready_host.candidate.release_dir)
    assert latch.read_bytes() == original
    assert host_state(ready_host) == before
    assert not os.path.lexists(ready_host.uam / "current.new")


@pytest.mark.parametrize("control", ["_stop_tunnel", "_start_tunnel"])
def test_the_service_controls_refuse_under_a_freeze_without_calling_launchctl(ready_host, tmp_path, control):
    latch = freeze(ready_host)
    original = latch.read_bytes()
    log = tmp_path / "launchctl.log"
    fake = executable(tmp_path / "bin" / "launchctl", f'echo "$@" >> "{log}"\n')
    plist = tmp_path / "tunnel.plist"
    plist.write_text("<plist/>")
    result = getattr(release, control)(ready_host.runtime, plist=plist, label="test.uam.tunnel",
                                       launchctl=str(fake))
    assert not result.ok and "frozen" in result.detail
    assert not log.exists()
    assert latch.read_bytes() == original


def test_a_freeze_found_after_the_switch_stops_further_host_changes(ready_host):
    refused = StepResult(False, "FROZEN.json present; tunnel start refused", {"frozen": {"path": "x"}})
    result, calls = run_release(ready_host, tunnel=refused)
    calls.refresh.assert_not_called()
    assert step(result, "index_refresh")["status"] == "SKIP"
    assert result["overall"] == "ACTIVATION_INCOMPLETE" and result["exit_code"] == 1


# --- P1: acceptance is exact and post-activation steps count ----------------------------------

def test_a_gap_free_release_with_every_step_passing_is_accepted(ready_host):
    result, _ = run_release(ready_host)
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("READY", True, 0)
    assert result["failure_stage"] is None
    assert result["activation"]["performed"] is True
    assert result["activation"]["active_release"]["release_id"] == ready_host.candidate.release_id
    assert result["activation"]["previous_release"] == ready_host.old_release.name
    assert os.readlink(ready_host.uam / "current") == str(ready_host.candidate.release_dir)
    json.dumps(result)


@pytest.mark.parametrize("tunnel_ok,index_ok,first_failure", [
    (False, True, "tunnel_start"), (True, False, "index_refresh"), (False, False, "tunnel_start")])
def test_a_ready_doctor_cannot_hide_a_failed_post_activation_step(ready_host, tunnel_ok, index_ok, first_failure):
    result, _ = run_release(ready_host,
                            tunnel=StepResult(tunnel_ok, "" if tunnel_ok else "tunnel boom"),
                            index=StepResult(index_ok, "" if index_ok else "index boom"))
    assert result["doctor_overall"] == "READY"
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("ACTIVATION_INCOMPLETE", False, 1)
    assert result["failure_stage"] == first_failure
    assert "post_steps_failed" in {item["code"] for item in result["acceptance"]["violations"]}
    assert result["activation"]["active_release"]["release_id"] == ready_host.candidate.release_id


def test_declared_gaps_are_accepted_end_to_end(degraded_host, tmp_path):
    declaration = write_declaration(tmp_path / "declaration.json")
    result, _ = run_release(degraded_host, acceptance_path=str(declaration))
    assert result["doctor_overall"] == "DEGRADED"
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("ACCEPTED_KNOWN_GAPS", True, 0)
    assert result["acceptance"]["mode"] == "declared_gaps"
    assert step(result, "acceptance_declaration")["sha256"] == hashlib.sha256(declaration.read_bytes()).hexdigest()
    assert len(step(result, "acceptance")["gaps"]) == 4


def test_the_same_gaps_without_a_declaration_keep_the_degraded_label_and_fail(degraded_host):
    result, _ = run_release(degraded_host)
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("DEGRADED", False, 1)
    assert result["failure_stage"] == "acceptance"


def test_an_extra_fault_beyond_the_declaration_is_not_accepted(degraded_host, tmp_path):
    report = copy.deepcopy(degraded_host.report)
    report["checks"]["audit_chain"] = {"status": "FAIL"}
    declaration = write_declaration(tmp_path / "declaration.json")
    result, _ = run_release(degraded_host, acceptance_path=str(declaration), reports=[doctor_run(report)])
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("DEGRADED", False, 1)
    assert {"code": "check_not_pass", "detail": "audit_chain=FAIL"} in result["acceptance"]["violations"]


def test_an_invalid_declaration_stops_before_anything_is_built(ready_host, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    result, calls = run_release(ready_host, acceptance_path=str(bad))
    assert result["failure_stage"] == "acceptance_declaration" and result["exit_code"] == 1
    calls.stage.assert_not_called()


def test_a_dry_run_never_activates_and_does_not_report_success(ready_host):
    before = host_state(ready_host)
    result, calls = run_release(ready_host, dry_run=True)
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("DRY_RUN", False, 1)
    assert result["activation"]["performed"] is False
    assert host_state(ready_host) == before
    for untouched in (calls.stop, calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def test_a_tunnel_that_is_still_starting_is_waited_for(ready_host):
    starting = copy.deepcopy(ready_host.report)
    starting["checks"]["tunnel"] = {"status": "FAIL"}
    starting.update(overall="DEGRADED", severity="P2")
    result, calls = run_release(ready_host, reports=[doctor_run(starting), doctor_run(ready_host.report)])
    assert result["overall"] == "READY" and calls.doctor.call_count == 2
    assert [attempt["doctor_overall"] for attempt in result["doctor_attempts"]] == ["DEGRADED", "READY"]


def test_any_other_failure_is_judged_once_and_never_waited_for(ready_host):
    broken = copy.deepcopy(ready_host.report)
    broken["checks"]["mcp"]["status"] = "FAIL"
    result, calls = run_release(ready_host, reports=[doctor_run(broken)])
    assert calls.doctor.call_count == 1 and result["accepted"] is False


def test_a_tunnel_that_never_recovers_ends_the_wait(ready_host):
    starting = copy.deepcopy(ready_host.report)
    starting["checks"]["tunnel"] = {"status": "FAIL"}
    starting.update(overall="DEGRADED", severity="P2")
    with patch.object(release, "READINESS_WINDOW", 0.05):
        result, calls = run_release(ready_host, reports=lambda manifest: doctor_run(starting))
    assert result["accepted"] is False and calls.doctor.call_count >= 2
    assert result["overall"] == "DEGRADED"
    assert {item["code"] for item in result["acceptance"]["violations"]} == {"check_not_pass"}


# --- failure receipts --------------------------------------------------------------------------

def test_a_doctor_timeout_still_produces_a_complete_receipt(ready_host):
    outcome = ProcessOutcome("doctor", None, True, 30.0, 30.02, b"partial \xff", b"")
    timed_out = release._DoctorRun(None, outcome, "Doctor timed out after 30s; process state is uncertain")
    result, _ = run_release(ready_host, reports=[timed_out])
    assert (result["overall"], result["doctor_overall"], result["exit_code"]) == ("ACTIVATION_INCOMPLETE", "ERROR", 1)
    doctor = step(result, "doctor")
    assert doctor["status"] == "ERROR" and doctor["process"]["timed_out"] is True
    assert "timed out" in doctor["reason"]
    assert result["activation"]["active_release"]["release_id"] == ready_host.candidate.release_id
    json.dumps(result)


def test_an_unexpected_exception_after_the_switch_is_recorded_not_raised(ready_host):
    with patch.object(release, "_verify_activation", side_effect=RuntimeError("probe exploded")):
        result, _ = run_release(ready_host)
    assert result["overall"] == "ACTIVATION_INCOMPLETE" and result["failure_stage"] == "unexpected_error"
    assert "probe exploded" in step(result, "unexpected_error")["reason"]
    assert result["activation"]["active_release"]["release_id"] == ready_host.candidate.release_id


def test_a_manifest_that_cannot_be_loaded_is_a_receipt_not_a_traceback(capsys):
    assert main(["release", "--runtime-manifest", "/nonexistent/uam-runtime.json", "--json"]) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["schema_version"] == "uam-release-receipt-v1"
    assert (receipt["overall"], receipt["accepted"], receipt["exit_code"]) == ("FAILED", False, 1)
    assert receipt["failure_stage"] == "load_runtime"
    assert receipt["orchestrator"]["python"] and receipt["orchestrator"]["module"].endswith("release.py")


def test_refresh_index_timeout_keeps_partial_bytes_out_of_the_way(tmp_path):
    python = executable(tmp_path / "python", "printf 'partial \\377 stderr' >&2\nexec sleep 5\n")
    result = release._refresh_index(python, {"registry_file": "/dev/null", "state_root": "/tmp"}, timeout=0.5)
    process = result.detail["process"]
    assert not result.ok and "timed out" in result.reason and "uncertain" in result.reason
    assert process["timed_out"] is True and process["returncode"] is None
    assert 0.4 <= process["elapsed_seconds"] < 4
    assert "partial" in process["stderr_tail"]
    json.dumps(result.detail)


@pytest.mark.parametrize("body,fragment", [
    ("echo 'index exploded' >&2\nexit 3\n", "rc=3"),
    ("echo 'index exploded' >&2\nexit 3\n", "index exploded"),
    ("echo 'not json'\n", "output is not a JSON object"),
    ("echo '[1, 2]'\n", "output is not a JSON object"),
])
def test_refresh_index_failures_are_receipts(tmp_path, body, fragment):
    python = executable(tmp_path / "python", body)
    result = release._refresh_index(python, {"registry_file": "/dev/null", "state_root": "/tmp"})
    assert not result.ok and result.reason.startswith("index refresh failed") and fragment in result.reason
    assert result.detail["process"]["stage"] == "index_refresh"


def test_refresh_index_that_cannot_start_is_a_receipt(tmp_path):
    result = release._refresh_index(tmp_path / "missing-python", {"registry_file": "/dev/null", "state_root": "/tmp"})
    assert not result.ok and "could not start" in result.reason
    assert result.detail["process"]["launch_error"].startswith("FileNotFoundError")


def test_refresh_index_success_uses_the_given_python_and_enriches_git(tmp_path):
    log = tmp_path / "argv.log"
    python = executable(tmp_path / "python", f'echo "$@" > "{log}"\necho \'{{"indexed": 1}}\'\n')
    result = release._refresh_index(python, {"registry_file": "/r/workspaces.json", "state_root": "/r/state"})
    assert result.ok
    argv = log.read_text().split()
    assert argv[:4] == ["-I", "-m", "universal_agent_middleware.cli", "index"] and "--enrich-git" in argv


@pytest.fixture
def doctor_python(ready_host):
    """The interpreter `_run_doctor` selects: the active release's venv python."""
    path = Path(ready_host.runtime["current_release"]) / "venv/bin/python"

    def install(body: str) -> None:
        executable(path, body)
    return install


@pytest.mark.parametrize("body,returncode", [("echo '{\"overall\": \"READY\"}'\n", 0),
                                             ("echo '{\"overall\": \"DEGRADED\"}'\nexit 1\n", 1)])
def test_run_doctor_parses_ready_and_degraded_exits(ready_host, doctor_python, body, returncode):
    doctor_python(body)
    run = release._run_doctor(str(ready_host.canonical))
    assert run.report["overall"] in {"READY", "DEGRADED"} and run.error == ""
    assert run.outcome.returncode == returncode


def test_run_doctor_timeout_is_an_error_with_a_receipt(ready_host, doctor_python):
    doctor_python("printf 'half a report \\377' \nexec sleep 5\n")
    run = release._run_doctor(str(ready_host.canonical), timeout=0.5)
    assert run.report is None and "timed out" in run.error
    assert run.outcome.timed_out and run.outcome.stdout.startswith(b"half a report")


@pytest.mark.parametrize("body,fragment", [("exit 2\n", "rc=2"), ("echo 'garbage'\n", "not a JSON object"),
                                            ("echo '[]'\n", "not a JSON object")])
def test_run_doctor_other_failures_are_errors(ready_host, doctor_python, body, fragment):
    doctor_python(body)
    run = release._run_doctor(str(ready_host.canonical))
    assert run.report is None and fragment in run.error


@pytest.fixture
def launchctl(tmp_path):
    log = tmp_path / "launchctl.log"
    plist = tmp_path / "tunnel.plist"
    plist.write_text("<plist/>")

    def install(body: str) -> dict[str, Any]:
        fake = executable(tmp_path / "bin" / "launchctl", f'echo "$1" >> "{log}"\n' + body)
        return {"plist": plist, "label": "test.uam.tunnel", "launchctl": str(fake)}

    def calls() -> list[str]:
        return log.read_text().split() if log.exists() else []
    return SimpleNamespace(install=install, calls=calls, plist=plist)


NOT_LOADED = '[ "$1" = print ] && exit 113\n'


def test_stop_tunnel_boots_out_and_confirms_that_launchd_no_longer_knows_the_service(ready_host, launchctl):
    result = release._stop_tunnel(ready_host.runtime, **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert result.ok and launchctl.calls() == ["bootout", "print"]
    assert result.detail["unload_check"]["returncode"] == 113


def test_stop_tunnel_waits_while_the_service_is_still_exiting(ready_host, launchctl, tmp_path):
    polls = tmp_path / "polls"
    options = launchctl.install(
        f'if [ "$1" = print ]; then\n  n=$(cat "{polls}" 2>/dev/null || echo 0)\n  echo $((n + 1)) > "{polls}"\n'
        '  [ "$n" -lt 2 ] && exit 0\n  exit 113\nfi\nexit 0\n')
    result = release._stop_tunnel(ready_host.runtime, poll_seconds=0.01, **options)
    assert result.ok and launchctl.calls() == ["bootout", "print", "print", "print"]


def test_stop_tunnel_gives_up_while_the_service_stays_loaded(ready_host, launchctl):
    result = release._stop_tunnel(ready_host.runtime, wait_seconds=0.05, poll_seconds=0.01,
                                  **launchctl.install("exit 0\n"))
    assert not result.ok and "still loaded" in result.reason and "nothing was switched" in result.reason


def ps_identity(pid: int) -> str:
    """What the service records as `process_identity`: the exact `ps` description of its child."""
    return subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="],
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def recorded_tunnel(ready_host):
    """A stand-in for the running tunnel-client, recorded the way the service records it."""
    child = subprocess.Popen(["sleep", "60"])
    identity = Path(ready_host.runtime["recovery_root"]) / "tunnel-identity.json"
    identity.write_text(json.dumps({"pid": child.pid, "process_identity": ps_identity(child.pid)}))
    yield child
    child.kill()
    child.wait()


def test_stop_tunnel_waits_for_the_old_process_to_exit_after_launchd_forgets_it(
        ready_host, launchctl, recorded_tunnel):
    def exit_and_reap():
        recorded_tunnel.terminate()
        recorded_tunnel.wait()
    threading.Timer(0.3, exit_and_reap).start()
    result = release._stop_tunnel(ready_host.runtime, poll_seconds=0.02, wait_seconds=10,
                                  **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert result.ok, result.reason
    assert result.detail["process_exit_check"]["returncode"] == 1


def test_stop_tunnel_refuses_to_switch_while_the_old_process_still_holds_the_port(
        ready_host, launchctl, recorded_tunnel):
    result = release._stop_tunnel(ready_host.runtime, wait_seconds=0.2, poll_seconds=0.02,
                                  **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert not result.ok and f"tunnel process {recorded_tunnel.pid} is still running" in result.reason
    assert "nothing was switched" in result.reason


def test_a_recorded_pid_that_now_describes_another_process_counts_as_gone(ready_host, launchctl, recorded_tunnel):
    identity = Path(ready_host.runtime["recovery_root"]) / "tunnel-identity.json"
    identity.write_text(json.dumps({"pid": recorded_tunnel.pid, "process_identity": "Mon Jan  1 00:00:00 2024 other"}))
    result = release._stop_tunnel(ready_host.runtime, **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert result.ok


@pytest.mark.parametrize("identity", ["not json", "[]", '{"pid": "7", "process_identity": "x"}',
                                      '{"pid": 0, "process_identity": "x"}', '{"pid": 7}'])
def test_an_unusable_identity_record_means_there_is_nothing_to_wait_for(ready_host, launchctl, identity):
    (Path(ready_host.runtime["recovery_root"]) / "tunnel-identity.json").write_text(identity)
    result = release._stop_tunnel(ready_host.runtime, **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert result.ok and "process_exit_check" not in result.detail


def test_a_ps_that_cannot_answer_leaves_the_state_uncertain(ready_host, launchctl, recorded_tunnel):
    with patch.object(release, "run_bounded", side_effect=lambda argv, **kw: (
            ProcessOutcome(kw["stage"], None, True, kw["timeout"], 0.0, b"", b"") if argv[0] == "ps"
            else run_bounded(argv, **kw))):
        result = release._stop_tunnel(ready_host.runtime, **launchctl.install(NOT_LOADED + "exit 0\n"))
    assert not result.ok and "uncertain" in result.reason and "nothing was switched" in result.reason


def test_bootout_of_a_service_that_is_not_loaded_is_not_an_error(ready_host, launchctl):
    result = release._stop_tunnel(ready_host.runtime, **launchctl.install(
        '[ "$1" = bootout ] && exit 3\n' + NOT_LOADED + "exit 0\n"))
    assert result.ok and result.detail["bootout"]["returncode"] == 3


def test_an_unexpected_answer_to_the_unload_check_leaves_the_state_uncertain(ready_host, launchctl):
    result = release._stop_tunnel(ready_host.runtime, **launchctl.install(
        '[ "$1" = print ] && { echo "domain refused" >&2; exit 2; }\nexit 0\n'))
    assert not result.ok and "uncertain" in result.reason and "rc=2" in result.reason
    assert "domain refused" in result.reason


def test_a_bootout_timeout_leaves_the_service_state_uncertain_and_checks_nothing_further(ready_host, launchctl):
    result = release._stop_tunnel(ready_host.runtime, timeout=0.4, **launchctl.install(
        '[ "$1" = bootout ] && exec sleep 5\nexit 0\n'))
    assert not result.ok and "timed out" in result.reason and "uncertain" in result.reason
    assert launchctl.calls() == ["bootout"]


def test_start_tunnel_only_bootstraps(ready_host, launchctl):
    result = release._start_tunnel(ready_host.runtime, **launchctl.install("exit 0\n"))
    assert result.ok and launchctl.calls() == ["bootstrap"]


def test_bootstrap_failure_is_reported_with_its_exit_status(ready_host, launchctl):
    result = release._start_tunnel(ready_host.runtime, **launchctl.install(
        '[ "$1" = bootstrap ] && { echo "service not found" >&2; exit 78; }\nexit 0\n'))
    assert not result.ok and "bootstrap failed" in result.reason
    assert "rc=78" in result.reason and "service not found" in result.reason


@pytest.mark.parametrize("control", ["_stop_tunnel", "_start_tunnel"])
def test_a_missing_plist_means_no_launchctl_call_at_all(ready_host, launchctl, tmp_path, control):
    options = launchctl.install("exit 0\n")
    options["plist"] = tmp_path / "missing.plist"
    result = getattr(release, control)(ready_host.runtime, **options)
    assert not result.ok and "plist not found" in result.reason and launchctl.calls() == []


@pytest.mark.parametrize("control", ["_stop_tunnel", "_start_tunnel"])
def test_a_launchctl_that_cannot_start_is_a_receipt(ready_host, launchctl, tmp_path, control):
    options = launchctl.install("exit 0\n")
    options["launchctl"] = str(tmp_path / "bin" / "no-such-launchctl")
    result = getattr(release, control)(ready_host.runtime, **options)
    assert not result.ok and "could not start" in result.reason


# --- the running service guards the manifest and `current`: it is stopped before either changes ---

def guarded_state(host: Host) -> tuple[str, bytes]:
    return os.readlink(host.uam / "current"), host.canonical.read_bytes()


def test_the_service_is_stopped_before_anything_it_guards_changes_and_started_after(ready_host):
    initial = guarded_state(ready_host)
    loaded, events = {"value": True}, []
    real_activate, real_update = release._activate, release._update_global_runtime

    def stop(runtime):
        events.append(("stop", guarded_state(ready_host) == initial))
        loaded["value"] = False
        return OK

    def activate(runtime, release_dir):
        events.append(("switch current", loaded["value"]))
        real_activate(runtime, release_dir)

    def update(manifest, release_dir):
        events.append(("update manifest", loaded["value"]))
        real_update(manifest, release_dir)

    def start(runtime):
        events.append(("start", guarded_state(ready_host) != initial))
        loaded["value"] = True
        return OK

    with patch.object(release, "_activate", side_effect=activate), \
         patch.object(release, "_update_global_runtime", side_effect=update):
        result, _ = run_release(ready_host, stop=stop, tunnel=start)
    assert events == [("stop", True), ("switch current", False), ("update manifest", False), ("start", True)]
    assert loaded["value"] is True and result["overall"] == "READY"
    assert [item["name"] for item in result["steps"] if item["name"].startswith("tunnel_")] == [
        "tunnel_stop", "tunnel_start"]


def test_a_service_that_cannot_be_stopped_blocks_the_switch(ready_host):
    before = host_state(ready_host)
    result, calls = run_release(ready_host, stop=StepResult(False, "still loaded 30s after bootout"))
    assert (result["overall"], result["failure_stage"], result["exit_code"]) == ("FAILED", "tunnel_stop", 1)
    assert result["activation"]["performed"] is False and host_state(ready_host) == before
    for untouched in (calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def test_a_switch_that_fails_puts_the_old_service_back(ready_host):
    before = host_state(ready_host)
    with patch.object(release, "_activate", side_effect=OSError("read-only file system")):
        result, calls = run_release(ready_host)
    assert [(item["name"], item["status"]) for item in result["steps"]][-3:] == [
        ("tunnel_stop", "OK"), ("activate", "FAIL"), ("tunnel_restore", "OK")]
    assert result["failure_stage"] == "activate" and result["activation"]["performed"] is False
    assert host_state(ready_host) == before
    calls.start.assert_called_once()
    calls.refresh.assert_not_called()
    calls.doctor.assert_not_called()


def test_a_manifest_update_that_fails_leaves_the_service_stopped_and_says_so(ready_host):
    with patch.object(release, "_update_global_runtime", side_effect=OSError("read-only file system")):
        result, calls = run_release(ready_host)
    update = next(item for item in result["steps"] if item["name"] == "update_runtime")
    assert update["status"] == "FAIL" and "not started" in update["service"]
    assert (result["overall"], result["failure_stage"]) == ("ACTIVATION_INCOMPLETE", "update_runtime")
    assert result["activation"]["performed"] is True
    for untouched in (calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def stage_runtime(host: Host) -> Path:
    """The release-internal runtime manifest exactly as the build writes it."""
    release._write_runtime_in_release(host.candidate.release_dir, host.runtime, str(host.canonical))
    return host.candidate.release_dir / "runtime" / "uam-runtime.json"


def test_updating_the_global_manifest_is_a_no_op_when_the_release_already_carries_it(ready_host):
    staged = stage_runtime(ready_host)
    release._activate(ready_host.runtime, ready_host.candidate.release_dir)
    before = (staged.read_bytes(), staged.stat().st_ino)
    release._update_global_runtime(str(ready_host.canonical), ready_host.candidate.release_dir)
    assert (staged.read_bytes(), staged.stat().st_ino) == before


def test_a_changed_global_manifest_is_replaced_atomically_and_keeps_its_mode(ready_host):
    staged = stage_runtime(ready_host)
    stale = json.loads(staged.read_text())
    stale["release_manifest_sha256"] = "0" * 64
    staged.write_text(json.dumps(stale, indent=2))
    staged.chmod(0o640)
    release._activate(ready_host.runtime, ready_host.candidate.release_dir)
    inode = staged.stat().st_ino
    release._update_global_runtime(str(ready_host.canonical), ready_host.candidate.release_dir)
    assert json.loads(staged.read_text())["release_manifest_sha256"] == release._sha256(
        ready_host.candidate.release_dir / "RELEASE_MANIFEST.json")
    assert staged.stat().st_ino != inode and staged.stat().st_mode & 0o777 == 0o640
    assert not [path for path in staged.parent.iterdir() if path.name.startswith(".")]


# The real service (`service.run_tunnel`) polls the sha256 of the runtime manifest and the target of
# `current` every 0.5 s and writes FROZEN.json when either differs from its start. This stands in for
# it with a real process so the order of operations is checked against actual behaviour.
GUARD = '''\
import hashlib, os, sys, time
from pathlib import Path

manifest, uam_home, latch, identity = (Path(arg) for arg in sys.argv[1:5])


def snapshot():
    return hashlib.sha256(manifest.read_bytes()).hexdigest(), (uam_home / "current").resolve()


started = snapshot()
identity.write_text(str(os.getpid()))
while True:
    try:
        aligned = snapshot() == started
    except OSError:
        aligned = False
    if not aligned:
        latch.write_text('{"overall": "FROZEN", "failure_class": "runtime_path_failure"}')
        break
    time.sleep(0.02)
'''


@pytest.fixture
def guard_service(ready_host, tmp_path):
    guard = tmp_path / "guard.py"
    guard.write_text(GUARD)
    identity = tmp_path / "guard.pid"

    def pid() -> int | None:
        try:
            value = int(identity.read_text())
            os.kill(value, 0)
            return value
        except (OSError, ValueError):
            return None

    def wait_for(condition, seconds: float = 5.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.01)
        return False

    log = tmp_path / "guard-launchctl.log"
    fake = executable(tmp_path / "guard-bin" / "launchctl", f'''echo "$1" >> "{log}"
case "$1" in
  bootout)
    pid=$(cat "{identity}" 2>/dev/null) && kill "$pid" 2>/dev/null
    i=0; while [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && [ $i -lt 200 ]; do sleep 0.01; i=$((i + 1)); done
    rm -f "{identity}"; exit 0 ;;
  print)
    pid=$(cat "{identity}" 2>/dev/null) && kill -0 "$pid" 2>/dev/null && exit 0
    exit 113 ;;
  bootstrap)
    rm -f "{identity}"
    nohup "{sys.executable}" "{guard}" "{ready_host.canonical}" "{ready_host.uam}" "{ready_host.latch}" "{identity}" >/dev/null 2>&1 &
    i=0; while [ ! -s "{identity}" ] && [ $i -lt 500 ]; do sleep 0.01; i=$((i + 1)); done
    exit 0 ;;
esac
''')
    plist = tmp_path / "guard.plist"
    plist.write_text("<plist/>")
    options = {"plist": plist, "label": "test.uam.tunnel", "launchctl": str(fake)}

    def start():
        assert release._start_tunnel(ready_host.runtime, **options).ok
        assert wait_for(lambda: pid() is not None)

    def stop():
        return release._stop_tunnel(ready_host.runtime, poll_seconds=0.01, **options)

    yield SimpleNamespace(start=start, stop=stop, pid=pid, wait_for=wait_for, log=log)
    running = pid()
    if running is not None:
        os.kill(running, signal.SIGKILL)


def test_the_stand_in_service_freezes_when_the_old_order_changes_what_it_guards(ready_host, guard_service):
    guard_service.start()
    release._activate(ready_host.runtime, ready_host.candidate.release_dir)
    assert guard_service.wait_for(ready_host.latch.exists), "the guard must notice a changed `current`"
    assert json.loads(ready_host.latch.read_text())["failure_class"] == "runtime_path_failure"


def test_stopping_the_service_first_leaves_no_freeze_and_a_service_that_matches_the_new_release(ready_host, guard_service):
    stage_runtime(ready_host)
    guard_service.start()
    old_pid = guard_service.pid()
    assert guard_service.stop().ok and guard_service.pid() is None
    release._activate(ready_host.runtime, ready_host.candidate.release_dir)
    release._update_global_runtime(str(ready_host.canonical), ready_host.candidate.release_dir)
    guard_service.start()
    assert guard_service.pid() not in (None, old_pid)
    assert not guard_service.wait_for(ready_host.latch.exists, seconds=0.5), "no freeze may appear"
    assert guard_service.pid() is not None
    assert guard_service.log.read_text().split() == ["bootstrap", "bootout", "print", "bootstrap"]


# --- fail-closed source identity --------------------------------------------------------------

def test_git_failure_is_an_error_and_never_an_empty_clean_answer(tmp_path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    with pytest.raises(release.ReleaseError, match="git rev-parse"):
        release._git(not_a_repo, "rev-parse", "HEAD")


def test_stage_candidate_stops_at_a_failing_git(ready_host, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    run = release._Run(str(ready_host.canonical), False, [], {})
    with patch.object(release, "_locate_source", return_value=(plain, "module")):
        assert release._stage_candidate(run, ready_host.runtime) is None
    assert [(item["name"], item["status"]) for item in run.steps] == [
        ("find_source", "OK"), ("git_identity", "FAIL")]


def test_stage_candidate_refuses_a_dirty_worktree_and_records_the_commit(ready_host, tmp_path):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "untracked.txt").write_text("dirty\n")
    run = release._Run(str(ready_host.canonical), False, [], {})
    with patch.object(release, "_locate_source", return_value=(repo, "cwd")):
        assert release._stage_candidate(run, ready_host.runtime) is None
    dirty = run.steps[-1]
    assert (dirty["name"], dirty["status"], dirty["entries"]) == ("git_clean", "FAIL", 1)
    assert len(run.result["source"]["commit"]) == 40 and run.result["source"]["selected_by"] == "cwd"


# --- CLI contract ------------------------------------------------------------------------------

@pytest.mark.parametrize("overall,exit_code", [
    ("READY", 0), ("ACCEPTED_KNOWN_GAPS", 0), ("DEGRADED", 1), ("ACTIVATION_INCOMPLETE", 1),
    ("DRY_RUN", 1), ("FAILED", 1)])
def test_the_cli_exit_code_is_the_receipts_exit_code(overall, exit_code, capsys):
    receipt = {"overall": overall, "accepted": exit_code == 0, "exit_code": exit_code, "steps": [],
               "release_id": "v0+x"}
    with patch("universal_agent_middleware.release.build_and_activate", return_value=receipt) as build:
        code = main(["release", "--runtime-manifest", "/x/uam-runtime.json", "--acceptance", "/x/gaps.json"])
    assert code == exit_code
    assert build.call_args.kwargs == {"manifest_path": "/x/uam-runtime.json", "dry_run": False,
                                      "acceptance_path": "/x/gaps.json"}
    assert f"release: {overall} (accepted={exit_code == 0}, exit={exit_code})" in capsys.readouterr().out


def test_without_an_acceptance_file_the_legacy_invocation_stays_strict():
    receipt = {"overall": "FAILED", "accepted": False, "exit_code": 1, "steps": []}
    with patch("universal_agent_middleware.release.build_and_activate", return_value=receipt) as build:
        main(["release", "--runtime-manifest", "/x/uam-runtime.json", "--dry-run"])
    assert build.call_args.kwargs["acceptance_path"] is None and build.call_args.kwargs["dry_run"] is True
