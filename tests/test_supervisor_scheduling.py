"""Supervisor scheduling: nothing is judged before it is refreshed, and no cycle stays silent.

The reality index is served for 300 s after it was written while the Supervisor ticks every 300 s,
so a refresh that reacts to a stale verdict always arrives one cycle late and the verdict alternates
between READY and DEGRADED. These tests pin the replacement:

- every cycle refreshes the required scopes before the Doctor looks at them, bounded, single-flight
  and never able to freeze the install;
- a probe that merely timed out is not a reason to restart the tunnel, and a policy file written
  before a failure class existed does not turn that class into a P0 freeze;
- every published verdict is dated, and a cycle that overruns its deadline says so.
"""
from __future__ import annotations

import fcntl
import json
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from synthetic_fixtures import init_git_repo
from test_hardening import healthy_checks, runtime_fixture  # noqa: F401  (pytest fixture import)

from universal_agent_middleware import supervisor as sup
from universal_agent_middleware.reality_index import DEFAULT_MAX_AGE_SEC
from universal_agent_middleware.runtime import SUPERVISOR_LOCK_NAME

ROOT = Path(__file__).resolve().parents[1]
UNCERTAIN_TUNNEL = {"status": "UNKNOWN", "uncertain": True, "stage": "health_endpoint", "reason": "timed out"}


def require_index(runtime, *scope_ids):
    scopes = [{"scope_id": scope_id, "root": f"/tmp/{scope_id}", "authority": {"discover": True, "index": True}}
              for scope_id in scope_ids]
    Path(runtime["root_scopes_file"]).write_text(
        json.dumps({"schema_version": "root-scope-registry-v1", "scopes": scopes}))


def worker(pid=4242, returncode=0, *, busy=False):
    proc = MagicMock()
    proc.pid = pid
    if busy:
        proc.wait.side_effect = subprocess.TimeoutExpired(cmd="index", timeout=1)
    else:
        proc.wait.return_value = returncode
    return proc


def state_file(runtime):
    return Path(runtime["recovery_root"]) / "index_refresh_cooldown.json"


def status_file(runtime):
    return Path(runtime["recovery_root"]) / "health_status.json"


def incidents(runtime):
    folder = Path(runtime["log_root"]) / "incidents"
    return [json.loads(path.read_text()) for path in sorted(folder.glob("*.json"))]


def degraded(**overrides):
    return {"overall": "DEGRADED", "checks": {**healthy_checks(), **overrides}}


def cycle(manifest, report):
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value=report):
        return sup.run_cycle(str(manifest))


# --- the budget -----------------------------------------------------------------------------

def test_a_cycle_fits_its_tick_and_a_refresh_may_start_again_before_the_index_expires():
    assert sup.INDEX_REFRESH_MIN_INTERVAL_SEC < DEFAULT_MAX_AGE_SEC
    longest_doctor = 60
    assert sup.INDEX_REFRESH_WAIT_SEC + longest_doctor < sup.CYCLE_DEADLINE_SEC < 300


# --- refreshing before judging ----------------------------------------------------------------

def test_every_required_scope_gets_its_own_enriched_detached_worker_and_the_cycle_waits_for_them(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha", "beta")
    with patch.object(sup.subprocess, "Popen", side_effect=[worker(11), worker(12)]) as popen:
        summary = sup.refresh_required_indexes(r, now=1000.0)
    assert summary["status"] == "refreshed"
    assert [item["state"] for item in summary["scopes"]] == ["completed", "completed"]
    for call, scope in zip(popen.call_args_list, ["alpha", "beta"]):
        command = call.args[0]
        assert command[command.index("--scope") + 1] == scope
        assert "--enrich-git" in command and command[:3] == [
            str(Path(r["current_release"]) / "venv/bin/python"), "-I", "-m"]
        assert call.kwargs["start_new_session"] is True
    recorded = json.loads(state_file(r).read_text())
    assert (recorded["last_spawn"], recorded["scopes"], recorded["pids"]) == (1000.0, ["alpha", "beta"], [11, 12])


def test_only_scopes_that_are_both_discoverable_and_indexable_are_refreshed(runtime_fixture):
    r, _, _ = runtime_fixture
    Path(r["root_scopes_file"]).write_text(json.dumps({"schema_version": "root-scope-registry-v1", "scopes": [
        {"scope_id": "no-index", "root": "/tmp/a", "authority": {"discover": True, "index": False}},
        {"scope_id": "no-discover", "root": "/tmp/b", "authority": {"discover": False, "index": True}},
        {"scope_id": "bare", "root": "/tmp/c"}]}))
    with patch.object(sup.subprocess, "Popen") as popen:
        summary = sup.refresh_required_indexes(r, now=1000.0)
    popen.assert_not_called()
    assert summary["status"] == "skipped" and not state_file(r).exists()


def test_a_refresh_waits_out_the_minimum_interval_and_then_runs_again(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    interval = sup.INDEX_REFRESH_MIN_INTERVAL_SEC
    with patch.object(sup, "_is_index_worker", return_value=False), \
         patch.object(sup.subprocess, "Popen", side_effect=lambda *a, **k: worker()) as popen:
        assert sup.refresh_required_indexes(r, now=1000.0)["status"] == "refreshed"
        early = sup.refresh_required_indexes(r, now=1000.0 + interval - 1)
        assert early["status"] == "skipped" and early["reason"] == "refreshed recently"
        assert popen.call_count == 1
        assert sup.refresh_required_indexes(r, now=1000.0 + interval)["status"] == "refreshed"
        assert popen.call_count == 2


def test_a_clock_that_moved_backwards_does_not_stop_the_index_from_being_refreshed(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    state_file(r).write_text(json.dumps({"last_spawn": 5000.0, "pids": []}))
    with patch.object(sup.subprocess, "Popen", return_value=worker()) as popen:
        assert sup.refresh_required_indexes(r, now=1000.0)["status"] == "refreshed"
    popen.assert_called_once()


def test_a_worker_that_is_still_running_is_never_duplicated(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    state_file(r).write_text(json.dumps({"last_spawn": 1.0, "pids": [777]}))
    with patch.object(sup, "_is_index_worker", return_value=True), \
         patch.object(sup.subprocess, "Popen") as popen:
        summary = sup.refresh_required_indexes(r, now=10_000.0)
    popen.assert_not_called()
    assert summary["status"] == "skipped" and summary["pids"] == [777]


def test_a_worker_that_outlives_the_wait_keeps_running_and_is_recorded(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    with patch.object(sup.subprocess, "Popen", return_value=worker(31, busy=True)):
        summary = sup.refresh_required_indexes(r, now=1000.0, wait_seconds=0.0)
    assert summary["status"] == "running"
    assert summary["scopes"] == [{"scope_id": "alpha", "state": "running", "pid": 31}]
    assert json.loads(state_file(r).read_text())["pids"] == [31]


def test_a_failing_worker_is_reported_and_leaves_the_judgement_to_the_doctor(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    with patch.object(sup.subprocess, "Popen", return_value=worker(returncode=3)):
        summary = sup.refresh_required_indexes(r, now=1000.0)
    assert summary["status"] == "failed"
    assert summary["scopes"][0]["state"] == "failed" and summary["scopes"][0]["returncode"] == 3


def test_a_worker_that_cannot_start_is_reported_without_raising_or_leaving_a_state(runtime_fixture):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    with patch.object(sup.subprocess, "Popen", side_effect=PermissionError("mock")):
        summary = sup.refresh_required_indexes(r, now=1000.0)
    assert summary["status"] == "failed"
    assert summary["scopes"] == [{"scope_id": "alpha", "state": "not_started", "error": "PermissionError"}]
    assert not state_file(r).exists()


@pytest.mark.parametrize("damage", ["not json", "[]", '{"pids": "x", "last_spawn": "y"}', '{"pids": [null, -1]}'])
def test_a_damaged_state_file_does_not_stop_the_refresh(runtime_fixture, damage):
    r, _, _ = runtime_fixture
    require_index(r, "alpha")
    state_file(r).write_text(damage)
    with patch.object(sup.subprocess, "Popen", return_value=worker()) as popen:
        assert sup.refresh_required_indexes(r, now=1000.0)["status"] == "refreshed"
    popen.assert_called_once()


def test_refreshing_never_raises_even_when_the_scope_registry_is_unreadable(runtime_fixture):
    r, _, _ = runtime_fixture
    summary = sup.refresh_required_indexes(dict(r, root_scopes_file=str(Path(r["config_root"]) / "gone.json")))
    assert summary["status"] == "failed" and "FileNotFoundError" in summary["reason"]


def test_the_worker_the_supervisor_starts_really_refreshes_the_index(runtime_fixture, tmp_path):
    """The command line is built here and run for real: a typo in a flag would only show in production."""
    r, _, _ = runtime_fixture
    code = tmp_path / "code"
    code.mkdir()
    init_git_repo(code / "alpha", files={"README.md": "# alpha\n"})
    Path(r["root_scopes_file"]).write_text(json.dumps({"schema_version": "root-scope-registry-v1", "scopes": [{
        "scope_id": "code", "root": str(code),
        "authority": {"discover": True, "index": True, "metadata_read": True, "git_observe": True}}]}))
    interpreter = Path(r["current_release"]) / "venv/bin/python"
    interpreter.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n')
    interpreter.chmod(0o700)

    summary = sup.refresh_required_indexes(r, wait_seconds=120)

    assert summary["status"] == "refreshed", summary
    database = Path(r["state_root"]) / "reality_index.db"
    with sqlite3.connect(database) as conn:
        enriched, count = conn.execute(
            "SELECT s.git_enriched, (SELECT COUNT(*) FROM instances) FROM active_generation a "
            "JOIN scope_snapshots s ON s.scope_id = a.scope_id AND s.generation_id = a.generation_id "
            "WHERE a.scope_id = 'code'").fetchone()
    assert (enriched, count) == (1, 1)


def completed(stdout, returncode=0):
    return subprocess.CompletedProcess(["ps"], returncode, stdout, "")


@pytest.mark.parametrize("answer,alive", [
    (completed("/x/venv/bin/python -I -m universal_agent_middleware.cli index --registry r\n"), True),
    (completed("/bin/bash unrelated\n"), False),
    (completed("", returncode=1), False),
    (subprocess.TimeoutExpired("ps", 5), True),
    (OSError("no ps"), True),
])
def test_a_worker_is_recognised_by_its_command_line_and_doubt_counts_as_alive(answer, alive):
    outcome = {"side_effect": answer} if isinstance(answer, BaseException) else {"return_value": answer}
    with patch.object(sup.subprocess, "run", **outcome):
        assert sup._is_index_worker(4242) is alive


@pytest.mark.parametrize("pid", [None, 0, -5, "12", True])
def test_a_pid_that_is_not_a_positive_integer_is_not_a_worker(pid):
    with patch.object(sup.subprocess, "run") as probe:
        assert sup._is_index_worker(pid) is False
    probe.assert_not_called()


# --- the order inside a cycle -------------------------------------------------------------------

def test_the_index_is_refreshed_before_the_doctor_judges_it_and_the_summary_is_published(runtime_fixture):
    r, manifest, _ = runtime_fixture
    order = []
    summary = {"status": "refreshed", "scopes": []}
    ready = {"overall": "READY", "checks": healthy_checks()}
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "refresh_required_indexes", side_effect=lambda runtime: order.append("refresh") or summary), \
         patch.object(sup, "doctor_process", side_effect=lambda *a: order.append("doctor") or dict(ready)):
        result = sup.run_cycle(str(manifest))
    assert order == ["refresh", "doctor"]
    assert result["overall"] == "READY" and result["index_refresh"] == summary
    assert json.loads(status_file(r).read_text())["index_refresh"] == summary


def test_the_runtime_is_read_again_once_the_lock_is_held(runtime_fixture):
    """`uam release` holds this lock while it switches the install, so a runtime read before waiting
    may describe the release that has just been replaced."""
    r, manifest, _ = runtime_fixture
    after_the_switch = {**r, "current_release": "/the/release/after/the/switch"}
    judged = []
    with patch.object(sup, "load_runtime", side_effect=[r, after_the_switch]), \
         patch.object(sup, "validate_release", side_effect=lambda runtime: judged.append(runtime["current_release"]) or {}), \
         patch.object(sup, "refresh_required_indexes", return_value={"status": "skipped"}), \
         patch.object(sup, "doctor_process", return_value={"overall": "READY", "checks": healthy_checks()}):
        sup.run_cycle(str(manifest))
    assert judged == ["/the/release/after/the/switch"]


def test_a_cycle_waits_while_another_party_holds_the_lock(runtime_fixture):
    r, manifest, _ = runtime_fixture
    entered = threading.Event()
    lock_path = Path(r["recovery_root"]) / SUPERVISOR_LOCK_NAME

    def cycle_in_thread():
        with patch.object(sup, "validate_release", side_effect=lambda runtime: entered.set() or {}), \
             patch.object(sup, "doctor_process", return_value={"overall": "READY", "checks": healthy_checks()}):
            sup.run_cycle(str(manifest))

    with lock_path.open("a+b") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)
        worker_thread = threading.Thread(target=cycle_in_thread)
        worker_thread.start()
        assert not entered.wait(0.5), "the cycle ran while the lock was held"
        fcntl.flock(holder, fcntl.LOCK_UN)
    assert entered.wait(30)
    worker_thread.join(30)


def test_a_frozen_install_gets_no_index_work(runtime_fixture):
    r, manifest, _ = runtime_fixture
    (Path(r["recovery_root"]) / "FROZEN.json").write_text(json.dumps({"failure_class": "runtime_path_failure"}))
    with patch.object(sup, "refresh_required_indexes") as refresh:
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
    refresh.assert_not_called()


def test_a_credential_failure_gets_no_index_work(runtime_fixture):
    r, manifest, _ = runtime_fixture
    (Path(r["credential_root"]) / "control_plane_api_key").write_text(" \n")
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "refresh_required_indexes") as refresh:
        assert sup.run_cycle(str(manifest))["failure_class"] == "credential_security_failure"
    refresh.assert_not_called()


# --- a probe that timed out is not a dead tunnel ----------------------------------------------------

def test_an_uncertain_tunnel_probe_is_logged_and_never_restarts_the_tunnel(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup.subprocess, "run") as external:
        result = cycle(manifest, degraded(tunnel=UNCERTAIN_TUNNEL))
    external.assert_not_called()
    assert result["overall"] == "DEGRADED" and not (Path(r["recovery_root"]) / "FROZEN.json").exists()
    assert not (Path(r["recovery_root"]) / "budget.json").exists()
    (receipt,) = incidents(r)
    assert (receipt["failure_class"], receipt["action"], receipt["affected_component"]) == (
        "tunnel_probe_uncertain", "log_only", "tunnel")


def test_a_tunnel_that_definitely_failed_is_still_restarted_within_its_budget(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as external:
        result = cycle(manifest, degraded(tunnel={"status": "FAIL", "stage": "listener"}))
    assert external.call_args.args[0][:3] == ["launchctl", "kickstart", "-k"]
    assert (result["failure_class"], result["restart_returncode"]) == ("tunnel_unavailable", 0)


def test_a_restart_request_that_times_out_is_uncertain_and_freezes_nothing(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup.subprocess, "run", side_effect=subprocess.TimeoutExpired("launchctl", 10)):
        result = cycle(manifest, degraded(tunnel={"status": "FAIL", "stage": "listener"}))
    assert (result["overall"], result["restart_state"]) == ("FAILED", "uncertain_timeout")
    assert result["restart_returncode"] is None
    assert not (Path(r["recovery_root"]) / "FROZEN.json").exists()
    (receipt,) = incidents(r)
    assert (receipt["failure_class"], receipt["action"], receipt["final_state"]) == (
        "tunnel_unavailable", "restart_tunnel", "FAILED")


def test_a_failure_class_missing_from_an_older_policy_file_is_logged_not_frozen(runtime_fixture):
    r, manifest, _ = runtime_fixture
    policy_file = Path(r["policy_file"])
    older = json.loads(policy_file.read_text())
    del older["policies"]["tunnel_probe_uncertain"]
    policy_file.write_text(json.dumps(older))
    with patch.object(sup.subprocess, "run") as external:
        result = cycle(manifest, degraded(tunnel=UNCERTAIN_TUNNEL))
    external.assert_not_called()
    assert result["overall"] == "DEGRADED" and not (Path(r["recovery_root"]) / "FROZEN.json").exists()
    assert incidents(r)[-1]["action"] == "log_only"


def test_a_p0_class_is_never_defaulted():
    with pytest.raises(KeyError):
        sup.policy_for({"policies": {}}, "audit_integrity_failure")
    assert sup.policy_for({"policies": {}}, "something_new")["action"] == "log_only"


def test_the_policy_file_shipped_with_the_repository_covers_the_new_classes():
    policies = sup.load_policies(ROOT / "tools/system-service/config/recovery_policies.yaml")["policies"]
    for failure in ("tunnel_probe_uncertain", "supervisor_cycle_timeout"):
        assert policies[failure]["action"] == "log_only"
    assert sup._component_for("tunnel_probe_uncertain") == "tunnel"
    assert sup._component_for("supervisor_cycle_timeout") == "supervisor"


# --- every verdict is dated ----------------------------------------------------------------------------

def test_every_published_verdict_carries_the_time_it_was_reached(runtime_fixture):
    r, manifest, _ = runtime_fixture
    before = time.time()
    cycle(manifest, {"overall": "READY", "checks": healthy_checks()})
    ready = json.loads(status_file(r).read_text())
    assert before <= ready["observed_at"] <= time.time() and ready["cycle_seconds"] >= 0

    with patch.object(sup, "validate_release", side_effect=ValueError("tampered")):
        sup.run_cycle(str(manifest))
    frozen = json.loads(status_file(r).read_text())
    assert frozen["overall"] == "FROZEN" and frozen["observed_at"] >= ready["observed_at"]

    later = time.time()
    sup.run_cycle(str(manifest))
    latched = json.loads(status_file(r).read_text())
    assert latched["reason"].startswith("persistent freeze latch") and latched["observed_at"] >= later


# --- a cycle that overruns its deadline ------------------------------------------------------------

@pytest.fixture
def alarm_guard():
    """Restores the process alarm state however the test ends."""
    handler = signal.getsignal(signal.SIGALRM)
    yield handler
    signal.alarm(0)
    signal.signal(signal.SIGALRM, handler)


def run_main(monkeypatch, manifest, slow_cycle):
    monkeypatch.setattr(sys, "argv", ["supervisor", "--runtime-manifest", str(manifest)])
    monkeypatch.setattr(sup, "CYCLE_DEADLINE_SEC", 1)
    monkeypatch.setattr(sup, "run_cycle", slow_cycle)
    return sup.main()


def test_a_cycle_that_overruns_its_deadline_publishes_a_timeout_instead_of_going_silent(
        runtime_fixture, monkeypatch, alarm_guard, capsys):
    r, manifest, _ = runtime_fixture
    started = time.time()
    assert run_main(monkeypatch, manifest, lambda m: time.sleep(30)) == 1
    assert time.time() - started < 10
    published = json.loads(status_file(r).read_text())
    assert (published["overall"], published["failure_class"]) == ("FAILED", "supervisor_cycle_timeout")
    assert published["observed_at"] >= started
    (receipt,) = incidents(r)
    assert (receipt["failure_class"], receipt["action"]) == ("supervisor_cycle_timeout", "log_only")
    assert json.loads(capsys.readouterr().out)["failure_class"] == "supervisor_cycle_timeout"
    assert signal.getsignal(signal.SIGALRM) is alarm_guard and signal.alarm(0) == 0


def test_the_deadline_never_overwrites_a_freeze(runtime_fixture, monkeypatch, alarm_guard, capsys):
    r, manifest, _ = runtime_fixture
    status_file(r).write_text(json.dumps({"overall": "FROZEN", "observed_at": 1.0}))
    (Path(r["recovery_root"]) / "FROZEN.json").write_text(json.dumps({"failure_class": "runtime_path_failure"}))
    assert run_main(monkeypatch, manifest, lambda m: time.sleep(30)) == 1
    assert json.loads(status_file(r).read_text()) == {"overall": "FROZEN", "observed_at": 1.0}
    assert json.loads(capsys.readouterr().out)["persisted"] is False


def test_the_deadline_is_not_mistaken_for_an_integrity_failure(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", side_effect=sup.CycleDeadlineExceeded(1)):
        with pytest.raises(sup.CycleDeadlineExceeded):
            sup.run_cycle(str(manifest))
    assert not (Path(r["recovery_root"]) / "FROZEN.json").exists()


def test_a_cycle_that_finishes_in_time_leaves_no_alarm_behind(runtime_fixture, monkeypatch, alarm_guard):
    r, manifest, _ = runtime_fixture
    result = {"overall": "READY", "checks": {}}
    assert run_main(monkeypatch, manifest, lambda m: result) == 0
    assert signal.alarm(0) == 0 and signal.getsignal(signal.SIGALRM) is alarm_guard
