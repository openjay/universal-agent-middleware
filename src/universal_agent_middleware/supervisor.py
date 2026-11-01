"""One bounded recovery cycle. Persistent P0 latch requires explicit operator resolution."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .runtime import SUPERVISOR_LOCK_NAME, atomic_json, check_credential, load_runtime, validate_release

P0_FAILURES = {"audit_integrity_failure", "credential_security_failure", "release_manifest_failure",
               "runtime_path_failure", "restart_storm", "recovery_state_failure"}

# One cycle must fit inside the launchd tick (300 s), and the reality index is only served for
# DEFAULT_MAX_AGE_SEC (300 s) after it was written. A refresh that reacts to a stale verdict is
# therefore always one cycle late, so the index is refreshed before each Doctor run instead:
#   INDEX_REFRESH_WAIT_SEC + Doctor timeout (<= 60 s) < CYCLE_DEADLINE_SEC < 300 s
# and a refresh may start again after INDEX_REFRESH_MIN_INTERVAL_SEC < DEFAULT_MAX_AGE_SEC.
INDEX_REFRESH_MIN_INTERVAL_SEC = 120.0
INDEX_REFRESH_WAIT_SEC = 90.0
CYCLE_DEADLINE_SEC = 240

# A policy file is copied from the previous release, so a failure class introduced by this release
# may be missing from it. Looking it up must never turn into a P0 freeze: only P0 classes are
# mandatory in the file (load_policies enforces that), every other class falls back to logging.
_DEFAULT_POLICY = {"severity": "P2", "action": "log_only", "auto_repair": False}

_COMPONENT_MAP = {
    "audit_integrity_failure": "audit",
    "credential_security_failure": "credential",
    "release_manifest_failure": "release",
    "runtime_path_failure": "runtime",
    "restart_storm": "tunnel",
    "recovery_state_failure": "supervisor",
    "supervisor_cycle_timeout": "supervisor",
    "doctor_timeout": "doctor",
    "doctor_output_invalid": "doctor",
    "core_semantic_failure": "core",
    "tunnel_unavailable": "tunnel",
    "tunnel_probe_uncertain": "tunnel",
    "reality_index_stale": "reality_index",
    "reality_index_missing": "reality_index",
    "reality_index_policy_mismatch": "reality_index",
    "reality_index_locked": "reality_index",
    "reality_index_integrity_failure": "reality_index",
    "reality_index_schema_incompatible": "reality_index",
    "workspace_degraded": "workspace",
}


class CycleDeadlineExceeded(BaseException):
    """Raised by the cycle alarm.

    Deliberately not an Exception: ``run_cycle`` turns every Exception into a P0 freeze, and a host
    that is merely too slow to finish a cycle is not an integrity failure.
    """


def _component_for(failure_class: str) -> str:
    return _COMPONENT_MAP.get(failure_class, failure_class.split("_")[0])


def load_policies(path: Path) -> dict[str, Any]:
    # JSON is a strict YAML subset. No YAML runtime dependency or second policy parser.
    value = json.loads(path.read_text())
    if value.get("schema") != "UAM_RECOVERY_POLICIES_V2":
        raise ValueError("unsupported recovery policy schema")
    policies = value["policies"]
    for name in P0_FAILURES:
        policy = policies[name]
        if policy != {"severity": "P0", "action": "freeze", "auto_repair": False}:
            raise ValueError(f"P0 policy cannot permit repair: {name}")
    for policy in policies.values():
        if policy.get("action") not in {"freeze", "log_only", "restart_tunnel"}:
            raise ValueError("unsupported recovery action")
        if policy["action"] == "restart_tunnel":
            for field in ("max_attempts", "window_seconds"):
                if type(policy.get(field)) is not int or policy[field] <= 0:
                    raise ValueError("invalid recovery budget")
    if type(value.get("doctor_timeout_seconds")) is not int or not 1 <= value["doctor_timeout_seconds"] <= 60:
        raise ValueError("invalid Doctor timeout")
    return value


def policy_for(policies: dict[str, Any], failure: str) -> dict[str, Any]:
    """The policy for a failure class; a class the file does not know is logged, never acted on."""
    if failure in P0_FAILURES:
        return policies["policies"][failure]
    return policies["policies"].get(failure, _DEFAULT_POLICY)


def consume_budget(path: Path, policy: dict[str, Any], now: float) -> bool:
    """Must be called under cycle flock; all restart classes share one budget."""
    data = json.loads(path.read_text()) if path.exists() else {"schema": 1, "tunnel_restarts": []}
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("tunnel_restarts"), list):
        raise ValueError("invalid recovery budget")
    entries = data["tunnel_restarts"]
    if any(type(t) not in (int, float) or not 0 <= t <= now for t in entries):
        raise ValueError("invalid recovery timestamp or clock rollback")
    # Keep every timestamp: pruning by a short policy window would erase a longer budget.
    count = sum(t > now - policy["window_seconds"] for t in entries)
    if count >= policy["max_attempts"]:
        return False
    entries.append(now)
    atomic_json(path, data)
    return True


def _incident(runtime: dict[str, Any], failure: str, action: str, final_state: str,
              evidence: dict[str, Any]) -> dict[str, Any]:
    root = Path(runtime["recovery_root"])
    index_path = root / "incidents.json"
    index = json.loads(index_path.read_text()) if index_path.exists() else {}
    now = time.time()
    prior = index.get(failure)
    incident_id = prior["incident_id"] if prior else str(uuid.uuid4())
    receipt = {"schema": "INCIDENT_RECEIPT_V2", "incident_id": incident_id,
               "first_seen": prior["first_seen"] if prior else now, "last_seen": now,
               "occurrence_count": prior["occurrence_count"] + 1 if prior else 1,
               "failure_class": failure, "affected_component": _component_for(failure),
               "release_identity": runtime["current_release"], "action": action,
               "final_state": final_state, "evidence": evidence}
    # Unique, immutable event receipts; index is only a mutable lifecycle projection.
    folder = Path(runtime["log_root"]) / "incidents"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{incident_id}-{uuid.uuid4()}.json"
    with path.open("x") as fh:
        json.dump(receipt, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    index[failure] = receipt
    atomic_json(index_path, index)
    return receipt


def _freeze(runtime: dict[str, Any], failure: str, evidence: dict[str, Any]) -> dict[str, Any]:
    result = {"overall": "FROZEN", "severity": "P0", "failure_class": failure,
              "checked_at": time.time(), "evidence": evidence}
    # Latch first: a receipt failure must not make a later cycle attempt recovery.
    atomic_json(Path(runtime["recovery_root"]) / "FROZEN.json", result)
    try:
        _incident(runtime, failure, "freeze", "FROZEN", evidence)
    except Exception as exc:
        # Corrupt incident projections must not leave an earlier READY status visible.
        result["incident_write_error"] = type(exc).__name__
    return result


def _publish(status_path: Path, result: dict[str, Any], started: float) -> None:
    """Write the verdict together with the time it was reached.

    A reader can then tell a current verdict from one a stalled Supervisor left behind: the file
    is never trusted for being the latest write, only for the time stamped in it.
    """
    now = time.time()
    result["observed_at"] = now
    result["cycle_seconds"] = round(now - started, 3)
    atomic_json(status_path, result)


def doctor_process(manifest: str, runtime: dict[str, Any], timeout: int) -> dict[str, Any]:
    python = Path(runtime["current_release"]) / "venv/bin/python"
    try:
        result = subprocess.run([str(python), "-I", "-m", "universal_agent_middleware.cli", "doctor",
                                 "--runtime-manifest", manifest, "--json"],
                                capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as te:
        partial_stderr = ""
        if te.stderr:
            raw = te.stderr if isinstance(te.stderr, str) else te.stderr.decode("utf-8", errors="replace")
            partial_stderr = raw[:1000]
        result: dict[str, Any] = {"overall": "FAILED", "checks": {},
                "failure_class": "doctor_timeout",
                "timeout_seconds": timeout,
                "stderr": partial_stderr}
        progress_path = Path(runtime["state_root"]) / "doctor_progress.json"
        try:
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            result["last_phase"] = progress.get("last_phase")
            result["partial_timing"] = progress.get("timing")
        except (OSError, ValueError, KeyError):
            pass
        return result
    try:
        report = json.loads(result.stdout)
        if (not isinstance(report, dict) or report.get("overall") not in
                {"READY", "DEGRADED", "FAILED", "FROZEN", "UNKNOWN"}
                or not isinstance(report.get("checks"), dict)):
            raise ValueError("invalid Doctor output")
        if report["overall"] == "FROZEN":
            return report
        required = {"release", "runtime_paths", "credential", "audit_chain", "core", "mcp", "workspace_canary", "tunnel"}
        if not required.issubset(report["checks"]) or any(
                not isinstance(c, dict) or c.get("status") not in {"PASS", "FAIL", "ERROR", "UNKNOWN", "DEGRADED"}
                for c in report["checks"].values()):
            raise ValueError("incomplete Doctor checks")
        if report["overall"] == "READY" and (result.returncode != 0 or any(c["status"] != "PASS" for c in report["checks"].values())):
            raise ValueError("inconsistent Doctor success")
        return report
    except (ValueError, TypeError):
        return {"overall": "FAILED", "checks": {}, "failure_class": "doctor_output_invalid",
                "stderr": (result.stderr or "")[:1000]}


def _restart_tunnel(runtime: dict[str, Any], failure: str, report: dict[str, Any]) -> dict[str, Any]:
    try:
        action = subprocess.run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/com.openjay.uam.tunnel"],
                                capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        # launchctl may already have delivered the request: the outcome is unknown, so the cycle
        # neither retries nor freezes, and the next Doctor decides.
        result = {"overall": "FAILED", "failure_class": failure, "restart_returncode": None,
                  "restart_state": "uncertain_timeout", "readiness": "awaiting_next_doctor"}
    else:
        # An accepted restart is not evidence of readiness.
        result = {"overall": "DEGRADED" if action.returncode == 0 else "FAILED",
                  "failure_class": failure, "restart_returncode": action.returncode,
                  "readiness": "awaiting_next_doctor"}
    _incident(runtime, failure, "restart_tunnel", result["overall"], report)
    return result


def _classify(checks: dict[str, Any]) -> str:
    """The failure class of a Doctor report that is neither READY nor a P0."""
    if checks.get("core", {}).get("status") != "PASS":
        return "core_semantic_failure"
    if checks.get("mcp", {}).get("status") != "PASS":
        return "core_semantic_failure"
    tunnel = checks.get("tunnel", {})
    if tunnel.get("status") == "FAIL":
        return "tunnel_unavailable"
    if tunnel.get("uncertain"):
        return "tunnel_probe_uncertain"
    if checks.get("reality_index", {}).get("status") in ("DEGRADED", "FAIL"):
        idx_class = checks["reality_index"].get("failure_class", "reality_index_stale")
        return idx_class if idx_class in _COMPONENT_MAP else "reality_index_stale"
    return "workspace_degraded"


def run_cycle(manifest: str) -> dict[str, Any]:
    root = Path(load_runtime(manifest)["recovery_root"])
    root.mkdir(parents=True, exist_ok=True)
    with (root / SUPERVISOR_LOCK_NAME).open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # `uam release` holds this lock while it switches the install, so what was read before
        # waiting may describe the release that has just been replaced.
        runtime = load_runtime(manifest)
        started = time.time()
        status_path = root / "health_status.json"
        latch = root / "FROZEN.json"
        if latch.exists():
            result = {"overall": "FROZEN", "severity": "P0", "reason": "persistent freeze latch; operator resolution required"}
            try:
                evidence = json.loads(latch.read_text())
                failure = evidence.get("failure_class", "runtime_path_failure")
                _incident(runtime, failure, "freeze", "FROZEN", evidence)
            except Exception as exc:
                result["incident_write_error"] = type(exc).__name__
            _publish(status_path, result, started)
            return result
        try:
            validate_release(runtime)
        except Exception as exc:
            result = _freeze(runtime, "release_manifest_failure", {"reason": str(exc)})
            _publish(status_path, result, started)
            return result
        refresh = None
        try:
            policies = load_policies(Path(runtime["policy_file"]))
            credential = check_credential(runtime)
            if credential["status"] != "PASS":
                result = _freeze(runtime, "credential_security_failure", credential)
            else:
                refresh = refresh_required_indexes(runtime)
                report = doctor_process(manifest, runtime, policies["doctor_timeout_seconds"])
                checks = report.get("checks", {})
                failure = None
                for key, kind in [("audit_chain", "audit_integrity_failure"),
                                  ("runtime_paths", "runtime_path_failure"),
                                  ("release", "release_manifest_failure"),
                                  ("credential", "credential_security_failure")]:
                    if key in checks and checks[key].get("status") != "PASS":
                        failure = kind
                        break
                if failure or report.get("overall") == "FROZEN":
                    result = _freeze(runtime, failure or "runtime_path_failure", report)
                elif report.get("failure_class"):
                    # Unknown/timed-out diagnosis must never authorize a restart.
                    result = report
                    _incident(runtime, report["failure_class"], "log_only", "FAILED", report)
                elif report["overall"] == "READY":
                    result = report
                else:
                    failure = _classify(checks)
                    policy = policy_for(policies, failure)
                    if policy["action"] == "restart_tunnel":
                        if not consume_budget(root / "budget.json", policy, time.time()):
                            result = _freeze(runtime, "restart_storm", report)
                        else:
                            result = _restart_tunnel(runtime, failure, report)
                    else:
                        result = report
                        _incident(runtime, failure, "log_only", report["overall"], report)
        except Exception as exc:
            result = _freeze(runtime, "recovery_state_failure", {"reason": str(exc)})
        if refresh is not None:
            result["index_refresh"] = refresh
        # No invented uptime: report only the wrapper's observed child start time.
        try:
            result["uptime_since"] = json.loads((root / "tunnel-identity.json").read_text())["started_at"]
        except (OSError, ValueError, KeyError):
            result["uptime_since"] = None
        _publish(status_path, result, started)
        return result


def _required_index_scopes(runtime: dict[str, Any]) -> list[str]:
    """Scopes the service answers from the index: discoverable and allowed to be indexed."""
    raw = json.loads(Path(runtime["root_scopes_file"]).read_text())
    return [scope["scope_id"] for scope in raw.get("scopes", [])
            if scope.get("authority", {}).get("discover") and scope.get("authority", {}).get("index")]


def _is_index_worker(pid: object) -> bool:
    """Whether pid is a live index worker; an answer that cannot be had counts as alive.

    Adding a second scan to a host that is too slow to even answer ``ps`` would only deepen the
    overload, and a recycled pid is told apart by its command line.
    """
    if type(pid) is not int or pid <= 0:
        return False
    try:
        probe = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                               capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return True
    return probe.returncode == 0 and "universal_agent_middleware.cli index" in probe.stdout


def refresh_required_indexes(runtime: dict[str, Any], *, now: float | None = None,
                             wait_seconds: float = INDEX_REFRESH_WAIT_SEC) -> dict[str, Any]:
    """Bring the index of every required scope up to date before the Doctor judges its age.

    Workers run in their own session, so one that is still busy when the wait ends keeps going and
    is not duplicated by the next cycle. Bounded and never raising: the summary says what happened
    and the Doctor stays the judge of whether the index is fresh.
    """
    now = time.time() if now is None else now
    try:
        scopes = _required_index_scopes(runtime)
        if not scopes:
            return {"status": "skipped", "reason": "no scope requires an index"}
        state_path = Path(runtime["recovery_root"]) / "index_refresh_cooldown.json"
        try:
            previous = json.loads(state_path.read_text())
        except (OSError, ValueError):
            previous = {}
        if not isinstance(previous, dict):
            previous = {}
        pids = previous.get("pids")
        running = [pid for pid in pids if _is_index_worker(pid)] if isinstance(pids, list) else []
        if running:
            return {"status": "skipped", "reason": "previous index worker still running", "pids": running}
        last_spawn = previous.get("last_spawn")
        elapsed = now - last_spawn if type(last_spawn) in (int, float) else None
        if elapsed is not None and 0 <= elapsed < INDEX_REFRESH_MIN_INTERVAL_SEC:
            return {"status": "skipped", "reason": "refreshed recently", "seconds_ago": round(elapsed, 1)}

        python = str(Path(runtime["current_release"]) / "venv/bin/python")
        workers: list[tuple[str, subprocess.Popen[bytes]]] = []
        failures: list[dict[str, Any]] = []
        for scope_id in scopes:
            try:
                workers.append((scope_id, subprocess.Popen(
                    [python, "-I", "-m", "universal_agent_middleware.cli", "index",
                     "--registry", runtime["registry_file"], "--state-dir", runtime["state_root"],
                     "--scope", scope_id, "--enrich-git", "--json"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)))
            except OSError as exc:
                failures.append({"scope_id": scope_id, "state": "not_started", "error": type(exc).__name__})
        if workers:
            atomic_json(state_path, {"last_spawn": now, "scopes": [s for s, _ in workers],
                                     "pids": [proc.pid for _, proc in workers]})

        began = time.monotonic()
        deadline = began + wait_seconds
        outcomes = list(failures)
        for scope_id, proc in workers:
            try:
                code = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                outcomes.append({"scope_id": scope_id, "state": "running", "pid": proc.pid})
            else:
                outcomes.append({"scope_id": scope_id, "state": "completed" if code == 0 else "failed",
                                 "pid": proc.pid, "returncode": code})
        if all(item["state"] == "completed" for item in outcomes):
            status = "refreshed"
        elif any(item["state"] == "running" for item in outcomes):
            status = "running"
        else:
            status = "failed"
        return {"status": status, "scopes": outcomes, "waited_seconds": round(time.monotonic() - began, 1)}
    except Exception as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}


def _on_cycle_deadline(signum: int, frame: Any) -> None:
    raise CycleDeadlineExceeded(CYCLE_DEADLINE_SEC)


def _record_cycle_timeout(manifest: str, started: float) -> dict[str, Any]:
    """Publish that the deadline passed without a verdict, so health cannot silently go stale."""
    result: dict[str, Any] = {"overall": "FAILED", "severity": "P2", "checks": {},
                              "failure_class": "supervisor_cycle_timeout",
                              "deadline_seconds": CYCLE_DEADLINE_SEC}
    try:
        runtime = load_runtime(manifest)
        root = Path(runtime["recovery_root"])
        if (root / "FROZEN.json").exists():
            result.update(persisted=False, reason="freeze latch present; its status is left as it is")
            return result
        _incident(runtime, "supervisor_cycle_timeout", "log_only", "FAILED",
                  {"deadline_seconds": CYCLE_DEADLINE_SEC})
        _publish(root / "health_status.json", result, started)
    except Exception as exc:
        result.update(persisted=False, error=type(exc).__name__)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-manifest", required=True)
    args = parser.parse_args()
    started = time.time()
    previous_handler = signal.signal(signal.SIGALRM, _on_cycle_deadline)
    signal.alarm(CYCLE_DEADLINE_SEC)
    try:
        result = run_cycle(args.runtime_manifest)
    except CycleDeadlineExceeded:
        result = _record_cycle_timeout(args.runtime_manifest, started)
    except Exception as exc:
        # A missing/invalid manifest gives no trusted root in which to write state.
        result = {"overall": "FROZEN", "severity": "P0", "reason": str(exc), "persisted": False}
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
    print(json.dumps(result))
    return 0 if result["overall"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
