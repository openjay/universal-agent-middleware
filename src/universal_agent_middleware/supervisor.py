"""One bounded recovery cycle. Persistent P0 latch requires explicit operator resolution."""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .runtime import atomic_json, load_runtime, validate_release, check_credential

P0_FAILURES = {"audit_integrity_failure", "credential_security_failure", "release_manifest_failure",
               "runtime_path_failure", "restart_storm", "recovery_state_failure"}


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
               "failure_class": failure, "affected_component": failure.split("_")[0],
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


def doctor_process(manifest: str, runtime: dict[str, Any], timeout: int) -> dict[str, Any]:
    python = Path(runtime["current_release"]) / "venv/bin/python"
    try:
        result = subprocess.run([str(python), "-I", "-m", "universal_agent_middleware.cli", "doctor",
                                 "--runtime-manifest", manifest, "--json"],
                                capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"overall": "FAILED", "checks": {}, "failure_class": "doctor_timeout"}
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
        return {"overall": "FAILED", "checks": {}, "failure_class": "doctor_output_invalid"}


def run_cycle(manifest: str) -> dict[str, Any]:
    runtime = load_runtime(manifest)
    root = Path(runtime["recovery_root"])
    root.mkdir(parents=True, exist_ok=True)
    with (root / "supervisor.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
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
            atomic_json(status_path, result)
            return result
        try:
            validate_release(runtime)
        except Exception as exc:
            result = _freeze(runtime, "release_manifest_failure", {"reason": str(exc)})
            atomic_json(status_path, result)
            return result
        try:
            policies = load_policies(Path(runtime["policy_file"]))
            credential = check_credential(runtime)
            if credential["status"] != "PASS":
                result = _freeze(runtime, "credential_security_failure", credential)
            else:
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
                    if checks.get("core", {}).get("status") != "PASS":
                        failure = "core_semantic_failure"
                    elif checks.get("mcp", {}).get("status") != "PASS":
                        failure = "core_semantic_failure"
                    elif checks.get("tunnel", {}).get("status") == "FAIL":
                        failure = "tunnel_unavailable"
                    else:
                        failure = "workspace_degraded"
                    policy = policies["policies"][failure]
                    if policy["action"] == "restart_tunnel":
                        if not consume_budget(root / "budget.json", policy, time.time()):
                            result = _freeze(runtime, "restart_storm", report)
                        else:
                            action = subprocess.run(["launchctl", "kickstart", "-k",
                                f"gui/{os.getuid()}/com.openjay.uam.tunnel"],
                                capture_output=True, text=True, timeout=10)
                            # An accepted restart is not evidence of readiness.
                            result = {"overall": "DEGRADED" if action.returncode == 0 else "FAILED",
                                      "failure_class": failure, "restart_returncode": action.returncode,
                                      "readiness": "awaiting_next_doctor"}
                            _incident(runtime, failure, "restart_tunnel", result["overall"], report)
                    else:
                        result = report
                        _incident(runtime, failure, "log_only", report["overall"], report)
        except Exception as exc:
            result = _freeze(runtime, "recovery_state_failure", {"reason": str(exc)})
        # No invented uptime: report only the wrapper's observed child start time.
        try:
            result["uptime_since"] = json.loads((root / "tunnel-identity.json").read_text())["started_at"]
        except (OSError, ValueError, KeyError):
            result["uptime_since"] = None
        atomic_json(status_path, result)
        return result


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-manifest", required=True)
    args = parser.parse_args()
    try:
        result = run_cycle(args.runtime_manifest)
    except Exception as exc:
        # A missing/invalid manifest gives no trusted root in which to write state.
        result = {"overall": "FROZEN", "severity": "P0", "reason": str(exc), "persisted": False}
    print(json.dumps(result))
    return 0 if result["overall"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
