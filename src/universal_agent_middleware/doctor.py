"""Semantic health: inspect evidence without appending to the ledger under test."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .errors import WorkspaceUnavailableError

_STATUS_RANK = ("ERROR", "FAIL", "DEGRADED", "UNKNOWN", "PASS")


def tool_contract(tools: list) -> dict[str, str]:
    """Bind each exact tool name to its public input/output and safety contract."""
    result = {}
    for tool in tools:
        body = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        body.pop("description", None)
        result[tool.name] = hashlib.sha256(json.dumps(body, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return result


def _check_audit(state_dir: str, *, require_existing: bool = False) -> dict[str, Any]:
    from .audit import HashChainedAuditLog
    audit_file = Path(state_dir) / "audit.jsonl"
    try:
        if require_existing and not audit_file.is_file():
            return {"status": "FAIL", "severity": "P0", "failure_type": "MISSING_LEDGER",
                    "audit_file": str(audit_file), "error": "configured runtime ledger missing"}
        result = HashChainedAuditLog(audit_file).verify()
        migration = result["valid"] and result["records"] > 0 and result["schema_version"] == 1
        return {**result, "status": "FAIL" if not result["valid"] or migration else "PASS",
                "severity": "P0" if not result["valid"] or migration else "INFO",
                "entries": result["records"], "audit_file": str(audit_file),
                "migration_required": migration}
    except Exception as exc:
        return {"status": "ERROR", "severity": "P0", "failure_type": "AUDIT_UNREADABLE",
                "error": str(exc), "audit_file": str(audit_file)}


def _file_sha256(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _gateway_identity(gw: Any) -> dict[str, Any] | None:
    if gw is None:
        return None
    try:
        return gw.instance_info()
    except Exception as exc:
        return {"error": type(exc).__name__}


def _run_canary(gw: Any, canary: Any) -> dict[str, Any]:
    """Probe one configured canary; a failure always names the workspace and the stage."""
    workspace_id = canary.get("workspace_id") if isinstance(canary, dict) else None
    path = canary.get("path") if isinstance(canary, dict) else None
    if gw is None:
        return {"status": "FAIL", "workspace_id": workspace_id, "stage": "gateway_init",
                "reason": "gateway did not initialise; workspace was not probed"}
    if not workspace_id or not path:
        return {"status": "FAIL", "workspace_id": workspace_id, "stage": "canary_config",
                "reason": "canary requires workspace_id and a file path"}
    try:
        reader = gw._reader(workspace_id)
    except WorkspaceUnavailableError as exc:
        return {"status": "FAIL", "workspace_id": workspace_id, "stage": "workspace_unavailable",
                "unavailable_reason": exc.reason, "reason": str(exc)}
    except Exception as exc:
        return {"status": "FAIL", "workspace_id": workspace_id, "stage": "resolve",
                "error_type": type(exc).__name__, "reason": str(exc)}
    try:
        tree = reader.tree(".", depth=1)
        content = reader.read_file(path)
    except Exception as exc:
        return {"status": "FAIL", "workspace_id": workspace_id, "stage": "read",
                "error_type": type(exc).__name__, "reason": str(exc)}
    return {"status": "PASS", "workspace_id": workspace_id, "path": path,
            "tree_entries": len(tree.get("entries", [])),
            "read_verified": isinstance(content, dict)}


def _check_registry_coverage(gw: Any) -> dict[str, Any]:
    """Which registered workspaces this instance can actually serve; gaps are DEGRADED, never PASS."""
    if gw is None:
        return {"status": "UNKNOWN", "reason": "gateway unavailable"}
    try:
        coverage = gw.registry.coverage()
    except Exception as exc:
        return {"status": "ERROR", "reason": str(exc)}
    complete = coverage["complete"]
    return {"status": "PASS" if complete else "DEGRADED",
            "registered": coverage["registered"], "available": coverage["available"],
            "unavailable": coverage["unavailable"],
            "reason": None if complete else
            "registered workspaces cannot be served; coverage is incomplete"}


def _worst(statuses: list[str]) -> str:
    for status in _STATUS_RANK:
        if status in statuses:
            return status
    return "UNKNOWN"


def _derive_stages(checks: dict[str, Any]) -> dict[str, Any]:
    """Project the independent evidence behind the verdict; adds no probing of its own."""
    def status(name: str) -> str:
        entry = checks.get(name)
        return entry.get("status", "UNKNOWN") if isinstance(entry, dict) else "UNKNOWN"

    registry = checks.get("workspace_registry") or {}
    canary = checks.get("workspace_canary") or {}
    gaps = [f"registry:{item.get('workspace_id')}:{item.get('reason')}"
            for item in registry.get("unavailable", [])]
    gaps += [f"canary:{item.get('workspace_id')}:{item.get('stage')}"
             for item in canary.get("results", []) if item.get("status") != "PASS"]
    evidence = ("workspace_registry", "workspace_canary")
    problems = [f"{name}={status(name)}" for name in evidence
                if status(name) not in ("PASS", "DEGRADED", "FAIL")]
    incomplete = bool(gaps) or any(status(name) in ("DEGRADED", "FAIL") for name in evidence)
    completeness = _worst(["DEGRADED" if incomplete else "PASS", "UNKNOWN" if problems else "PASS"])
    return {
        "process_alive": {"status": status("tunnel"), "evidence": ["tunnel"]},
        "initialization": {"status": _worst([status("core"), status("mcp")]),
                           "evidence": ["core", "mcp"]},
        "workspace_readable": {
            "status": _worst([status("workspace_canary"), status("workspace_registry")]),
            "evidence": ["workspace_canary", "workspace_registry"]},
        "result_completeness": {
            "status": completeness,
            "known_gaps": gaps,
            "evidence_problems": problems,
            "evidence": ["workspace_canary", "workspace_registry"],
            "meaning": "PASS needs valid registry and canary evidence with no known gap; it does "
                       "not claim that unregistered content was covered. Missing, skipped or "
                       "failed evidence is never PASS"},
    }


def run_doctor(registry_path: str, state_dir: str, *, include_canary: bool = True,
               runtime_manifest: str | None = None) -> dict[str, Any]:
    from .runtime import (load_runtime, validate_paths, validate_release,
                          validate_configs, check_credential)
    checks: dict[str, Any] = {}
    report = {"overall": "UNKNOWN", "severity": "INFO",
              "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "request_id": str(uuid.uuid4()), "checks": checks}
    progress_file = Path(state_dir) / "doctor_progress.json"
    report["_progress_file"] = str(progress_file)
    runtime, release = None, None
    t0 = time.perf_counter()
    if runtime_manifest:
        try:
            runtime = load_runtime(runtime_manifest)
            validate_paths(runtime, registry_path, state_dir)
            checks["runtime_paths"] = {"status": "PASS", "registry_file": registry_path,
                                       "state_root": state_dir, "audit_file": runtime["audit_file"]}
        except Exception as exc:
            checks["runtime_paths"] = {"status": "FAIL", "severity": "P0", "reason": str(exc)}
        if runtime:
            try:
                release = validate_release(runtime)
                checks["release"] = {"status": "PASS", "release_id": release["release_id"]}
            except Exception as exc:
                checks["release"] = {"status": "FAIL", "severity": "P0", "reason": str(exc)}
            checks["credential"] = check_credential(runtime)
            if (Path(runtime["recovery_root"]) / "FROZEN.json").exists():
                checks["freeze_latch"] = {"status": "FAIL", "severity": "P0", "reason": "operator resolution required"}
    else:
        checks["release"] = {"status": "UNKNOWN", "reason": "development check; runtime manifest not supplied"}
    _record_phase(report, "runtime_checks", t0)
    t1 = time.perf_counter()
    checks["audit_chain"] = _check_audit(state_dir, require_existing=bool(runtime_manifest))
    _record_phase(report, "audit_chain_check", t1)
    t2 = time.perf_counter()
    try:
        from .gateway import MiddlewareGateway
        if runtime:
            validate_configs(runtime)
        gw = MiddlewareGateway(registry_path, state_dir)
        checks["core"] = {"status": "PASS", "workspace_count": len(gw.registry.list()),
                          "scope_count": len(gw.scopes.list_scopes())}
    except Exception as exc:
        gw = None
        checks["core"] = {"status": "ERROR", "reason": str(exc)}
    checks["workspace_registry"] = _check_registry_coverage(gw)
    _record_phase(report, "core_init", t2)
    t3 = time.perf_counter()
    try:
        from .adapters.mcp_sdk import create_session_read_server
        tools = asyncio.run(create_session_read_server(registry_path, state_dir).list_tools())
        actual = tool_contract(tools)
        expected = release["tool_contract"] if release else json.loads(
            Path(__file__).with_name("tool_contract.json").read_text())
        checks["mcp"] = {"status": "PASS" if actual == expected else "FAIL",
                         "contract_sha256": hashlib.sha256(
                             json.dumps(actual, sort_keys=True).encode()).hexdigest(),
                         "tools": sorted(actual), "missing": sorted(set(expected) - set(actual)),
                         "unexpected": sorted(set(actual) - set(expected)),
                         "schema_mismatch": sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])}
    except Exception as exc:
        checks["mcp"] = {"status": "ERROR", "reason": str(exc)}
    _record_phase(report, "mcp_contract", t3)
    t4 = time.perf_counter()
    if include_canary:
        canaries = runtime.get("canaries", []) if runtime else []
        results = [_run_canary(gw, canary) for canary in canaries]
        checks["workspace_canary"] = {
            "status": ("PASS" if all(r["status"] == "PASS" for r in results) else "FAIL") if results else "UNKNOWN",
            "results": results, "reason": "configured canaries only; no automatic authorization"}
    else:
        checks["workspace_canary"] = {"status": "UNKNOWN", "reason": "explicitly skipped"}
    _record_phase(report, "workspace_canary_check", t4)
    t5 = time.perf_counter()
    checks["tunnel"] = _check_tunnel(runtime) if runtime else {"status": "UNKNOWN", "reason": "no runtime identity"}
    _record_phase(report, "tunnel_check", t5)
    t6 = time.perf_counter()
    if gw is not None:
        checks["reality_index"] = gw.reality_index.health_report(gw.scopes)
    else:
        checks["reality_index"] = {"status": "UNKNOWN", "reason": "gateway unavailable"}
    _record_phase(report, "reality_index_check", t6)
    report["instance"] = {
        "probed": "fresh gateway created by this doctor process; the long-lived serving "
                  "process is identified by checks.tunnel",
        "pid": os.getpid(),
        "uam_version": __version__,
        "release_id": release.get("release_id") if release else None,
        "gateway": _gateway_identity(gw),
        "config": {"registry_sha256": _file_sha256(registry_path),
                   "runtime_manifest_sha256": _file_sha256(runtime_manifest)},
    }
    report["stages"] = _derive_stages(checks)
    report["total_duration_ms"] = round((time.perf_counter() - t0) * 1000)
    report.pop("_progress_file", None)
    try:
        progress_file.unlink(missing_ok=True)
    except OSError:
        pass
    values = list(checks.values())
    if any(r.get("severity") == "P0" and r["status"] != "PASS" for r in values):
        report.update(overall="FROZEN", severity="P0")
    elif any(r["status"] == "ERROR" for r in values):
        report.update(overall="FAILED", severity="P1")
    elif any(r.get("status") == "DEGRADED" for r in values):
        report.update(overall="DEGRADED", severity="P2")
    elif all(r["status"] == "PASS" for r in values):
        report["overall"] = "READY"
    else:
        report.update(overall="DEGRADED", severity="P2")
    return report


def _record_phase(report: dict[str, Any], phase_name: str, t_start: float) -> None:
    """Record phase duration in the report-level _timing dict."""
    timing = report.setdefault("_timing", {})
    timing[phase_name] = round((time.perf_counter() - t_start) * 1000)
    progress_path = report.get("_progress_file")
    if progress_path:
        try:
            Path(progress_path).write_text(
                json.dumps({"last_phase": phase_name, "timing": timing}),
                encoding="utf-8",
            )
        except OSError:
            pass


def _probe_timed_out(exc: BaseException) -> bool:
    """True when a probe gave no answer in time, as opposed to answering that something is wrong.

    A timeout says nothing about the tunnel itself: on an overloaded host the probe is as likely to
    be starved as the service is to be dead. ``urllib`` wraps connect timeouts in ``URLError``.
    """
    if isinstance(exc, (subprocess.TimeoutExpired, TimeoutError)):
        return True
    return isinstance(getattr(exc, "reason", None), TimeoutError)


def _check_tunnel(runtime: dict[str, Any]) -> dict[str, Any]:
    """Bind health endpoints to a PID started by our wrapper and its exact config.

    Only a definite answer is a FAIL. A probe that timed out leaves the state uncertain and is
    reported as UNKNOWN with ``uncertain: true``, so the Supervisor never restarts a service on
    the strength of a probe that was merely too slow.
    """
    from .runtime import sha256
    stage = "identity_file"
    evidence: dict[str, Any] = {}
    try:
        identity = json.loads((Path(runtime["recovery_root"]) / "tunnel-identity.json").read_text())
        pid = identity["pid"]
        if type(pid) is not int or pid <= 0:
            raise ValueError("invalid tunnel pid")
        evidence = {"pid": pid, "started_at": identity.get("started_at"),
                    "release_id": Path(str(identity.get("release", ""))).name or None,
                    "config_sha256": identity.get("config_sha256")}
        stage = "process_identity"
        info = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="],
                              capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        if not info or info != identity["process_identity"]:
            raise ValueError("tunnel PID identity mismatch")
        stage = "release_config"
        if (identity["release"] != runtime["current_release"] or
                identity["config_sha256"] != sha256(Path(runtime["tunnel_config"])) or
                identity["executable_sha256"] != sha256(Path(runtime["tunnel_client"]))):
            raise ValueError("tunnel release/config/executable mismatch")
        stage = "listener"
        listener = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid),
                                   "-iTCP:8080", "-sTCP:LISTEN", "-Fp"],
                                  capture_output=True, text=True, timeout=5, check=True)
        if f"p{pid}" not in listener.stdout.splitlines():
            raise ValueError("health port is not owned by the expected tunnel PID")
        stage = "health_endpoint"
        healthy = {}
        for endpoint in ("healthz", "readyz"):
            with urllib.request.urlopen(f"http://127.0.0.1:8080/{endpoint}", timeout=5) as resp:
                healthy[endpoint] = resp.status == 200
        result = {"status": "PASS" if all(healthy.values()) else "FAIL", **evidence, **healthy}
        if result["status"] != "PASS":
            result["stage"] = stage
        return result
    except Exception as exc:
        if _probe_timed_out(exc):
            return {"status": "UNKNOWN", "uncertain": True, "stage": stage,
                    "reason": f"probe timed out; the tunnel state is uncertain: {exc}", **evidence}
        return {"status": "FAIL", "stage": stage, "reason": str(exc), **evidence}
