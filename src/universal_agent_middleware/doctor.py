"""Semantic health: inspect evidence without appending to the ledger under test."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any


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


def run_doctor(registry_path: str, state_dir: str, *, include_canary: bool = True,
               runtime_manifest: str | None = None) -> dict[str, Any]:
    from .runtime import (load_runtime, validate_paths, validate_release,
                          validate_configs, check_credential)
    checks: dict[str, Any] = {}
    report = {"overall": "UNKNOWN", "severity": "INFO",
              "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": checks}
    runtime, release = None, None
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
    checks["audit_chain"] = _check_audit(state_dir, require_existing=bool(runtime_manifest))
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
    try:
        from .adapters.mcp_sdk import create_session_read_server
        tools = asyncio.run(create_session_read_server(registry_path, state_dir).list_tools())
        actual = tool_contract(tools)
        expected = release["tool_contract"] if release else json.loads(
            Path(__file__).with_name("tool_contract.json").read_text())
        checks["mcp"] = {"status": "PASS" if actual == expected else "FAIL",
                         "tools": sorted(actual), "missing": sorted(set(expected) - set(actual)),
                         "unexpected": sorted(set(actual) - set(expected)),
                         "schema_mismatch": sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])}
    except Exception as exc:
        checks["mcp"] = {"status": "ERROR", "reason": str(exc)}
    if include_canary:
        canaries = runtime.get("canaries", []) if runtime else []
        results = []
        for canary in canaries:
            try:
                if not gw or not isinstance(canary, dict) or not canary.get("path"):
                    raise ValueError("canary requires workspace_id and a file path")
                reader = gw._reader(canary["workspace_id"])
                tree = reader.tree(".", depth=1)
                content = reader.read_file(canary["path"])
                results.append({"status": "PASS", "workspace_id": canary["workspace_id"],
                                "path": canary["path"], "tree_entries": len(tree.get("entries", [])),
                                "read_verified": isinstance(content, dict)})
            except Exception as exc:
                results.append({"status": "FAIL", "reason": str(exc)})
        checks["workspace_canary"] = {
            "status": ("PASS" if all(r["status"] == "PASS" for r in results) else "FAIL") if results else "UNKNOWN",
            "results": results, "reason": "configured canaries only; no automatic authorization"}
    else:
        checks["workspace_canary"] = {"status": "UNKNOWN", "reason": "explicitly skipped"}
    checks["tunnel"] = _check_tunnel(runtime) if runtime else {"status": "UNKNOWN", "reason": "no runtime identity"}
    values = list(checks.values())
    if any(r.get("severity") == "P0" and r["status"] != "PASS" for r in values):
        report.update(overall="FROZEN", severity="P0")
    elif any(r["status"] == "ERROR" for r in values):
        report.update(overall="FAILED", severity="P1")
    elif all(r["status"] == "PASS" for r in values):
        report["overall"] = "READY"
    else:
        report.update(overall="DEGRADED", severity="P2")
    return report


def _check_tunnel(runtime: dict[str, Any]) -> dict[str, Any]:
    """Bind health endpoints to a PID started by our wrapper and its exact config."""
    import subprocess
    import urllib.request
    from .runtime import sha256
    try:
        identity = json.loads((Path(runtime["recovery_root"]) / "tunnel-identity.json").read_text())
        pid = identity["pid"]
        if type(pid) is not int or pid <= 0:
            raise ValueError("invalid tunnel pid")
        info = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="],
                              capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        if not info or info != identity["process_identity"]:
            raise ValueError("tunnel PID identity mismatch")
        if (identity["release"] != runtime["current_release"] or
                identity["config_sha256"] != sha256(Path(runtime["tunnel_config"])) or
                identity["executable_sha256"] != sha256(Path(runtime["tunnel_client"]))):
            raise ValueError("tunnel release/config/executable mismatch")
        listener = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid),
                                   "-iTCP:8080", "-sTCP:LISTEN", "-Fp"],
                                  capture_output=True, text=True, timeout=5, check=True)
        if f"p{pid}" not in listener.stdout.splitlines():
            raise ValueError("health port is not owned by the expected tunnel PID")
        healthy = {}
        for endpoint in ("healthz", "readyz"):
            with urllib.request.urlopen(f"http://127.0.0.1:8080/{endpoint}", timeout=5) as resp:
                healthy[endpoint] = resp.status == 200
        return {"status": "PASS" if all(healthy.values()) else "FAIL", "pid": pid, **healthy}
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)}
