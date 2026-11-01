"""Independent inspection of a built release: tool surface, package files and workspace coverage.

The probe runs inside the release's own interpreter, so it describes the artifact that would be
activated and not the code that happens to orchestrate the release. Its output is compared with
reviewed inputs (the committed ``tool_contract.json`` and the source tree); nothing here
trusts a value the artifact computed about itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .release_process import ProcessOutcome, run_bounded

PROBE_SOURCE = r'''
import asyncio
import hashlib
import json
import sys
from pathlib import Path

import universal_agent_middleware as package
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
from universal_agent_middleware.doctor import tool_contract
from universal_agent_middleware.gateway import MiddlewareGateway


def digest(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode()).hexdigest()


registry, state = sys.argv[1], sys.argv[2]
tools = asyncio.run(create_session_read_server(registry, state).list_tools())
fields = {}
for tool in tools:
    body = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    fields[tool.name] = {key: digest(value) for key, value in body.items()}
registry_view = MiddlewareGateway(registry, state).registry
coverage = registry_view.coverage() if hasattr(registry_view, "coverage") else None
root = Path(package.__file__).resolve().parent
files = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
        files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps({"version": package.__version__, "package_root": str(root),
                  "contract": tool_contract(tools), "fields": fields,
                  "coverage": coverage, "package_files": files}))
'''

PROBE_TIMEOUT_SECONDS = 60.0
FIXTURE_REGISTRY = {"registry_version": "uam-workspace-registry-v1", "workspaces": []}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LISTED_LIMIT = 20


@dataclass(frozen=True)
class ProbeResult:
    data: dict[str, Any] | None
    error: str
    outcome: ProcessOutcome


def validate_contract(value: object, *, label: str) -> dict[str, str]:
    """A tool contract is a non-empty mapping of exact tool name to a SHA-256 digest."""
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{label} must be a non-empty object")
    for name, digest in value.items():
        if not isinstance(name, str) or not name or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"{label} has an invalid entry: {name!r}")
    return dict(value)


def contract_sha256(contract: Mapping[str, str]) -> str:
    """Same digest Doctor reports as ``checks.mcp.contract_sha256``."""
    return hashlib.sha256(json.dumps(dict(contract), sort_keys=True).encode()).hexdigest()


def compare_contract(reviewed: Mapping[str, str], actual: Mapping[str, str]) -> dict[str, Any]:
    """Compare exact tool names and digests; a matching count proves nothing."""
    missing = sorted(set(reviewed) - set(actual))
    unexpected = sorted(set(actual) - set(reviewed))
    changed = sorted(name for name in set(reviewed) & set(actual) if reviewed[name] != actual[name])
    return {
        "match": not (missing or unexpected or changed),
        "reviewed_count": len(reviewed), "actual_count": len(actual),
        "tools": sorted(actual), "contract_sha256": contract_sha256(actual),
        "missing": missing, "unexpected": unexpected, "changed": changed,
    }


def diff_tool_fields(previous: Mapping[str, Mapping[str, str]],
                     candidate: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    """Which fields of which tools differ between two live tool listings (description, schemas, annotations, ...)."""
    changed: dict[str, list[str]] = {}
    for name in sorted(set(previous) & set(candidate)):
        keys = sorted(key for key in set(previous[name]) | set(candidate[name])
                      if previous[name].get(key) != candidate[name].get(key))
        if keys:
            changed[name] = keys
    return {
        "status": "COMPARED",
        "added": sorted(set(candidate) - set(previous)),
        "removed": sorted(set(previous) - set(candidate)),
        "changed": changed,
        "client_refresh_needed": bool(changed or set(candidate) ^ set(previous)),
    }


def compare_package_files(source: Mapping[str, str], installed: Mapping[str, str]) -> dict[str, Any]:
    missing = sorted(set(source) - set(installed))
    unexpected = sorted(set(installed) - set(source))
    changed = sorted(name for name in set(source) & set(installed) if source[name] != installed[name])
    return {
        "match": not (missing or unexpected or changed),
        "compared": len(source),
        "missing": missing[:_LISTED_LIMIT], "unexpected": unexpected[:_LISTED_LIMIT],
        "changed": changed[:_LISTED_LIMIT],
        "differences": len(missing) + len(unexpected) + len(changed),
    }


def _parse_probe_stdout(stdout: bytes) -> tuple[dict[str, Any] | None, str]:
    lines = [line for line in stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    if not lines:
        return None, "probe produced no output"
    try:
        data = json.loads(lines[-1])
    except ValueError as exc:
        return None, f"probe output is not valid JSON: {exc}"
    if not isinstance(data, dict) or not isinstance(data.get("contract"), dict) \
            or not isinstance(data.get("fields"), dict):
        return None, "probe output has an unexpected shape"
    return data, ""


def run_probe(python: Path, registry: str, state_dir: str, *, stage: str,
              timeout: float = PROBE_TIMEOUT_SECONDS) -> ProbeResult:
    # -B: inspecting a release must not write bytecode into it (or into the active one).
    outcome = run_bounded([str(python), "-I", "-B", "-c", PROBE_SOURCE, registry, state_dir],
                          stage=stage, timeout=timeout)
    if not outcome.succeeded:
        return ProbeResult(None, outcome.describe_failure(), outcome)
    data, error = _parse_probe_stdout(outcome.stdout)
    return ProbeResult(data, error, outcome)
