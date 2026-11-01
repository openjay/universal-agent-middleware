"""Helpers shared by the release-pipeline tests.

Nothing here touches a live UAM install, a LaunchAgent or the network: runtimes are built under
``tmp_path``, child processes are tiny shell scripts, and Doctor reports come from the real
Doctor run against a production-shaped fixture.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

from universal_agent_middleware import runtime as rt
from universal_agent_middleware.doctor import run_doctor

ROOT = Path(__file__).resolve().parents[1]
_validate_release = rt.validate_release  # captured before any test patches the module attribute
STALE = ("atlas-main", "atlas-pr7")
VALID = ("ws-a", "ws-b", "ws-c", "ws-d")
NEXT_COMMIT = "b" * 40


def executable(path: Path, body: str) -> Path:
    """A tiny sh program standing in for python, git or launchctl.

    macOS assesses a freshly written executable on its first launch, which takes 0.2-0.7 s; a
    test that measures a sub-second timeout would then time out before the script runs. The file
    is launched once in warm-up mode so the timed launch starts in milliseconds.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\n[ -n "$UAM_TEST_WARMUP" ] && exit 0\n' + body)
    path.chmod(0o755)
    subprocess.run([str(path)], env={**os.environ, "UAM_TEST_WARMUP": "1"}, capture_output=True,
                   timeout=30, check=True)
    return path


def next_release(r: dict[str, Any], commit: str = NEXT_COMMIT) -> Path:
    """Copy the fixture release into a second, internally consistent release directory."""
    current = Path(r["current_release"])
    target = current.parent / f"v0.4.1+{commit}"
    shutil.copytree(current, target, symlinks=True)
    manifest = json.loads((target / "RELEASE_MANIFEST.json").read_text())
    manifest.update(release_id=target.name, source_commit=commit)
    rt.atomic_json(target / "RELEASE_MANIFEST.json", manifest)
    runtime = json.loads((target / "runtime/uam-runtime.json").read_text())
    runtime.update(current_release=str(target), policy_file=str(target / "service/recovery_policies.yaml"),
                   release_manifest_sha256=rt.sha256(target / "RELEASE_MANIFEST.json"))
    rt.atomic_json(target / "runtime/uam-runtime.json", runtime)
    return target


def canonical_manifest(r: dict[str, Any]) -> Path:
    """The global manifest: a symlink into ``current`` exactly as in production."""
    return Path(r["uam_home"]) / "runtime/uam-runtime.json"


def production_shaped(r: dict[str, Any], manifest: Path, base: Path, *,
                      valid: tuple[str, ...] = VALID, stale: tuple[str, ...] = STALE) -> dict[str, Any]:
    """Registry with readable workspaces plus unreadable registrations, one canary for each."""
    entries, canaries = [], []
    for workspace_id in valid:
        root = base / "roots" / workspace_id
        root.mkdir(parents=True)
        (root / "README.md").write_text("fixture content\n")
        entries.append({"workspace_id": workspace_id, "root": str(root), "kind": "git-repository",
                        "capabilities": ["filesystem.read"]})
        canaries.append({"workspace_id": workspace_id, "path": "README.md"})
    for workspace_id in stale:
        entries.append({"workspace_id": workspace_id, "root": str(base / "gone" / workspace_id),
                        "kind": "git-repository", "capabilities": ["filesystem.read"]})
        canaries.append({"workspace_id": workspace_id, "path": "README.md"})
    Path(r["registry_file"]).write_text(json.dumps(
        {"registry_version": "uam-workspace-registry-v1", "workspaces": entries}))
    updated = dict(r, canaries=canaries)
    rt.atomic_json(manifest, updated)
    return updated


def doctor_report(r: dict[str, Any], manifest: Path) -> dict[str, Any]:
    """The real Doctor, with the two checks that need a live host replaced by their PASS shape."""
    with patch("universal_agent_middleware.runtime.validate_release",
               side_effect=lambda runtime: _validate_release(runtime, executing=False)), \
         patch("universal_agent_middleware.doctor._check_tunnel", return_value={"status": "PASS"}):
        return run_doctor(r["registry_file"], r["state_root"], runtime_manifest=str(manifest))


def declaration(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": "uam-release-acceptance-v1",
        "registry": {"registered": 6, "available": 4,
                     "unavailable": [{"workspace_id": name, "reason": "root_missing"} for name in STALE]},
        "canaries": {"total": 6, "failing": list(STALE)},
    }
    data.update(overrides)
    return data


def write_declaration(path: Path, data: dict[str, Any] | None = None) -> Path:
    path.write_text(json.dumps(declaration() if data is None else data))
    return path
