from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .errors import PathPolicyError, WorkspaceError
from .models import WorkspaceSpec
from .policy import resolve_safe_path, should_hide_path

_ALLOWED_KINDS = {"git-repository"}
_ALLOWED_CAPABILITIES = {"filesystem.read", "git.observe"}
_REGISTRY_VERSION = "uam-workspace-registry-v1"
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class WorkspaceRegistry:
    def __init__(self, registry_path: str | Path):
        self.registry_path = Path(registry_path)
        self._specs = self._load()

    def _load(self) -> dict[str, WorkspaceSpec]:
        try:
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise WorkspaceError(
                f"workspace registry not found: {self.registry_path}"
            ) from exc
        if not isinstance(payload, dict):
            raise WorkspaceError("workspace registry must be an object")
        unknown_root = sorted(set(payload) - {"registry_version", "workspaces"})
        if unknown_root:
            raise WorkspaceError(f"unknown workspace registry fields: {', '.join(unknown_root)}")
        if payload.get("registry_version") != _REGISTRY_VERSION:
            raise WorkspaceError(f"unsupported workspace registry version: {payload.get('registry_version')}")
        if not isinstance(payload.get("workspaces"), list):
            raise WorkspaceError("workspace registry must contain a workspaces list")
        specs: dict[str, WorkspaceSpec] = {}
        for raw in payload.get("workspaces", []):
            if not isinstance(raw, dict):
                raise WorkspaceError("workspace entry must be an object")
            allowed_fields = {
                "workspace_id", "root", "label", "kind", "capabilities",
                "max_file_bytes", "max_search_files",
                "project_id", "role", "lifecycle", "repository_identity", "discovery",
            }
            required_fields = {"workspace_id", "root", "kind", "capabilities"}
            missing = sorted(required_fields - set(raw))
            if missing:
                raise WorkspaceError(
                    f"missing required workspace fields: {', '.join(missing)}"
                )
            unknown = sorted(set(raw) - allowed_fields)
            if unknown:
                raise WorkspaceError(f"unknown workspace fields: {', '.join(unknown)}")
            spec = WorkspaceSpec(
                workspace_id=raw["workspace_id"],
                root=raw["root"],
                label=raw.get("label", ""),
                kind=raw["kind"],
                capabilities=raw["capabilities"],
                max_file_bytes=raw.get("max_file_bytes", 524_288),
                max_search_files=raw.get("max_search_files", 5_000),
            )
            if not _WORKSPACE_ID.fullmatch(spec.workspace_id) or spec.workspace_id in specs:
                raise WorkspaceError("workspace_id must be unique and match the V1 identifier grammar")
            if spec.kind not in _ALLOWED_KINDS:
                raise WorkspaceError(f"unsupported workspace kind: {spec.kind}")
            if not spec.capabilities or any(
                capability not in _ALLOWED_CAPABILITIES for capability in spec.capabilities
            ):
                raise WorkspaceError("workspace declares an unsupported capability")
            root = Path(spec.root).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise WorkspaceError(f"workspace root is not a directory: {root}")
            specs[spec.workspace_id] = WorkspaceSpec(
                workspace_id=spec.workspace_id,
                root=str(root),
                label=spec.label,
                kind=spec.kind,
                capabilities=list(dict.fromkeys(spec.capabilities)),
                max_file_bytes=spec.max_file_bytes,
                max_search_files=spec.max_search_files,
            )
        return specs

    def list(self) -> list[dict[str, Any]]:
        return [spec.to_dict() for spec in self._specs.values()]

    def get(self, workspace_id: str) -> WorkspaceSpec:
        try:
            return self._specs[workspace_id]
        except KeyError as exc:
            raise WorkspaceError(f"unknown workspace: {workspace_id}") from exc

    def require_capability(self, workspace_id: str, capability: str) -> WorkspaceSpec:
        spec = self.get(workspace_id)
        if capability not in spec.capabilities:
            raise WorkspaceError(
                f"workspace {workspace_id} does not grant capability {capability}"
            )
        return spec


class WorkspaceReader:
    def __init__(self, spec: WorkspaceSpec):
        if "filesystem.read" not in spec.capabilities:
            raise WorkspaceError("workspace does not grant filesystem.read")
        self.spec = spec
        self.root = Path(spec.root)

    def _safe(self, raw: str, *, must_exist: bool = True) -> Path:
        return resolve_safe_path(self.root, raw, must_exist=must_exist)

    def tree(
        self, path: str = ".", *, depth: int = 3, max_entries: int = 500
    ) -> dict[str, Any]:
        if depth < 0 or depth > 8:
            raise PathPolicyError("depth must be between 0 and 8")
        base = self._safe(path)
        if not base.is_dir():
            raise WorkspaceError("tree path must be a directory")
        entries: list[dict[str, Any]] = []
        base_depth = len(base.parts)
        for current, dirs, files in os.walk(base, followlinks=False):
            current_path = Path(current)
            current_depth = len(current_path.parts) - base_depth
            dirs[:] = sorted(
                d
                for d in dirs
                if not (current_path / d).is_symlink()
                and not should_hide_path(self.root, current_path / d)
                and current_depth < depth
            )
            for name in sorted(dirs + files):
                candidate = current_path / name
                if candidate.is_symlink() or should_hide_path(self.root, candidate):
                    continue
                rel = candidate.relative_to(self.root).as_posix()
                item = {
                    "path": rel,
                    "type": "dir" if candidate.is_dir() else "file",
                }
                if candidate.is_file():
                    try:
                        item["size"] = candidate.stat().st_size
                    except OSError:
                        item["size"] = None
                entries.append(item)
                if len(entries) >= max_entries:
                    return {"path": path, "entries": entries, "truncated": True}
        return {"path": path, "entries": entries, "truncated": False}

    def read_file(
        self, path: str, *, start_line: int = 1, end_line: int | None = None
    ) -> dict[str, Any]:
        target = self._safe(path)
        if not target.is_file():
            raise WorkspaceError("path is not a file")
        size = target.stat().st_size
        if size > self.spec.max_file_bytes:
            raise WorkspaceError(
                f"file exceeds max_file_bytes ({self.spec.max_file_bytes})"
            )
        raw = target.read_bytes()
        if b"\x00" in raw[:8192]:
            raise WorkspaceError("binary files are not readable")
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if start_line < 1:
            raise WorkspaceError("start_line must be >= 1")
        if end_line is None:
            end_line = min(len(lines), start_line + 399)
        if end_line < start_line or end_line - start_line > 999:
            raise WorkspaceError("invalid line range")
        selected = lines[start_line - 1 : end_line]
        return {
            "path": path,
            "start_line": start_line,
            "end_line": start_line + len(selected) - 1 if selected else start_line - 1,
            "total_lines": len(lines),
            "content": "\n".join(selected),
            "truncated": end_line < len(lines),
        }

    def search_text(
        self, query: str, *, path: str = ".", max_results: int = 100
    ) -> dict[str, Any]:
        if not query or len(query) > 256:
            raise WorkspaceError("query must contain 1..256 characters")
        if not (1 <= max_results <= 500):
            raise WorkspaceError("max_results must be 1..500")
        base = self._safe(path)
        if not base.is_dir():
            raise WorkspaceError("search path must be a directory")
        results: list[dict[str, Any]] = []
        files_scanned = 0
        for current, dirs, files in os.walk(base, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(
                d
                for d in dirs
                if not (current_path / d).is_symlink()
                and not should_hide_path(self.root, current_path / d)
            )
            for name in sorted(files):
                target = current_path / name
                if target.is_symlink() or should_hide_path(self.root, target):
                    continue
                try:
                    # Resolve every scanned file so a symlink/race cannot turn a
                    # lexical in-workspace name into an out-of-workspace read.
                    target = resolve_safe_path(self.root, target.relative_to(self.root).as_posix())
                except (PathPolicyError, OSError):
                    continue
                files_scanned += 1
                if files_scanned > self.spec.max_search_files:
                    return {
                        "query": query,
                        "results": results,
                        "files_scanned": files_scanned - 1,
                        "truncated": True,
                    }
                try:
                    if target.stat().st_size > self.spec.max_file_bytes:
                        continue
                    raw = target.read_bytes()
                    if b"\x00" in raw[:8192]:
                        continue
                    lines = raw.decode("utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for number, line in enumerate(lines, start=1):
                    if query.lower() in line.lower():
                        results.append(
                            {
                                "path": target.relative_to(self.root).as_posix(),
                                "line": number,
                                "text": line[:500],
                            }
                        )
                        if len(results) >= max_results:
                            return {
                                "query": query,
                                "results": results,
                                "files_scanned": files_scanned,
                                "truncated": True,
                            }
        return {
            "query": query,
            "results": results,
            "files_scanned": files_scanned,
            "truncated": False,
        }
