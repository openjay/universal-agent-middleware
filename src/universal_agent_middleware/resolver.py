"""Unified workspace resolution for UAM v0.6.

RealityResolver provides a single entry point for resolving workspace selectors
(static IDs, derived handles, project names, absolute paths) to WorkspaceSpec
instances with live authority verification at read time.

Index/Resolver provides candidates; Authority policy decides permission at read time.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .discovery import DiscoveryEngine
from .errors import WorkspaceError, WorkspaceUnavailableError
from .models import (
    KIND_CAPABILITIES,
    KIND_FILESYSTEM_DIRECTORY,
    KIND_GIT_REPOSITORY,
    WorkspaceSpec,
    is_git_checkout,
)
from .policy import is_denied_component
from .reality_index import RealityIndex
from .root_scope import RootScope, RootScopeRegistry
from .workspace import WorkspaceRegistry, bind_root_identity

ResolutionKind = Literal[
    "static",
    "derived",
    "project_name",
    "absolute_path",
]

ResolutionErrorKind = Literal[
    "DENIED",
    "AMBIGUOUS",
    "NOT_FOUND",
    "INVALID",
    "UNAVAILABLE",
    "UNSUPPORTED",
]

WORKSPACE_DIAGNOSTIC_SCHEMA = "workspace-diagnostic-v1"


def non_git_directory_diagnostic(scope_id: str) -> dict[str, Any]:
    """Why an existing, authorized directory was not served as a repository workspace.

    Carries no host path and no file content: it states what exists inside which authorized
    scope and which explicit step would turn it into a readable workspace.
    """
    return {
        "schema_version": WORKSPACE_DIAGNOSTIC_SCHEMA,
        "status": "UNSUPPORTED_WORKSPACE_KIND",
        "reason": "NON_GIT_DIRECTORY",
        "path_exists": True,
        "scope_authorized": True,
        "scope_id": scope_id,
        "directory_admission": "NOT_ENABLED",
        "suggested_actions": ["REGISTER_FILESYSTEM_DIRECTORY", "ENABLE_DIRECTORY_ADMISSION"],
    }


def unsupported_capability_diagnostic(kind: str, capability: str) -> dict[str, Any]:
    """Why a capability can never be granted for a workspace of this kind."""
    return {
        "schema_version": WORKSPACE_DIAGNOSTIC_SCHEMA,
        "status": "UNSUPPORTED_CAPABILITY",
        "reason": "CAPABILITY_NOT_SUPPORTED_BY_WORKSPACE_KIND",
        "workspace_kind": kind,
        "capability": capability,
        "supported_capabilities": sorted(KIND_CAPABILITIES.get(kind, ())),
    }


@dataclass
class ResolutionCandidate:
    workspace_id: str
    scope_id: str
    rel_path: str
    project_id: str = ""
    resolution_kind: ResolutionKind = "derived"

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "scope_id": self.scope_id,
            "rel_path": self.rel_path,
            "project_id": self.project_id,
            "resolution_kind": self.resolution_kind,
        }


@dataclass
class ResolutionResult:
    spec: WorkspaceSpec
    workspace_id: str
    resolution_kind: ResolutionKind
    policy_generation: str
    scope_id: str = ""
    project_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "resolution_kind": self.resolution_kind,
            "policy_generation": self.policy_generation,
            "scope_id": self.scope_id,
            "project_id": self.project_id,
            "capabilities": self.spec.capabilities,
            "kind": self.spec.kind,
            "label": self.spec.label,
        }


class ResolutionError(WorkspaceError):
    """Structured resolution failure."""

    def __init__(
        self,
        message: str,
        *,
        kind: ResolutionErrorKind,
        candidates: list[ResolutionCandidate] | None = None,
        diagnostic: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.kind = kind
        self.candidates = candidates or []
        self.diagnostic = diagnostic

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"error": str(self), "kind": self.kind}
        if self.candidates:
            d["candidates"] = [c.to_dict() for c in self.candidates]
        if self.diagnostic:
            d["diagnostic"] = self.diagnostic
        return d


class AutoAdmissionEngine:
    """On-demand admission of repositories and ordinary directories inside authorized scopes.

    A path holding a ``.git`` entry is admitted as a ``git-repository`` (scope bit
    ``auto_admit``); any other directory is admitted as a read-only ``filesystem-directory``
    only when the most specific scope enables ``directory_admit``. Both need ``content_read``.

    Capabilities are computed fresh on every call — never cached permanently.
    """

    def __init__(
        self,
        scope_registry: RootScopeRegistry,
        *,
        protected_roots: Sequence[Path | str] = (),
    ):
        self._scopes = scope_registry
        self._protected_roots = tuple(Path(p).resolve() for p in protected_roots)

    def overlaps_control_plane(self, root: Path) -> bool:
        """True when ``root`` equals, contains or lies inside one of UAM's own paths."""
        resolved = root.resolve()
        return any(
            resolved == protected
            or resolved.is_relative_to(protected)
            or protected.is_relative_to(resolved)
            for protected in self._protected_roots
        )

    def admit(
        self,
        full_path: Path,
        *,
        workspace_id: str,
        scope_id: str = "",
        rel_path: str = "",
    ) -> WorkspaceSpec:
        """Admit a repository or directory path after live authority verification.

        Authority is checked before the filesystem is consulted, so a path outside every
        authorized scope (or in a scope that cannot admit) is refused identically whether or
        not it exists.
        """
        resolved = full_path.resolve()
        name = rel_path or resolved.name

        effective = self._scopes.effective_authority(resolved)
        if effective is None:
            raise ResolutionError(
                f"path {name} is not within any authorized scope",
                kind="DENIED",
            )

        if not (effective.auto_admit or effective.directory_admit):
            raise ResolutionError(
                f"most-specific scope for {name} does not permit auto-admission",
                kind="DENIED",
            )

        if not effective.content_read:
            raise ResolutionError(
                f"most-specific scope for {name} denies content_read",
                kind="DENIED",
            )

        scope = self._scopes.resolve_scope(resolved)
        if scope is None:
            raise ResolutionError(
                f"path {name} is not within any authorized scope",
                kind="DENIED",
            )

        scope_root = Path(scope.root).resolve()
        try:
            resolved.relative_to(scope_root)
        except ValueError:
            raise WorkspaceError("path escapes scope root")

        if is_git_checkout(resolved):
            return self._admit_repository(
                resolved, effective.auto_admit, workspace_id=workspace_id, name=name,
            )
        return self._admit_directory(
            resolved,
            scope,
            scope_root,
            effective.directory_admit,
            workspace_id=workspace_id,
            name=name,
        )

    def _admit_repository(
        self, resolved: Path, auto_admit: bool, *, workspace_id: str, name: str,
    ) -> WorkspaceSpec:
        if not auto_admit:
            raise ResolutionError(
                f"most-specific scope for {name} does not permit auto-admission",
                kind="DENIED",
            )
        try:
            identity = bind_root_identity(resolved, policy_generation=self._scopes.policy_generation)
        except WorkspaceError as exc:
            raise ResolutionError(f"derived workspace path not found: {name}", kind="NOT_FOUND") from exc
        return WorkspaceSpec(
            workspace_id=workspace_id,
            root=str(resolved),
            label=f"[auto-admitted] {name}",
            kind=KIND_GIT_REPOSITORY,
            capabilities=self._capabilities_for_path(resolved),
            root_identity=identity,
        )

    def _admit_directory(
        self,
        resolved: Path,
        scope: RootScope,
        scope_root: Path,
        directory_admit: bool,
        *,
        workspace_id: str,
        name: str,
    ) -> WorkspaceSpec:
        if not directory_admit:
            if not resolved.is_dir():
                raise ResolutionError(
                    f"derived workspace path not found: {name}", kind="NOT_FOUND",
                )
            raise ResolutionError(
                f"{name} is not a Git repository and scope {scope.scope_id} "
                "does not enable directory_admit",
                kind="UNSUPPORTED",
                diagnostic=non_git_directory_diagnostic(scope.scope_id),
            )

        for part in resolved.relative_to(scope_root).parts:
            if is_denied_component(part):
                raise ResolutionError(
                    f"directory path contains a protected name and cannot be admitted: {part}",
                    kind="DENIED",
                )
        if self.overlaps_control_plane(resolved):
            raise ResolutionError(
                f"directory {name} overlaps the UAM control plane and cannot be admitted",
                kind="DENIED",
            )
        nested = self._scopes.nested_scopes(resolved)
        if nested:
            raise ResolutionError(
                f"directory {name} spans nested scope {nested[0][1].scope_id}; "
                "admit a narrower directory or the nested scope itself",
                kind="DENIED",
            )
        if not resolved.is_dir():
            raise ResolutionError(f"derived workspace path not found: {name}", kind="NOT_FOUND")
        try:
            identity = bind_root_identity(resolved, policy_generation=self._scopes.policy_generation)
        except WorkspaceError as exc:
            raise ResolutionError(f"derived workspace path not found: {name}", kind="NOT_FOUND") from exc
        return WorkspaceSpec(
            workspace_id=workspace_id,
            root=str(resolved),
            label=f"[directory-admitted] {name}",
            kind=KIND_FILESYSTEM_DIRECTORY,
            capabilities=["filesystem.read"],
            root_identity=identity,
        )

    def _capabilities_for_path(
        self, path: Path, kind: str = KIND_GIT_REPOSITORY,
    ) -> list[str]:
        """Compute capabilities from live effective authority — never cached."""
        effective = self._scopes.effective_authority(path)
        if effective is None or not effective.content_read:
            return []
        if kind == KIND_FILESYSTEM_DIRECTORY:
            return ["filesystem.read"] if effective.directory_admit else []
        caps = ["filesystem.read"]
        if effective.git_observe:
            caps.append("git.observe")
        return caps

    def verify_capability(
        self, path: Path, capability: str, kind: str = KIND_GIT_REPOSITORY,
    ) -> None:
        """Re-verify a capability against live authority before an operation."""
        caps = self._capabilities_for_path(path.resolve(), kind)
        if capability not in caps:
            raise ResolutionError(
                f"live authority denies {capability} for this workspace",
                kind="DENIED",
            )


class RealityResolver:
    """Unified workspace selector resolution with live authority checks."""

    def __init__(
        self,
        registry: WorkspaceRegistry,
        scope_registry: RootScopeRegistry,
        discovery: DiscoveryEngine | None = None,
        reality_index: RealityIndex | None = None,
        *,
        protected_roots: Sequence[Path | str] = (),
    ):
        self._registry = registry
        self._scopes = scope_registry
        self._discovery = discovery
        self._index = reality_index
        self._admission = AutoAdmissionEngine(scope_registry, protected_roots=protected_roots)

    @property
    def admission(self) -> AutoAdmissionEngine:
        return self._admission

    @staticmethod
    def _require_kind_support(kind: str, capability: str) -> None:
        """Refuse a capability the workspace kind can never grant, with a machine-readable why."""
        if capability not in KIND_CAPABILITIES.get(kind, frozenset()):
            raise ResolutionError(
                f"workspace kind {kind} does not support {capability}",
                kind="UNSUPPORTED",
                diagnostic=unsupported_capability_diagnostic(kind, capability),
            )

    def resolve(self, selector: str, capability: str = "filesystem.read") -> ResolutionResult:
        """Resolve a workspace selector to a WorkspaceSpec with live authority."""
        # 1. Static registry (priority override). A registered identity whose
        # root is unavailable must fail here: falling through to derived or
        # bare-name resolution would silently rebind it to another workspace.
        if self._registry.is_registered(selector):
            try:
                self._require_kind_support(self._registry.get(selector).kind, capability)
                spec = self._registry.require_capability(selector, capability)
            except WorkspaceUnavailableError as exc:
                raise ResolutionError(str(exc), kind="UNAVAILABLE") from exc
            except ResolutionError:
                raise
            except WorkspaceError as exc:
                raise ResolutionError(
                    str(exc),
                    kind="DENIED",
                ) from exc
            if spec.kind == KIND_FILESYSTEM_DIRECTORY and self._admission.overlaps_control_plane(
                Path(spec.root)
            ):
                raise ResolutionError(
                    f"directory workspace {selector} overlaps the UAM control plane "
                    "and cannot be served",
                    kind="DENIED",
                )
            return ResolutionResult(
                spec=spec,
                workspace_id=selector,
                resolution_kind="static",
                policy_generation=self._scopes.policy_generation,
            )

        # 2. Derived handle: derived:scope_id:rel_path
        if selector.startswith("derived:"):
            return self._resolve_derived(selector, capability)

        # 3. Absolute path within authorized scope
        if selector.startswith("/"):
            return self._resolve_absolute_path(selector, capability)

        # 4. Project name / bare alias
        return self._resolve_by_name(selector, capability)

    def _resolve_derived(self, workspace_id: str, capability: str) -> ResolutionResult:
        parts = workspace_id.split(":", 2)
        if len(parts) < 3:
            raise ResolutionError(
                f"invalid derived workspace id: {workspace_id}",
                kind="INVALID",
            )

        scope_id = parts[1]
        rel_path = parts[2]

        target_scope = None
        for s in self._scopes._scopes:
            if s.scope_id == scope_id:
                target_scope = s
                break
        if not target_scope:
            raise ResolutionError(
                f"unknown scope in derived workspace: {scope_id}",
                kind="NOT_FOUND",
            )

        full_path = (Path(target_scope.root) / rel_path).resolve()
        spec = self._admission.admit(
            full_path,
            workspace_id=workspace_id,
            scope_id=scope_id,
            rel_path=rel_path,
        )
        self._require_kind_support(spec.kind, capability)
        self._admission.verify_capability(full_path, capability, spec.kind)
        return ResolutionResult(
            spec=spec,
            workspace_id=workspace_id,
            resolution_kind="derived",
            policy_generation=self._scopes.policy_generation,
            scope_id=scope_id,
        )

    def _resolve_absolute_path(self, abs_path: str, capability: str) -> ResolutionResult:
        path = Path(abs_path).resolve()

        # Authority first, existence second: a path outside every authorized scope is
        # refused the same way whether or not it exists, and the message never echoes it.
        scope = self._scopes.resolve_scope(path)
        if scope is None:
            raise ResolutionError(
                "absolute path is not within any authorized scope",
                kind="DENIED",
            )

        try:
            rel = str(path.relative_to(Path(scope.root).resolve()))
        except ValueError:
            raise ResolutionError(
                "absolute path escapes scope root",
                kind="DENIED",
            )

        workspace_id = f"derived:{scope.scope_id}:{rel}"
        spec = self._admission.admit(
            path,
            workspace_id=workspace_id,
            scope_id=scope.scope_id,
            rel_path=rel,
        )
        self._require_kind_support(spec.kind, capability)
        self._admission.verify_capability(path, capability, spec.kind)
        return ResolutionResult(
            spec=spec,
            workspace_id=workspace_id,
            resolution_kind="absolute_path",
            policy_generation=self._scopes.policy_generation,
            scope_id=scope.scope_id,
        )

    def _resolve_by_name(self, name: str, capability: str) -> ResolutionResult:
        """Resolve a bare project name via discovery index."""
        if self._discovery is None:
            raise ResolutionError(
                f"unknown workspace: {name}",
                kind="NOT_FOUND",
            )

        candidates = self._find_name_candidates(name)
        if not candidates:
            raise ResolutionError(
                f"no workspace found matching: {name}",
                kind="NOT_FOUND",
            )
        if len(candidates) > 1:
            raise ResolutionError(
                f"ambiguous workspace selector '{name}': {len(candidates)} candidates",
                kind="AMBIGUOUS",
                candidates=candidates,
            )

        candidate = candidates[0]
        result = self._resolve_derived(candidate.workspace_id, capability)
        return ResolutionResult(
            spec=result.spec,
            workspace_id=result.workspace_id,
            resolution_kind="project_name",
            policy_generation=result.policy_generation,
            scope_id=result.scope_id,
            project_id=candidate.project_id,
        )

    def _find_name_candidates(self, name: str) -> list[ResolutionCandidate]:
        """Find workspace candidates matching a bare project name."""
        normalized = name.lower().strip()
        candidates: list[ResolutionCandidate] = []

        # Sub-millisecond fast path: SQLite alias index
        if self._index is not None and not self._index.is_corrupt:
            indexed = self._index.lookup_by_alias(
                normalized,
                policy_generation=self._scopes.policy_generation,
            )
            for inst in indexed:
                scope_entry = next(
                    (s for s in self._scopes.list_scopes() if s["scope_id"] == inst.scope_id),
                    None,
                )
                if not scope_entry:
                    continue
                if not scope_entry["authority"].get("auto_admit"):
                    continue
                if not scope_entry["authority"].get("content_read"):
                    continue
                candidates.append(ResolutionCandidate(
                    workspace_id=inst.workspace_id,
                    scope_id=inst.scope_id,
                    rel_path=inst.rel_path,
                    project_id=inst.project_id,
                    resolution_kind="project_name",
                ))
            if candidates:
                return candidates

        for scope_entry in self._scopes.list_scopes():
            if not scope_entry["authority"].get("auto_admit"):
                continue
            if not scope_entry["authority"].get("discover"):
                continue

            scope_id = scope_entry["scope_id"]
            scope_root = Path(scope_entry["root"])

            try:
                inventory = self._discovery.scope_inventory(scope_id) if self._discovery else {}
            except Exception:
                continue

            if "error" in inventory:
                candidates.extend(
                    self._scan_scope_for_name(scope_id, scope_root, normalized)
                )
                continue

            for project in inventory.get("projects", []):
                project_id = project.get("project_id", "").lower()
                if project_id != normalized and not project_id.endswith(f"/{normalized}"):
                    basename_match = project_id == normalized
                    if not basename_match and "/" in project_id:
                        basename_match = project_id.rsplit("/", 1)[-1] == normalized
                    if not basename_match:
                        continue

                for inst in project.get("instances", []):
                    ws_id = inst.get("workspace_id", "")
                    if not ws_id:
                        inst_path = inst.get("path", "")
                        if inst_path:
                            try:
                                rel = str(Path(inst_path).relative_to(scope_root.resolve()))
                                ws_id = f"derived:{scope_id}:{rel}"
                            except ValueError:
                                ws_id = f"derived:{scope_id}:{Path(inst_path).name}"
                    if ws_id:
                        candidates.append(ResolutionCandidate(
                            workspace_id=ws_id,
                            scope_id=scope_id,
                            rel_path=ws_id.split(":", 2)[-1] if ws_id.startswith("derived:") else "",
                            project_id=project.get("project_id", ""),
                            resolution_kind="project_name",
                        ))

            if not any(c.scope_id == scope_id for c in candidates):
                candidates.extend(
                    self._scan_scope_for_name(scope_id, scope_root, normalized)
                )

        return candidates

    def _scan_scope_for_name(
        self, scope_id: str, scope_root: Path, normalized: str,
    ) -> list[ResolutionCandidate]:
        """Lightweight filesystem scan for a repo matching the name."""
        found: list[ResolutionCandidate] = []
        if not scope_root.is_dir():
            return found

        def walk(path: Path, depth: int = 0) -> None:
            if depth > 4:
                return
            try:
                entries = list(path.iterdir())
            except (PermissionError, OSError):
                return

            has_git = any(e.name == ".git" for e in entries)
            if has_git:
                repo_name = path.name.lower()
                if repo_name == normalized:
                    try:
                        rel = str(path.resolve().relative_to(scope_root.resolve()))
                    except ValueError:
                        rel = path.name
                    ws_id = f"derived:{scope_id}:{rel}"
                    effective = self._scopes.effective_authority(path)
                    if effective and effective.auto_admit and effective.content_read:
                        found.append(ResolutionCandidate(
                            workspace_id=ws_id,
                            scope_id=scope_id,
                            rel_path=rel,
                            project_id=repo_name,
                            resolution_kind="project_name",
                        ))
                return

            for entry in entries:
                if entry.is_dir() and not entry.is_symlink():
                    if entry.name.startswith(".") and entry.name != ".git":
                        continue
                    walk(entry, depth + 1)

        walk(scope_root)
        return found
