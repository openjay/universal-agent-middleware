from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .audit import HashChainedAuditLog
from .contracts import (
    BASELINE_FILE_DIGESTS,
    BASELINE_GIT_HEAD,
    PROFILE_REPOSITORY_CHANGE_V1,
    PROFILE_WORKSPACE_CHANGE_V2,
    ContractStore,
    normalize_file_path,
)
from .discovery import DiscoveryEngine, scan_coverage
from .exploration import ExplorationEngine
from .git_readonly import ReadOnlyGit
from .models import KIND_GIT_REPOSITORY, WorkspaceSpec
from .northbound import HostRoot, NorthboundBoundary, default_roots
from .project import ProjectRegistry, RegistryGenerationChanged
from .results import ExecutorResultStore
from .results_v2 import (
    ABSENT,
    INCOMPLETE,
    PRESENT,
    FileObservation,
    GitObservation,
    ResultV2Store,
    parse_status_paths,
)
from .reality_index import DEFAULT_MAX_AGE_SEC, RealityIndex
from .root_scope import RootScopeRegistry
from .errors import ContractError, ScopeAuthorityError, WorkspaceError, WorkspaceUnavailableError
from .path_authority import PathPolicy
from .resolver import RealityResolver, ResolutionError, ResolutionResult
from .policy import ensure_relative_path, resolve_safe_path
from .runtime import control_plane_paths, load_runtime, validate_dedicated_state, validate_paths
from .workspace import WorkspaceReader, WorkspaceRegistry


def _scope_ids(discovery: dict[str, Any] | None, status: str) -> list[str]:
    if discovery is None:
        return []
    return [scope["scope_id"] for scope in discovery["scopes"] if scope["status"] == status]


def _index_only_worktree_discovery(instances: list[dict[str, Any]]) -> dict[str, Any]:
    """The index holds no Git facts: nobody was asked, so its empty worktree list proves nothing."""
    return {
        "complete": False,
        "not_observed_instances": sorted(str(instance["workspace_id"]) for instance in instances),
    }


# ``WorkspaceReader.file_digest`` answers this, after the path was authorised, for a path that is not there.
# Authority is decided first, so the message is no existence oracle; ``tests/test_results_v2.py`` pins it.
_PATH_ABSENT_MESSAGE = "path does not exist"
_TREE_DEPTH = 8


class _GatewayReadback:
    """UAM's independent observation of a workspace, through the gateway's own authority-checked read path.

    Everything here is a read: it goes through the same resolver, nested-scope policy, descriptor-based
    reads and audit log as the read-only tools. Nothing a result claims is used to decide what to look at.
    """

    def __init__(self, gateway: MiddlewareGateway):
        self._gateway = gateway

    def git_observation(self, workspace_id: str) -> GitObservation:
        status = self._gateway._git(workspace_id).status()
        files, directories = parse_status_paths(status["status"])
        changed = set(files)
        complete = True
        reason: str | None = None
        for directory in directories:
            base = directory.rstrip("/")
            listing = self._gateway.tree(workspace_id, base, depth=_TREE_DEPTH)
            changed.update(entry["path"] for entry in listing["entries"] if entry["type"] == "file")
            # The listing silently stops below ``_TREE_DEPTH`` and withholds what a nested scope denies.
            deepest = max(
                (entry["path"].count("/") - base.count("/") for entry in listing["entries"] if entry["type"] == "dir"),
                default=0,
            )
            if listing["truncated"] or listing.get("excluded_by_scope_authority") or deepest >= _TREE_DEPTH:
                complete = False
                reason = "untracked_directory_not_fully_enumerated"
        return GitObservation(
            head=status["head"], changed_paths=frozenset(changed), complete=complete, incomplete_reason=reason,
        )

    def file_observation(self, workspace_id: str, path: str) -> FileObservation:
        try:
            result = self._gateway.file_digest(workspace_id, path)
        except WorkspaceError as exc:
            if str(exc) == _PATH_ABSENT_MESSAGE:
                return FileObservation(ABSENT)
            raise
        if result["complete"]:
            return FileObservation(PRESENT, sha256=result["sha256"], size_bytes=result["size_bytes"])
        return FileObservation(INCOMPLETE, reason=result["reason"])


class MiddlewareGateway:
    """Stable capability surface shared by all northbound protocol adapters."""

    def __init__(self, registry_path: str, state_dir: str, *, sealed_runtime: dict[str, Any] | None = None):
        """``sealed_runtime`` is a runtime the caller already admitted (``runtime.admit_dedicated_runtime``) for a process that keeps
        a state directory of its own. It binds exactly what ``UAM_RUNTIME_MANIFEST`` binds (the audit stamp, the FROZEN latch, the
        protected control-plane paths) but takes the dedicated-state rule instead of the one that forces the runtime's own state,
        and the environment variable is not consulted. Without it nothing changes."""
        self._started_at = datetime.now(timezone.utc).isoformat()
        self.registry = WorkspaceRegistry(registry_path)
        # Derived instances are only ever observed through the live resolver (see _git).
        self.projects = ProjectRegistry(self.registry, registry_path, derived_git=self._git)
        self.state_dir = Path(state_dir).expanduser().resolve(strict=False)
        self._validate_state_isolation()
        runtime = None
        # UAM's own directories: no directory workspace may overlap them (see AutoAdmissionEngine).
        protected_roots = [
            self.state_dir,
            Path(registry_path).expanduser().resolve(strict=False).parent,
        ]
        if sealed_runtime is not None:
            validate_dedicated_state(sealed_runtime, registry_path, state_dir)
            runtime = sealed_runtime
            protected_roots.extend(control_plane_paths(runtime))
        elif os.environ.get("UAM_RUNTIME_MANIFEST"):
            runtime = load_runtime(os.environ["UAM_RUNTIME_MANIFEST"])
            validate_paths(runtime, registry_path, state_dir)
            protected_roots.extend(control_plane_paths(runtime))
        self.audit = HashChainedAuditLog(
            self.state_dir / "audit.jsonl",
            runtime_release=Path(runtime["current_release"]).name if runtime else None,
            freeze_file=Path(runtime["recovery_root"]) / "FROZEN.json" if runtime else None,
        )
        self.contracts = ContractStore(self.state_dir)
        self.results = ExecutorResultStore(self.state_dir, self.contracts)
        self._readback = _GatewayReadback(self)
        self.results_v2 = ResultV2Store(self.state_dir, self.contracts, self._readback)

        scope_config = Path(registry_path).parent / "root_scopes.json"
        self.scopes = RootScopeRegistry(scope_config if scope_config.exists() else None)
        self.reality_index = RealityIndex(self.state_dir)
        self.discovery = DiscoveryEngine(self.scopes, reality_index=self.reality_index)
        self.exploration = ExplorationEngine(self.discovery, self.scopes)
        self.resolver = RealityResolver(
            self.registry, self.scopes, self.discovery, self.reality_index,
            protected_roots=protected_roots,
        )
        # The one place where an answer stops being data and becomes what a client reads (see northbound.py).
        self._control_roots = [Path(root) for root in protected_roots]
        self.northbound = NorthboundBoundary(self._host_roots)

    def _host_roots(self) -> list[HostRoot]:
        """Every directory this process knows by path, asked afresh each time (the registry and the scopes reload)."""
        roots: list[HostRoot] = []
        try:
            _, declarations = self.registry.declarations()
        except WorkspaceError:
            declarations = []  # an unreadable registry names no roots; the boundary's generic rule still applies
        for declared in declarations:
            for key in ("root", "resolved_root"):
                if declared.get(key):
                    roots.append(HostRoot("workspace", declared["workspace_id"], declared[key]))
        try:
            scopes = self.scopes.list_scopes()
        except Exception:  # a scope list that cannot be read must not stop an answer from being checked
            scopes = []
        roots.extend(HostRoot("scope", scope["scope_id"], scope["root"]) for scope in scopes)
        roots.append(HostRoot("state", "", str(self.state_dir)))
        roots.extend(HostRoot("config", "", str(root)) for root in self._control_roots if root != self.state_dir)
        return default_roots(roots)

    def _validate_state_isolation(self) -> None:
        # Unavailable workspaces stay in the check: their declared root can
        # still contain (or sit inside) the state directory.
        for raw in [*self.registry.list(), *self.registry.unavailable()]:
            root = Path(raw["root"]).resolve(strict=False)
            try:
                self.state_dir.relative_to(root)
            except ValueError:
                pass
            else:
                raise WorkspaceError(
                    f"UAM state_dir must be outside target workspace: {raw['workspace_id']}"
                )
            try:
                root.relative_to(self.state_dir)
            except ValueError:
                pass
            else:
                raise WorkspaceError(
                    f"target workspace must not be nested inside UAM state_dir: {raw['workspace_id']}"
                )

    def instance_info(self) -> dict[str, Any]:
        """Which process, release and configuration snapshot is answering.

        ``instance_id`` equals the ``writer_instance_id`` stamped on this
        process's audit records, so a response can be tied to its audit entries.
        """
        return {
            "instance_id": self.audit.writer_instance_id,
            "pid": os.getpid(),
            "started_at": self._started_at,
            "uam_version": __version__,
            "runtime_release": self.audit.runtime_release,
            "registry": self.registry.snapshot(),
            "policy_generation": self.scopes.policy_generation,
        }

    def resolve_workspace(self, workspace_id: str, capability: str = "filesystem.read") -> ResolutionResult:
        """Unified workspace resolution with live authority verification."""
        return self.resolver.resolve(workspace_id, capability)

    def _resolve(self, workspace_id: str, capability: str) -> ResolutionResult:
        """Resolve a workspace from the static registry OR derived auto-admission."""
        try:
            return self.resolver.resolve(workspace_id, capability)
        except ResolutionError as exc:
            cause = exc.__cause__
            if isinstance(cause, WorkspaceUnavailableError):
                raise WorkspaceUnavailableError(cause.workspace_id, cause.reason) from exc
            error = WorkspaceError(str(exc))
            error.diagnostic = exc.diagnostic
            raise error from exc

    def _resolve_workspace(self, workspace_id: str, capability: str) -> WorkspaceSpec:
        return self._resolve(workspace_id, capability).spec

    def _path_policy(self, resolution: ResolutionResult) -> PathPolicy:
        """Path-level authority for one operation on a resolved workspace.

        A static registration is its own, separately authorized contract and keeps it. Every
        other resolution (derived handle, absolute path, project name) was admitted from a
        RootScope, so RootScopes nested under its root narrow it. Default-guarded on purpose: a
        resolution kind added later is restricted until it is deliberately exempted.
        """
        if resolution.resolution_kind == "static":
            return PathPolicy.unrestricted()
        return PathPolicy.beneath(self.scopes, resolution.spec.root)

    def _reverify_resolution(self, resolution: ResolutionResult, capability: str) -> None:
        current = self._resolve(resolution.workspace_id, capability)
        bound = resolution.spec.root_identity
        now = current.spec.root_identity
        if bound is None or now is None or (
            (now.dev, now.ino, now.root, now.policy_version, now.policy_generation)
            != (bound.dev, bound.ino, bound.root, bound.policy_version, bound.policy_generation)
        ):
            raise WorkspaceError("workspace root identity changed")

    def _reader(self, workspace_id: str) -> WorkspaceReader:
        resolution = self._resolve(workspace_id, "filesystem.read")
        if resolution.spec.root_identity is None:
            raise WorkspaceError("workspace root identity is not bound")
        return WorkspaceReader(
            resolution.spec,
            path_policy=self._path_policy(resolution),
            authority_check=lambda: self._reverify_resolution(resolution, "filesystem.read"),
        )

    def _git(self, workspace_id: str) -> ReadOnlyGit:
        resolution = self._resolve(workspace_id, "git.observe")
        if resolution.spec.root_identity is None:
            raise WorkspaceError("workspace root identity is not bound")
        return ReadOnlyGit(
            resolution.spec.root,
            path_policy=self._path_policy(resolution),
            root_identity=resolution.spec.root_identity,
            authority_check=lambda: self._reverify_resolution(resolution, "git.observe"),
            require_bound_identity=True,
        )

    @contextmanager
    def _audited_denial(
        self, action: str, workspace_id: str, details: dict[str, Any],
    ) -> Iterator[None]:
        """Record a scope-authority denial in the audit chain, then let it propagate.

        The record names the path the caller asked for and the governing scope; it never carries
        content. Other failures keep their existing behaviour (they are not audited here).
        """
        try:
            yield
        except ScopeAuthorityError as exc:
            self.audit.append(
                action=action,
                workspace_id=workspace_id,
                outcome="DENIED",
                details={
                    **details,
                    "code": exc.code,
                    "operation": exc.operation,
                    "scope_id": exc.scope_id,
                },
            )
            raise

    def list_workspaces(self, *, view: str = "all") -> dict[str, Any]:
        """List workspaces with optional views: registered, discovered, all (default)."""
        request_id = str(uuid.uuid4())
        registered = self.registry.list()
        coverage = self.registry.coverage()
        result: dict[str, Any] = {
            "schema_version": "workspace-list-v1",
            "view": view,
            "registered": registered,
            "workspaces": registered,  # backward compat for v0.5 callers
            "coverage": coverage,
            "request_id": request_id,
            "instance": self.instance_info(),
        }

        # The registered view is answered from the registry alone: nothing about the index may cost it.
        discovered: list[dict[str, Any]] = []
        discovery: dict[str, Any] | None = None
        if view in ("discovered", "all"):
            discovered, discovery = self._discovered_workspaces()
            result["discovered"] = discovered
            result["discovery"] = discovery
        if view == "all":
            seen_paths: set[str] = set()
            for ws in registered:
                root = ws.get("root")
                if root:
                    seen_paths.add(str(Path(root).resolve()))
            eligible = list(registered)
            for entry in discovered:
                if not entry.get("capabilities"):
                    continue
                path = entry.get("path", "")
                if path:
                    realpath = str(Path(path).resolve())
                    if realpath in seen_paths:
                        continue
                    seen_paths.add(realpath)
                eligible.append(entry)
            result["eligible"] = eligible

        self.audit.append(
            action="list_workspaces",
            workspace_id=None,
            outcome="PASS",
            details={
                "count": len(registered),
                "discovered_count": len(discovered),
                "view": view,
                "unavailable_count": len(coverage["unavailable"]),
                "discovery_status": discovery["status"] if discovery is not None else "not_requested",
                "stale_scopes": _scope_ids(discovery, "stale"),
                "unavailable_scopes": _scope_ids(discovery, "unavailable"),
                "not_indexed_scopes": _scope_ids(discovery, "not_indexed"),
            },
            request_id=request_id,
        )
        return result

    def _discovered_workspaces(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Index-backed discovered entries, and what the index could and could not vouch for.

        The listing never waits for a scan, so it serves a snapshot even after its age limit. The
        age therefore travels with every entry and every scope, and a scope without a usable
        snapshot is named instead of contributing nothing: a project missing from the list is
        only "not found" when the status is ``fresh``, and then only within the bounded scan.

        Each scope is built whole or not at all. Whatever goes wrong while reading or shaping one
        scope costs that scope (``unavailable``) and never the other scopes or the registered part.
        """
        max_age_ms = int(DEFAULT_MAX_AGE_SEC * 1000)
        discovered: list[dict[str, Any]] = []
        scopes: list[dict[str, Any]] = []
        for scope in self.scopes.list_scopes():
            if not scope["authority"].get("discover"):
                continue
            try:
                item, entries = self._discovered_scope(scope)
            except Exception as exc:  # isolation boundary: reported as a status, never swallowed
                item = {
                    "scope_id": scope["scope_id"],
                    "status": "unavailable",
                    # The type only: exception text can carry host paths that must not leave.
                    "reason": f"reading this scope's index snapshot failed ({type(exc).__name__})",
                }
                entries = []
            scopes.append(item)
            discovered.extend(entries)

        statuses = {item["status"] for item in scopes}
        if not scopes:
            status = "not_configured"
        elif statuses & {"unavailable", "not_indexed"}:
            status = "incomplete"
        elif "stale" in statuses:
            status = "stale"
        else:
            status = "fresh"
        discovery = {
            "status": status,
            "max_age_ms": max_age_ms,
            "scopes": scopes,
            "coverage": scan_coverage(),
        }
        return discovered, discovery

    def _discovered_scope(
        self, scope: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """One scope's status item and its entries, from the index snapshot only."""
        scope_id = scope["scope_id"]
        snapshot = self.reality_index.get_active_snapshot(
            scope_id,
            self.scopes.policy_generation,
            allow_stale=True,
        )
        if snapshot is None:
            if not scope["authority"].get("index"):
                return {
                    "scope_id": scope_id,
                    "status": "not_indexed",
                    "reason": "scope has no index authority, so its projects are never part of "
                              "this list; use uam_scope_inventory",
                }, []
            return {
                "scope_id": scope_id,
                "status": "unavailable",
                "reason": self._no_snapshot_reason(),
            }, []
        stale = snapshot["freshness"]["stale"]
        age_ms = snapshot["freshness"]["cache_age_ms"]
        item = {
            "scope_id": scope_id,
            "status": "stale" if stale else "fresh",
            "cache_age_ms": age_ms,
            "total_projects": snapshot.get("total_projects"),
            "total_repositories": snapshot.get("total_repositories"),
        }
        entries: list[dict[str, Any]] = []
        for project in snapshot.get("projects", []):
            for inst in project.get("instances", []):
                ws_id = inst.get("workspace_id", "")
                caps, content_authorized, metadata_only = self._instance_authorization(inst)
                entries.append({
                    "workspace_id": ws_id,
                    "scope_id": scope_id,
                    "project_id": project.get("project_id", ""),
                    "path": inst.get("path", ""),
                    "admission_state": "discovered",
                    "capabilities": caps,
                    "content_authorized": content_authorized,
                    "metadata_only": metadata_only,
                    "source": "reality_index",
                    "freshness": {"stale": stale, "cache_age_ms": age_ms},
                })
        return item, entries

    def _no_snapshot_reason(self) -> str:
        """Why an indexable scope has no snapshot to serve, as far as the index can tell."""
        if self.reality_index.schema_incompatible:
            return ("the index schema is newer than this release supports, so its snapshots are not "
                    "served; uam_scope_inventory still answers by live scan")
        return ("no usable index snapshot: never indexed, indexed under a different "
                "policy generation, or the index could not be read")

    def _instance_authorization(
        self, inst: dict[str, Any]
    ) -> tuple[list[str], bool, bool]:
        """Return (capabilities, content_authorized, metadata_only) from live path policy."""
        path = inst.get("path", "")
        if not path:
            return [], False, False
        authority = self.scopes.effective_authority(path)
        if authority is None:
            return [], False, False
        metadata_only = authority.discover or authority.metadata_read
        if not authority.auto_admit or not authority.content_read:
            return [], False, metadata_only
        caps = ["filesystem.read"]
        if authority.git_observe:
            caps.append("git.observe")
        return caps, True, False

    def tree(
        self, workspace_id: str, path: str = ".", depth: int = 3
    ) -> dict[str, Any]:
        with self._audited_denial("tree", workspace_id, {"path": path, "depth": depth}):
            result = self._reader(workspace_id).tree(path, depth=depth)
        self.audit.append(
            action="tree",
            workspace_id=workspace_id,
            outcome="PASS",
            details={
                "path": path,
                "depth": depth,
                "entries": len(result["entries"]),
            },
        )
        return result

    def read_file(
        self,
        workspace_id: str,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        with self._audited_denial("read_file", workspace_id, {"path": path}):
            result = self._reader(workspace_id).read_file(
                path, start_line=start_line, end_line=end_line
            )
        self.audit.append(
            action="read_file",
            workspace_id=workspace_id,
            outcome="PASS",
            details={
                "path": path,
                "start_line": start_line,
                "end_line": result["end_line"],
            },
        )
        return result

    def file_digest(self, workspace_id: str, path: str) -> dict[str, Any]:
        with self._audited_denial("file_digest", workspace_id, {"path": path}):
            result = self._reader(workspace_id).file_digest(path)
        self.audit.append(
            action="file_digest",
            workspace_id=workspace_id,
            outcome="PASS",
            details={
                "path": path,
                "complete": result["complete"],
                "reason": result["reason"],
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
            },
        )
        return result

    def search(
        self,
        workspace_id: str,
        query: str,
        path: str = ".",
        max_results: int = 100,
    ) -> dict[str, Any]:
        with self._audited_denial("search", workspace_id, {"query": query[:80], "path": path}):
            result = self._reader(workspace_id).search_text(
                query, path=path, max_results=max_results
            )
        self.audit.append(
            action="search",
            workspace_id=workspace_id,
            outcome="PASS",
            details={
                "query": query[:80],
                "path": path,
                "results": len(result["results"]),
            },
        )
        return result

    def git_status(self, workspace_id: str) -> dict[str, Any]:
        result = self._git(workspace_id).status()
        self.audit.append(
            action="git_status", workspace_id=workspace_id, outcome="PASS"
        )
        return result

    def git_diff(
        self, workspace_id: str, path: str | None = None
    ) -> dict[str, Any]:
        with self._audited_denial("git_diff", workspace_id, {"path": path}):
            result = self._git(workspace_id).diff(path)
        self.audit.append(
            action="git_diff",
            workspace_id=workspace_id,
            outcome="PASS",
            details={"path": path},
        )
        return result

    def git_log(self, workspace_id: str, limit: int = 20) -> dict[str, Any]:
        result = self._git(workspace_id).log(limit)
        self.audit.append(
            action="git_log",
            workspace_id=workspace_id,
            outcome="PASS",
            details={"limit": limit},
        )
        return result

    def list_projects(self) -> dict[str, Any]:
        result = {"projects": self.projects.list_projects()}
        self.audit.append(
            action="list_projects",
            workspace_id=None,
            outcome="PASS",
            details={"count": len(result["projects"])},
        )
        return result

    def project_instances(self, project_id: str) -> dict[str, Any]:
        try:
            generation = self.projects.generation()
            project = self.projects.get_project(project_id)
            discovery = self.projects.worktree_discovery(project_id)
            unavailable = {
                item["workspace_id"]: item["reason"] for item in self.registry.unavailable()
            }
            instances = []
            for inst in project.instances:
                entry = inst.to_dict()
                if inst.workspace_id in unavailable:
                    entry["available"] = False
                    entry["unavailable_reason"] = unavailable[inst.workspace_id]
                instances.append(entry)
            result = {
                "project_id": project_id,
                "source": "registered",
                "repository_identity": project.repository_identity,
                "instances": instances,
                "discovered_worktrees": discovery.worktrees,
                "worktree_discovery": discovery.to_dict(),
            }
            self.projects.require_generation(generation)
        except RegistryGenerationChanged:
            raise  # an answer from two registry generations is dropped, never completed from the index
        except WorkspaceError:
            indexed = self.reality_index.get_project_instances(
                project_id,
                policy_generation=self.scopes.policy_generation,
            )
            if not indexed:
                raise
            instances = [self._indexed_instance_dict(inst) for inst in indexed]
            result = {
                "project_id": project_id,
                "source": "reality_index",
                "repository_identity": indexed[0].remote_identity if indexed else "",
                "instances": instances,
                "discovered_worktrees": [],
                "worktree_discovery": _index_only_worktree_discovery(instances),
            }
        self.audit.append(
            action="project_instances",
            workspace_id=None,
            outcome="PASS",
            details={
                "project_id": project_id,
                "source": result.get("source", "registered"),
                "instances": len(result["instances"]),
            },
        )
        return result

    def project_reality(self, project_id: str) -> dict[str, Any]:
        try:
            result = self.projects.project_reality_snapshot(project_id)
            result["source"] = "registered"
        except RegistryGenerationChanged:
            raise  # an answer from two registry generations is dropped, never completed from the index
        except WorkspaceError:
            indexed = self.reality_index.get_project_instances(
                project_id,
                policy_generation=self.scopes.policy_generation,
            )
            if not indexed:
                raise
            instances = []
            for inst in indexed:
                entry = self._indexed_instance_dict(inst)
                entry["observable"] = entry.get("content_authorized", False)
                instances.append(entry)
            result = {
                "schema_version": "project-reality-snapshot-v2",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "project_id": project_id,
                "source": "reality_index",
                "repository_identity": indexed[0].remote_identity,
                "instances": instances,
                "discovered_worktrees": [],
                "total_worktrees": 0,
                "unregistered_worktree_count": 0,
                "worktrees_truncated": False,
                "worktree_discovery": _index_only_worktree_discovery(instances),
                "coverage": {
                    "status": "PARTIAL",
                    "surfaces": {"canonical_source": "observed"},
                    "warnings": ["INDEX_ONLY: git metadata not hydrated; use workspace tools"],
                },
            }
        self.audit.append(
            action="project_reality",
            workspace_id=None,
            outcome="PASS",
            details={
                "project_id": project_id,
                "coverage_status": result["coverage"]["status"],
                "instances": len(result["instances"]),
                "source": result.get("source", "registered"),
            },
        )
        return result

    def _indexed_instance_dict(self, inst: Any) -> dict[str, Any]:
        scope_root = None
        for scope in self.scopes.list_scopes():
            if scope["scope_id"] == inst.scope_id:
                scope_root = scope.get("root")
                break
        path = str(Path(scope_root) / inst.rel_path) if scope_root and inst.rel_path else ""
        if not path and inst.rel_path:
            path = inst.rel_path
        caps, content_authorized, metadata_only = self._instance_authorization({"path": path})
        return {
            "workspace_id": inst.workspace_id,
            "project_id": inst.project_id,
            "scope_id": inst.scope_id,
            "rel_path": inst.rel_path,
            "admission_state": "discovered",
            "capabilities": caps,
            "content_authorized": content_authorized,
            "metadata_only": metadata_only,
        }

    def index_scope(
        self,
        scope_id: str,
        *,
        enrich_git: bool = False,
        background: bool = False,
    ) -> dict[str, Any]:
        """Build or refresh the cross-process reality index for a scope."""
        if background:
            scheduled = self.reality_index.schedule_background_refresh(
                scope_id,
                lambda: self.discovery.index_scope(scope_id, enrich_git=enrich_git),
            )
            return {
                "scope_id": scope_id,
                "status": "scheduled" if scheduled else "already_running",
            }
        result = self.discovery.index_scope(scope_id, enrich_git=enrich_git)
        outcome = "PASS" if "error" not in result else "DENY"
        self.audit.append(
            action="index_scope",
            workspace_id=None,
            outcome=outcome,
            details={
                "scope_id": scope_id,
                "total_projects": result.get("total_projects", 0),
                "index_generation": result.get("index_generation", ""),
            },
        )
        return result

    def list_scopes(self) -> dict[str, Any]:
        scopes = self.scopes.list_scopes()
        self.audit.append(
            action="list_scopes",
            workspace_id=None,
            outcome="PASS",
            details={"count": len(scopes)},
        )
        return {"scopes": scopes}

    def discover_projects(self, scope_id: str) -> dict[str, Any]:
        result = self.discovery.scope_inventory(scope_id, enrich_git=True)
        outcome = "PASS" if "error" not in result else "DENY"
        self.audit.append(
            action="discover_projects",
            workspace_id=None,
            outcome=outcome,
            details={
                "scope_id": scope_id,
                "total_projects": result.get("total_projects", 0),
                "total_repositories": result.get("total_repositories", 0),
            },
        )
        return result

    def scope_inventory(self, scope_id: str) -> dict[str, Any]:
        result = self.discovery.scope_inventory(scope_id)
        outcome = "PASS" if "error" not in result else "DENY"
        self.audit.append(
            action="scope_inventory",
            workspace_id=None,
            outcome=outcome,
            details={
                "scope_id": scope_id,
                "total_projects": result.get("total_projects", 0),
                "cache_hit": result.get("freshness", {}).get("cache_hit", False),
            },
        )
        return result

    def search_scope(self, scope_id: str, query: str, max_results: int = 50) -> dict[str, Any]:
        result = self.discovery.search_scope(scope_id, query, max_results=max_results)
        outcome = "PASS" if "error" not in result else "DENY"
        details: dict[str, Any] = {
            "scope_id": scope_id,
            "query": query[:80],
            "matches": result.get("total_matches", 0),
        }
        for key in ("search_completeness", "failure_reason", "failure_stage"):
            if result.get(key):
                details[key] = result[key]
        self.audit.append(
            action="search_scope",
            workspace_id=None,
            outcome=outcome,
            details=details,
        )
        return result

    def explain_coverage(self, scope_id: str, project_id: str) -> dict[str, Any]:
        result = self.exploration.explain_coverage(scope_id, project_id)
        self.audit.append(
            action="explain_coverage",
            workspace_id=None,
            outcome="PASS",
            details={
                "scope_id": scope_id,
                "project_id": project_id,
                "gaps_count": len(result.get("coverage_gaps", [])),
            },
        )
        return result

    def what_am_i_missing(self, scope_id: str) -> dict[str, Any]:
        result = self.exploration.what_am_i_missing(scope_id)
        self.audit.append(
            action="what_am_i_missing",
            workspace_id=None,
            outcome="PASS",
            details={
                "scope_id": scope_id,
                "total_gaps": result.get("total_gaps", 0),
            },
        )
        return result

    def explore(
        self, scope_id: str, intent: str = "", max_projects: int = 10,
        max_files: int = 50, max_bytes: int = 500_000,
    ) -> dict[str, Any]:
        result = self.exploration.explore(
            scope_id, intent=intent, max_projects=max_projects,
            max_files=max_files, max_bytes=max_bytes,
        )
        self.audit.append(
            action="explore",
            workspace_id=None,
            outcome="PASS",
            details={
                "scope_id": scope_id,
                "intent": intent[:80] if intent else "",
                "max_projects": max_projects,
                "ranked_count": len(result.get("ranked_projects", [])),
            },
        )
        return result

    def create_contract(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Admit and store an execution contract for a workspace UAM can resolve.

        The workspace may be a registered one, a derived instance (``derived:<scope>:<path>``), an
        absolute path inside an authorized scope or a project name; whichever way it was named, the
        contract stores the canonical identity the resolver returned and records how it was admitted.
        A derived instance is admitted only with the authority its scope grants now (including
        nested-scope narrowing), and a contract can name only paths UAM itself could read back.
        """
        profile = str(payload.get("profile", ""))
        capability = "git.observe" if profile == PROFILE_REPOSITORY_CHANGE_V1 else "filesystem.read"
        resolution = self._resolve(str(payload.get("workspace_id", "")), capability)
        workspace_id = resolution.workspace_id
        if profile == PROFILE_WORKSPACE_CHANGE_V2:
            return self._create_contract_v2(payload, resolution)
        spec = resolution.spec
        if profile == PROFILE_REPOSITORY_CHANGE_V1:
            policy = self._path_policy(resolution)
            observed = self._git(workspace_id).status()
            current_head = observed["head"]
            if current_head is None:
                raise ContractError(
                    "repository-change-v1 requires a base revision, and this repository has no commit yet"
                )
            if observed["status"].strip():
                raise ContractError(
                    "repository-change-v1 requires a clean observed workspace; use an isolated clean checkout/worktree"
                )
            if str(payload.get("base_revision", "")) != current_head:
                raise ContractError(
                    "repository-change-v1 base_revision must equal the observed workspace HEAD"
                )
            for path in payload.get("allowed_change_paths", []):
                if not isinstance(path, str):
                    raise ContractError("allowed_change_paths must contain strings")
                policy.require("read", Path(spec.root) / ensure_relative_path(path))
            git = self._git(workspace_id)
            for path in payload.get("authoritative_paths", []):
                if not isinstance(path, str):
                    raise ContractError("authoritative_paths must contain strings")
                resolved = resolve_safe_path(spec.root, path, must_exist=True)
                policy.require("read", resolved)
                if not resolved.is_file():
                    raise ContractError(
                        f"authoritative path must resolve to an existing file: {path}"
                    )
                if not git.is_tracked(path):
                    raise ContractError(
                        f"authoritative path must be tracked by the bound repository snapshot: {path}"
                    )
        result = self.contracts.put({**payload, "workspace_id": workspace_id})
        self.audit.append(
            action="create_contract",
            workspace_id=result["workspace_id"],
            outcome="PASS",
            details={
                "contract_id": result["contract_id"],
                "profile": result["profile"],
                "readiness": result["readiness"]["state"],
                "resolution_kind": resolution.resolution_kind,
            },
        )
        return result

    def _create_contract_v2(self, payload: dict[str, Any], resolution: ResolutionResult) -> dict[str, Any]:
        """A ``workspace-change-v2`` contract: the baseline is what UAM observes now, never what the caller states."""
        workspace_id = resolution.workspace_id
        spec = resolution.spec
        policy = self._path_policy(resolution)
        root = Path(spec.root)
        paths: dict[str, list[str]] = {}
        for name in ("authoritative_paths", "allowed_change_paths"):
            value = payload.get(name, [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ContractError(f"{name} must be a list of strings")
            paths[name] = [normalize_file_path(item, name) for item in value]
            for path in paths[name]:
                # A path UAM may not read is a path whose result UAM could never verify.
                policy.require("read", root / path)
        if spec.kind == KIND_GIT_REPOSITORY:
            git = self._git(workspace_id)
            observed = git.status()
            if observed["head"] is None:
                raise ContractError(
                    "a git-head baseline requires a commit, and this repository has no commit yet"
                )
            if observed["status"].strip():
                raise ContractError(
                    "a git-head baseline requires a clean observed workspace; use an isolated clean checkout/worktree"
                )
            for path in paths["authoritative_paths"]:
                resolved = resolve_safe_path(root, path, must_exist=True)
                if not resolved.is_file():
                    raise ContractError(f"authoritative path must resolve to an existing file: {path}")
                if not git.is_tracked(path):
                    raise ContractError(
                        f"authoritative path must be tracked by the bound repository snapshot: {path}"
                    )
            baseline: dict[str, Any] = {"kind": BASELINE_GIT_HEAD, "revision": observed["head"]}
        else:
            files: dict[str, Any] = {}
            for path in paths["authoritative_paths"]:
                files[path] = self._baseline_file_state(workspace_id, path, must_exist=True)
            for path in paths["allowed_change_paths"]:
                if path not in files:
                    files[path] = self._baseline_file_state(workspace_id, path, must_exist=False)
            baseline = {"kind": BASELINE_FILE_DIGESTS, "files": files}
        # The admission recorded below must still be the live one when the contract is written.
        self._reverify_resolution(resolution, "filesystem.read")
        admission = {
            "resolution_kind": resolution.resolution_kind,
            "workspace_kind": spec.kind,
            "scope_id": resolution.scope_id,
            "policy_generation": resolution.policy_generation,
        }
        result = self.contracts.put_v2(
            {**payload, "workspace_id": workspace_id}, baseline=baseline, admission=admission,
        )
        self.audit.append(
            action="create_contract",
            workspace_id=result["workspace_id"],
            outcome="PASS",
            details={
                "contract_id": result["contract_id"],
                "profile": result["profile"],
                "readiness": result["readiness"]["state"],
                "resolution_kind": resolution.resolution_kind,
                "baseline_kind": baseline["kind"],
                "contract_digest": result["contract_digest"],
            },
        )
        return result

    def _baseline_file_state(self, workspace_id: str, path: str, *, must_exist: bool) -> dict[str, Any]:
        observation = self._readback.file_observation(workspace_id, path)
        if observation.state == ABSENT:
            if must_exist:
                raise ContractError(f"authoritative path must resolve to an existing file: {path}")
            return {"absent": True}
        if observation.state == INCOMPLETE:
            raise ContractError(f"cannot baseline {path}: its digest could not be established ({observation.reason})")
        return {"sha256": observation.sha256, "size_bytes": observation.size_bytes}

    def get_contract(self, contract_id: str) -> dict[str, Any]:
        result = self.contracts.get_record(contract_id)
        self.audit.append(
            action="get_contract",
            workspace_id=result["workspace_id"],
            outcome="PASS",
            details={"contract_id": contract_id},
        )
        return result

    def record_executor_result(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.results.put(payload)
        self.audit.append(
            action="record_executor_result",
            workspace_id=result["workspace_id"],
            outcome=result["review"]["state"],
            details={
                "result_id": result["result_id"],
                "contract_id": result["contract_id"],
                "blockers": result["review"]["blockers"],
            },
        )
        return result

    def get_executor_result(self, result_id: str) -> dict[str, Any]:
        result = self.results.get(result_id)
        self.audit.append(
            action="get_executor_result",
            workspace_id=result["workspace_id"],
            outcome="PASS",
            details={"result_id": result_id},
        )
        return result

    def record_result_v2(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Admit a ``uam-result-v2`` result: validate, bind to its contract, observe the live workspace, review."""
        result = self.results_v2.put(payload)
        review = result["review"]
        self.audit.append(
            action="record_result_v2",
            # The contract's workspace, not the one the submitter named.
            workspace_id=self.contracts.binding(result["contract_id"]).workspace_id,
            outcome=review["state"],
            details={
                "result_id": result["result_id"],
                "contract_id": result["contract_id"],
                "result_kind": result["result_kind"],
                "blockers": review["blockers"],
                "readback": review["readback"]["state"],
            },
        )
        return result

    def get_result_v2(self, result_id: str) -> dict[str, Any]:
        result = self.results_v2.get(result_id)
        self.audit.append(
            action="get_result_v2",
            workspace_id=None,
            outcome="PASS",
            details={"result_id": result_id},
        )
        return result
