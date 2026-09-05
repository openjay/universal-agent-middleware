from __future__ import annotations

from pathlib import Path
import os
from typing import Any

from .audit import HashChainedAuditLog
from .contracts import ContractStore
from .discovery import DiscoveryEngine
from .exploration import ExplorationEngine
from .git_readonly import ReadOnlyGit
from .models import WorkspaceSpec
from .project import ProjectRegistry
from .results import ExecutorResultStore
from .root_scope import RootScopeRegistry
from .errors import ContractError, WorkspaceError
from .policy import ensure_relative_path, resolve_safe_path
from .workspace import WorkspaceReader, WorkspaceRegistry


class MiddlewareGateway:
    """Stable capability surface shared by all northbound protocol adapters."""

    def __init__(self, registry_path: str, state_dir: str):
        self.registry = WorkspaceRegistry(registry_path)
        self.projects = ProjectRegistry(self.registry, registry_path)
        self.state_dir = Path(state_dir).expanduser().resolve(strict=False)
        self._validate_state_isolation()
        runtime = None
        if os.environ.get("UAM_RUNTIME_MANIFEST"):
            from .runtime import load_runtime, validate_paths
            runtime = load_runtime(os.environ["UAM_RUNTIME_MANIFEST"])
            validate_paths(runtime, registry_path, state_dir)
        self.audit = HashChainedAuditLog(
            self.state_dir / "audit.jsonl",
            runtime_release=Path(runtime["current_release"]).name if runtime else None,
            freeze_file=Path(runtime["recovery_root"]) / "FROZEN.json" if runtime else None,
        )
        self.contracts = ContractStore(self.state_dir)
        self.results = ExecutorResultStore(self.state_dir, self.contracts)

        scope_config = Path(registry_path).parent / "root_scopes.json"
        self.scopes = RootScopeRegistry(scope_config if scope_config.exists() else None)
        self.discovery = DiscoveryEngine(self.scopes)
        self.exploration = ExplorationEngine(self.discovery, self.scopes)

        self._derived_specs: dict[str, WorkspaceSpec] = {}

    def _validate_state_isolation(self) -> None:
        for raw in self.registry.list():
            root = Path(raw["root"]).resolve(strict=True)
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

    def _resolve_workspace(self, workspace_id: str, capability: str) -> WorkspaceSpec:
        """Resolve workspace from static registry OR derived auto-admission."""
        try:
            return self.registry.require_capability(workspace_id, capability)
        except WorkspaceError:
            pass

        if workspace_id.startswith("derived:"):
            spec = self._get_or_create_derived(workspace_id)
            if capability not in spec.capabilities:
                raise WorkspaceError(
                    f"derived workspace {workspace_id} does not grant {capability}"
                )
            return spec

        raise WorkspaceError(f"unknown workspace: {workspace_id}")

    def _get_or_create_derived(self, workspace_id: str) -> WorkspaceSpec:
        """Create a derived WorkspaceSpec for a repository within an authorized scope.

        Admission requires: auto_admit=true, content_read=true, path inside scope,
        .git marker present (verified repository), and secret/traversal policies pass.
        This is on-demand repository admission within an authorized auto-admit scope.
        """
        if workspace_id in self._derived_specs:
            return self._derived_specs[workspace_id]

        parts = workspace_id.split(":", 2)
        if len(parts) < 3:
            raise WorkspaceError(f"invalid derived workspace id: {workspace_id}")

        scope_id = parts[1]
        rel_path = parts[2]

        target_scope = None
        for s in self.scopes._scopes:
            if s.scope_id == scope_id:
                target_scope = s
                break
        if not target_scope:
            raise WorkspaceError(f"unknown scope in derived workspace: {scope_id}")

        if not target_scope.authority.auto_admit:
            raise WorkspaceError(f"scope {scope_id} does not permit auto-admission")

        if not target_scope.authority.content_read:
            raise WorkspaceError(f"scope {scope_id} does not grant content_read")

        full_path = (Path(target_scope.root) / rel_path).resolve()
        scope_root = Path(target_scope.root).resolve()

        try:
            full_path.relative_to(scope_root)
        except ValueError:
            raise WorkspaceError("path escapes scope root")

        if not full_path.is_dir():
            raise WorkspaceError(f"derived workspace path not found: {rel_path}")

        if not (full_path / ".git").exists() and not (full_path / ".git").is_file():
            raise WorkspaceError(
                f"derived workspace must be a discovered repository (no .git): {rel_path}"
            )

        capabilities = ["filesystem.read"]
        if target_scope.authority.git_observe:
            capabilities.append("git.observe")

        spec = WorkspaceSpec(
            workspace_id=workspace_id,
            root=str(full_path),
            label=f"[auto-admitted] {rel_path}",
            kind="git-repository",
            capabilities=capabilities,
        )
        self._derived_specs[workspace_id] = spec
        return spec

    def _reader(self, workspace_id: str) -> WorkspaceReader:
        return WorkspaceReader(self._resolve_workspace(workspace_id, "filesystem.read"))

    def _git(self, workspace_id: str) -> ReadOnlyGit:
        spec = self._resolve_workspace(workspace_id, "git.observe")
        return ReadOnlyGit(spec.root)

    def list_workspaces(self) -> dict[str, Any]:
        result = {"workspaces": self.registry.list()}
        self.audit.append(
            action="list_workspaces",
            workspace_id=None,
            outcome="PASS",
            details={"count": len(result["workspaces"])},
        )
        return result

    def tree(
        self, workspace_id: str, path: str = ".", depth: int = 3
    ) -> dict[str, Any]:
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

    def search(
        self,
        workspace_id: str,
        query: str,
        path: str = ".",
        max_results: int = 100,
    ) -> dict[str, Any]:
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
        project = self.projects.get_project(project_id)
        worktrees = self.projects.discover_worktrees(project_id)
        result = {
            "project_id": project_id,
            "repository_identity": project.repository_identity,
            "instances": [i.to_dict() for i in project.instances],
            "discovered_worktrees": worktrees,
        }
        self.audit.append(
            action="project_instances",
            workspace_id=None,
            outcome="PASS",
            details={
                "project_id": project_id,
                "registered": len(project.instances),
                "worktrees_discovered": len(worktrees),
            },
        )
        return result

    def project_reality(self, project_id: str) -> dict[str, Any]:
        result = self.projects.project_reality_snapshot(project_id)
        self.audit.append(
            action="project_reality",
            workspace_id=None,
            outcome="PASS",
            details={
                "project_id": project_id,
                "coverage_status": result["coverage"]["status"],
                "instances": len(result["instances"]),
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
        result = self.discovery.discover_scope(scope_id)
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
        self.audit.append(
            action="search_scope",
            workspace_id=None,
            outcome=outcome,
            details={
                "scope_id": scope_id,
                "query": query[:80],
                "matches": result.get("total_matches", 0),
            },
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
                "gaps_count": len(result.get("gaps", [])),
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
        workspace_id = str(payload.get("workspace_id", ""))
        spec = self.registry.get(workspace_id)
        profile = str(payload.get("profile", ""))
        if profile == "repository-change-v1":
            observed = self._git(workspace_id).status()
            current_head = observed["head"]
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
                ensure_relative_path(path)
            git = self._git(workspace_id)
            for path in payload.get("authoritative_paths", []):
                if not isinstance(path, str):
                    raise ContractError("authoritative_paths must contain strings")
                resolved = resolve_safe_path(spec.root, path, must_exist=True)
                if not resolved.is_file():
                    raise ContractError(
                        f"authoritative path must resolve to an existing file: {path}"
                    )
                if not git.is_tracked(path):
                    raise ContractError(
                        f"authoritative path must be tracked by the bound repository snapshot: {path}"
                    )
        result = self.contracts.put(payload)
        self.audit.append(
            action="create_contract",
            workspace_id=result["workspace_id"],
            outcome="PASS",
            details={
                "contract_id": result["contract_id"],
                "profile": result["profile"],
                "readiness": result["readiness"]["state"],
            },
        )
        return result

    def get_contract(self, contract_id: str) -> dict[str, Any]:
        result = self.contracts.get(contract_id)
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
