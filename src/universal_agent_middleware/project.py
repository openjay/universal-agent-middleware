"""Project-level reality model for UAM v0.3.2.

A Project is a logical product/repository identity that may have multiple
WorkspaceInstances — each representing a concrete checkout, worktree, or
carrier with a specific role and lifecycle state.

Backward-compatible: existing flat workspace registries without project_id
still work (workspace_id becomes the implicit project).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import WorkspaceError
from .git_readonly import ReadOnlyGit
from .workspace import WorkspaceRegistry

_INSTANCE_ROLES = frozenset({
    "canonical-main",
    "candidate",
    "review-carrier",
    "development",
    "runtime",
    "unspecified",
})

_LIFECYCLE_STATES = frozenset({
    "active",
    "landed",
    "stale",
    "superseded",
    "historical",
})

_COVERAGE_STATES = frozenset({
    "observed",
    "not_observed",
    "not_registered",
    "not_applicable",
    "discovered_not_authorized",
    "externally_verified",
})


@dataclass(frozen=True)
class WorkspaceInstance:
    workspace_id: str
    project_id: str
    role: str
    root: str
    label: str = ""
    lifecycle: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "role": self.role,
            "lifecycle": self.lifecycle,
            "label": self.label,
        }


@dataclass
class ProjectSpec:
    project_id: str
    repository_identity: str
    instances: list[WorkspaceInstance] = field(default_factory=list)
    discovery: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "repository_identity": self.repository_identity,
            "instances": [i.to_dict() for i in self.instances],
            "discovery": self.discovery,
        }


class ProjectRegistry:
    """Builds project-level view on top of the flat WorkspaceRegistry.

    Each workspace entry may optionally include:
      - project_id: groups multiple entries into one project
      - role: structural function (canonical-main, candidate, review-carrier)
      - lifecycle: temporal state (active, landed, stale, superseded, historical)
      - repository_identity: org/repo slug for matching worktrees

    If project_id is absent, workspace_id is used as the implicit project.
    """

    def __init__(self, workspace_registry: WorkspaceRegistry, registry_path: str | Path):
        self._ws_registry = workspace_registry
        self._registry_path = Path(registry_path)
        self._projects: dict[str, ProjectSpec] = {}
        self._observation_profiles: dict[str, dict[str, Any]] = {}
        self._build()
        self._load_observation_profiles()

    def _build(self) -> None:
        try:
            raw = json.loads(self._registry_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            raw = {"workspaces": []}

        for ws_raw in raw.get("workspaces", []):
            ws_id = ws_raw.get("workspace_id", "")
            project_id = ws_raw.get("project_id", ws_id)
            role = ws_raw.get("role", "unspecified")
            lifecycle = ws_raw.get("lifecycle", "active")
            repo_identity = ws_raw.get("repository_identity", "")

            # Backward compat: map old "active-candidate" to role=candidate, lifecycle=active
            if role == "active-candidate":
                role = "candidate"
                lifecycle = ws_raw.get("lifecycle", "active")

            if role not in _INSTANCE_ROLES:
                role = "unspecified"
            if lifecycle not in _LIFECYCLE_STATES:
                lifecycle = "active"

            instance = WorkspaceInstance(
                workspace_id=ws_id,
                project_id=project_id,
                role=role,
                root=ws_raw.get("root", ""),
                label=ws_raw.get("label", ""),
                lifecycle=lifecycle,
            )

            if project_id not in self._projects:
                self._projects[project_id] = ProjectSpec(
                    project_id=project_id,
                    repository_identity=repo_identity,
                    discovery=ws_raw.get("discovery", {}),
                )
            self._projects[project_id].instances.append(instance)

    def _load_observation_profiles(self) -> None:
        """Load project-specific observation profiles from config/."""
        profile_dir = self._registry_path.parent / "project-observation-profiles"
        if not profile_dir.is_dir():
            return
        for path in profile_dir.glob("*.json"):
            try:
                profile = json.loads(path.read_text(encoding="utf-8"))
                pid = profile.get("project_id", path.stem)
                self._observation_profiles[pid] = profile
            except (json.JSONDecodeError, OSError):
                continue

    def get_observation_profile(self, project_id: str) -> dict[str, Any] | None:
        return self._observation_profiles.get(project_id)

    def list_projects(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._projects.values()]

    def get_project(self, project_id: str) -> ProjectSpec:
        if project_id in self._projects:
            return self._projects[project_id]
        raise WorkspaceError(f"unknown project: {project_id}")

    def get_instance(self, workspace_id: str) -> WorkspaceInstance | None:
        for project in self._projects.values():
            for inst in project.instances:
                if inst.workspace_id == workspace_id:
                    return inst
        return None

    def discover_worktrees(self, project_id: str) -> list[dict[str, Any]]:
        """Discover git worktrees for a project's registered instances.

        Returns metadata about discovered worktrees. Does NOT auto-authorize
        content access to unregistered worktrees (discovery ≠ authority).
        """
        project = self.get_project(project_id)
        discovered: list[dict[str, Any]] = []
        seen_roots: set[str] = set()

        for instance in project.instances:
            try:
                git = ReadOnlyGit(instance.root)
                worktrees = git.worktree_list()
                for wt in worktrees:
                    wt_root = wt["path"]
                    if wt_root in seen_roots:
                        continue
                    seen_roots.add(wt_root)

                    registered_as = None
                    for inst in project.instances:
                        if str(Path(inst.root).resolve()) == str(Path(wt_root).resolve()):
                            registered_as = inst.workspace_id
                            break

                    discovered.append({
                        "path": wt_root,
                        "branch": wt.get("branch"),
                        "head": wt.get("head"),
                        "bare": wt.get("bare", False),
                        "registered_as": registered_as,
                        "content_authorized": registered_as is not None,
                    })
            except WorkspaceError:
                continue

        return discovered

    def project_reality_snapshot(self, project_id: str) -> dict[str, Any]:
        """Generate a multi-instance reality snapshot with coverage diagnostics."""
        project = self.get_project(project_id)
        observed_at = datetime.now(timezone.utc).isoformat()

        instances: list[dict[str, Any]] = []
        roles_observed: set[str] = set()
        has_active_candidate = False

        for instance in project.instances:
            try:
                git = ReadOnlyGit(instance.root)
                status = git.status()
                changed = [l for l in status["status"].splitlines() if l.strip()]

                instances.append({
                    "workspace_id": instance.workspace_id,
                    "role": instance.role,
                    "lifecycle": instance.lifecycle,
                    "head": status["head"],
                    "branch": status["branch"],
                    "head_state": status["head_state"],
                    "clean": len(changed) == 0,
                    "changed_count": len(changed),
                    "observable": True,
                })
                roles_observed.add(instance.role)
                if instance.role == "candidate" and instance.lifecycle == "active":
                    has_active_candidate = True
            except WorkspaceError as e:
                instances.append({
                    "workspace_id": instance.workspace_id,
                    "role": instance.role,
                    "lifecycle": instance.lifecycle,
                    "observable": False,
                    "error": str(e)[:200],
                })

        worktrees = self.discover_worktrees(project_id)
        unregistered_worktrees = [
            wt for wt in worktrees if not wt["content_authorized"]
        ]

        obs_profile = self.get_observation_profile(project_id)
        coverage = _compute_coverage(
            roles_observed, unregistered_worktrees,
            has_active_candidate, obs_profile,
        )

        max_worktrees_shown = 20
        worktrees_truncated = len(worktrees) > max_worktrees_shown

        return {
            "schema_version": "project-reality-snapshot-v2",
            "observed_at": observed_at,
            "project_id": project_id,
            "repository_identity": project.repository_identity,
            "instances": instances,
            "discovered_worktrees": worktrees[:max_worktrees_shown],
            "total_worktrees": len(worktrees),
            "unregistered_worktree_count": len(unregistered_worktrees),
            "worktrees_truncated": worktrees_truncated,
            "coverage": coverage,
        }


def _compute_coverage(
    roles_observed: set[str],
    unregistered_worktrees: list[dict[str, Any]],
    has_active_candidate: bool,
    observation_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute coverage diagnostics for a project.

    Coverage states:
      observed              — UAM can read live data from this surface
      not_observed          — no instance registered for this surface
      not_registered        — role exists logically but no instance is authorized
      not_applicable        — surface is not relevant in current project state
      discovered_not_authorized — worktree found but not registered
      externally_verified   — verified via external tool (e.g. GitHub API), not native UAM
    """

    surfaces: dict[str, str] = {}

    if "canonical-main" in roles_observed:
        surfaces["canonical_source"] = "observed"
    else:
        surfaces["canonical_source"] = "not_registered"

    if has_active_candidate:
        surfaces["active_candidate"] = "observed"
    elif "candidate" in roles_observed:
        surfaces["active_candidate"] = "observed"
    elif unregistered_worktrees:
        surfaces["active_candidate"] = "discovered_not_authorized"
    else:
        surfaces["active_candidate"] = "not_applicable"

    surfaces["forge_ci"] = "not_observed"
    surfaces["runtime"] = "not_observed"

    observed_or_na = sum(
        1 for v in surfaces.values() if v in ("observed", "not_applicable")
    )
    total = len(surfaces)

    if observed_or_na == total:
        status = "COMPLETE"
    elif all(v in ("not_observed", "not_registered") for v in surfaces.values()):
        status = "UNKNOWN"
    else:
        status = "PARTIAL"

    warnings: list[str] = []
    if unregistered_worktrees:
        warnings.append(
            f"UNREGISTERED_WORKTREES_FOUND: {len(unregistered_worktrees)} worktree(s) "
            "discovered but not authorized for content access"
        )
    if surfaces.get("forge_ci") == "not_observed":
        warnings.append("FORGE_CI_NOT_NATIVE: use external GitHub/forge readback for CI verification")

    observation_requirements = _observation_surface_requirements(observation_profile)

    return {
        "status": status,
        "surfaces": surfaces,
        "warnings": warnings,
        "observation_requirements": observation_requirements,
        "authority_evaluation": {
            "mode": "PROJECT_DEFINED",
            "evaluated_by_uam": False,
            "note": "UAM observes reality; project authority defines what PASS means",
        },
    }


def _observation_surface_requirements(
    observation_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return observation requirements either from project profile or defaults.

    These describe which truth surfaces must be at least 'observed' or
    'externally_verified' before a reasoning client can consider a given
    decision type. They are NOT authorization — project authority is separate.
    """
    if observation_profile and "requirements" in observation_profile:
        return observation_profile["requirements"]

    return {
        "candidate_consideration": {
            "surfaces": ["active_candidate", "canonical_source", "forge_ci"],
            "note": "Minimum observation for evaluating a candidate",
        },
        "merge_consideration": {
            "surfaces": ["active_candidate", "canonical_source", "forge_ci"],
            "note": "Observation needed before merge can be considered; does NOT grant authority",
        },
        "runtime_consideration": {
            "surfaces": ["canonical_source", "runtime"],
            "note": "Observation needed before runtime decisions",
        },
        "full_activation": {
            "surfaces": ["canonical_source", "active_candidate", "forge_ci", "runtime"],
            "note": "All surfaces required for major activation decisions",
        },
    }
