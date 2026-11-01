"""Project-level reality model for UAM v0.3.2.

A Project is a logical product/repository identity that may have multiple
WorkspaceInstances — each representing a concrete checkout, worktree, or
carrier with a specific role and lifecycle state.

Backward-compatible: existing flat workspace registries without project_id
still work (workspace_id becomes the implicit project).

The project view is never older than the registry being served (v0.6.1): every call first asks the
live ``WorkspaceRegistry`` for its current generation and rebuilds the view when that generation
changed. A project, an instance or a label that the registry no longer declares is therefore not
answered on the next call, in a process that has been running since before the revocation; a
registry that is missing serves no project and one that cannot be read refuses (fail closed).
What each instance may do is also not remembered: every Git question re-checks the instance's
``git.observe`` capability against the live registry (static) or the live resolver (derived) and
runs Git where that authority points now.
"""
from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import UAMError, WorkspaceError
from .git_readonly import ReadOnlyGit
from .models import KIND_GIT_REPOSITORY, RootIdentity
from .path_authority import PathPolicy
from .workspace import WorkspaceRegistry, open_verified_root

# Identifiers admitted from a RootScope rather than registered (static ids cannot contain ':').
DERIVED_WORKSPACE_PREFIX = "derived:"

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
    kind: str = KIND_GIT_REPOSITORY

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "role": self.role,
            "lifecycle": self.lifecycle,
            "label": self.label,
        }
        if self.kind != KIND_GIT_REPOSITORY:
            # Only non-Git kinds say so: existing Git-only payloads keep their exact shape.
            data["kind"] = self.kind
        return data


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


class RegistryGenerationChanged(WorkspaceError):
    """The registry was replaced while an answer was being assembled, so the answer was dropped.

    An answer is built from one registry generation or not at all: nothing assembled before the
    change (an instance a revocation just removed) may leave in the same response as something
    read after it. The caller asks again and gets the registry as it is now.
    """

    def __init__(self) -> None:
        super().__init__("the workspace registry changed while the answer was being assembled; ask again")


class GitObservationNotApplicable(WorkspaceError):
    """Git does not apply to this kind of workspace. That is not a failure of the workspace."""

    def __init__(self, kind: str):
        super().__init__(
            f"git observation is not applicable to {kind} workspaces; "
            "read it with uam_tree, uam_read_file or uam_search_text"
        )
        self.kind = kind


@dataclass(frozen=True)
class WorktreeDiscovery:
    """Worktrees found through the instances Git could be asked about, and the instances it could not.

    ``not_observed`` names registered Git instances that were not asked (no ``git.observe`` now,
    removed, unavailable) or whose repository could not be read, so ``worktrees`` is complete only
    when it is empty. A directory instance is not listed: it has no worktrees to find.
    """

    worktrees: list[dict[str, Any]]
    not_observed: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"complete": not self.not_observed, "not_observed_instances": sorted(self.not_observed)}


def _text(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _group_projects(declarations: list[dict[str, Any]]) -> dict[str, ProjectSpec]:
    """Projects and their instances from the declarations of one registry generation.

    A field of the wrong type is treated as absent (the registry validates names, not types), so
    one malformed declaration cannot raise out of a call and cannot make another project appear.
    """
    projects: dict[str, ProjectSpec] = {}
    for declared in declarations:
        ws_id = _text(declared.get("workspace_id"))
        project_id = _text(declared.get("project_id")) or ws_id
        role = _text(declared.get("role"), "unspecified")
        lifecycle = _text(declared.get("lifecycle"), "active")

        # Backward compat: map old "active-candidate" to role=candidate, lifecycle=active
        if role == "active-candidate":
            role = "candidate"

        if role not in _INSTANCE_ROLES:
            role = "unspecified"
        if lifecycle not in _LIFECYCLE_STATES:
            lifecycle = "active"

        instance = WorkspaceInstance(
            workspace_id=ws_id,
            project_id=project_id,
            role=role,
            root=_text(declared.get("root")),
            label=_text(declared.get("label")),
            lifecycle=lifecycle,
            kind=_text(declared.get("kind"), KIND_GIT_REPOSITORY),
        )

        if project_id not in projects:
            discovery = declared.get("discovery")
            projects[project_id] = ProjectSpec(
                project_id=project_id,
                repository_identity=_text(declared.get("repository_identity")),
                discovery=discovery if isinstance(discovery, dict) else {},
            )
        projects[project_id].instances.append(instance)
    return projects


class ProjectRegistry:
    """Builds project-level view on top of the flat WorkspaceRegistry.

    Each workspace entry may optionally include:
      - project_id: groups multiple entries into one project
      - role: structural function (canonical-main, candidate, review-carrier)
      - lifecycle: temporal state (active, landed, stale, superseded, historical)
      - repository_identity: org/repo slug for matching worktrees

    If project_id is absent, workspace_id is used as the implicit project.

    ``derived_git`` opens Git for a derived workspace id after the live resolver has verified its
    ``git.observe`` capability (the gateway passes its own). Without it a derived instance is never
    observed. Static instances never go through it: a registered identity is checked in the
    registry alone, so one that fails is not looked up again under the same name as a derived
    workspace.
    """

    def __init__(
        self,
        workspace_registry: WorkspaceRegistry,
        registry_path: str | Path,
        *,
        derived_git: Callable[[str], ReadOnlyGit] | None = None,
    ):
        self._ws_registry = workspace_registry
        self._derived_git = derived_git
        self._registry_path = Path(registry_path)
        self._projects: dict[str, ProjectSpec] = {}
        self._generation: str | None = None
        self._observation_profiles: dict[str, dict[str, Any]] = {}
        try:
            self._sync()
        except WorkspaceError:
            pass  # a registry that cannot be served is an empty view; the first call asks again and refuses
        self._load_observation_profiles()

    def _sync(self) -> str:
        """Make the project view the registry generation being served now, and return that generation.

        The live ``WorkspaceRegistry`` decides: it reloads when the registry file changed, serves
        nothing when the file is gone and raises when the file cannot be read. Whatever it raises,
        the earlier view is dropped before the error propagates, so no earlier identity can be
        answered from memory while the registry cannot vouch for it.
        """
        try:
            generation, declarations = self._ws_registry.declarations()
        except WorkspaceError:
            self._projects = {}
            self._generation = None
            raise
        if generation != self._generation:
            self._projects = _group_projects(declarations)
            self._generation = generation
        return generation

    def generation(self) -> str:
        """The registry generation the project view reflects now (use with ``require_generation``)."""
        return self._sync()

    def require_generation(self, generation: str) -> None:
        """Raise ``RegistryGenerationChanged`` unless the registry still is the generation ``generation``."""
        if self._sync() != generation:
            raise RegistryGenerationChanged()

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
        self._sync()
        return [p.to_dict() for p in self._projects.values()]

    def get_project(self, project_id: str) -> ProjectSpec:
        self._sync()
        if project_id in self._projects:
            return self._projects[project_id]
        raise WorkspaceError(f"unknown project: {project_id}")

    def get_instance(self, workspace_id: str) -> WorkspaceInstance | None:
        if workspace_id.startswith(DERIVED_WORKSPACE_PREFIX):
            return None  # admitted by a RootScope, never registered: the registry has nothing to say about it
        self._sync()
        for project in self._projects.values():
            for inst in project.instances:
                if inst.workspace_id == workspace_id:
                    return inst
        return None

    def _reverify_static_authority(self, workspace_id: str, bound_identity: RootIdentity) -> None:
        current = self._ws_registry.require_capability(workspace_id, "git.observe")
        if current.kind != KIND_GIT_REPOSITORY:
            raise GitObservationNotApplicable(current.kind)
        now = current.root_identity
        if now is None or (
            (now.dev, now.ino, now.root, now.policy_version, now.policy_generation)
            != (
                bound_identity.dev,
                bound_identity.ino,
                bound_identity.root,
                bound_identity.policy_version,
                bound_identity.policy_generation,
            )
        ):
            raise WorkspaceError("workspace root identity changed")

    def _observer(self, instance: WorkspaceInstance) -> ReadOnlyGit:
        """Git for one instance, under the capability it holds now.

        Nothing is trusted from when this object was built. A static instance must still be
        registered, available and granted ``git.observe`` by the registry as it is today, and Git
        runs in the root that registry returns today: a registration can be revoked, removed or
        rebound while the process runs. A derived instance is verified by the live resolver, so a
        revoked RootScope stops it. An identity that fails is never looked up under another name
        (no fallback to a same-named derived workspace), and a directory is never handed to Git.
        Raises ``WorkspaceError`` (``GitObservationNotApplicable`` for a directory) when Git must
        not be asked.
        """
        if instance.kind != KIND_GIT_REPOSITORY:
            raise GitObservationNotApplicable(instance.kind)
        if instance.workspace_id.startswith(DERIVED_WORKSPACE_PREFIX):
            if self._derived_git is None:
                raise WorkspaceError("no live authority is available to observe a derived workspace")
            git = self._derived_git(instance.workspace_id)
            if git.root_identity is None or git._authority_check is None:
                raise WorkspaceError("derived workspace git observer is missing bound root identity or live authority check")
            return git
        spec = self._ws_registry.require_capability(instance.workspace_id, "git.observe")
        if spec.kind != KIND_GIT_REPOSITORY:
            raise GitObservationNotApplicable(spec.kind)
        bound_identity = spec.root_identity
        if bound_identity is None:
            raise WorkspaceError("workspace root identity is not bound")
        return ReadOnlyGit(
            spec.root,
            path_policy=PathPolicy.unrestricted(),
            root_identity=bound_identity,
            authority_check=lambda: self._reverify_static_authority(instance.workspace_id, bound_identity),
            require_bound_identity=True,
        )

    def _registered_roots(self, project: ProjectSpec) -> dict[str, tuple[str, bool, RootIdentity]]:
        """Each root the registry serves now: which instance serves it, and whether it may read content.

        What an instance was registered for when this object was built says nothing about what it
        is registered for now, and a worktree counts as registered only while the registry still
        serves its root. A derived instance is admitted, not registered, so it vouches for nothing.
        """
        roots: dict[str, tuple[str, bool, RootIdentity]] = {}
        for instance in project.instances:
            if instance.workspace_id.startswith(DERIVED_WORKSPACE_PREFIX):
                continue
            try:
                spec = self._ws_registry.get(instance.workspace_id)
            except WorkspaceError:
                continue  # removed or unavailable: it authorizes nothing now
            if spec.root_identity is None:
                continue
            try:
                fd, _ = open_verified_root(spec.root_identity)
                os.close(fd)
            except WorkspaceError:
                continue
            roots.setdefault(
                spec.root_identity.root,
                (spec.workspace_id, "filesystem.read" in spec.capabilities, spec.root_identity),
            )
        return roots

    def worktree_discovery(self, project_id: str) -> WorktreeDiscovery:
        """Discover git worktrees through a project's instances, and say which could not be asked.

        Returns metadata about discovered worktrees. Does NOT auto-authorize
        content access to unregistered worktrees (discovery ≠ authority).
        """
        generation = self.generation()
        project = self.get_project(project_id)
        registered = self._registered_roots(project)
        discovered: list[dict[str, Any]] = []
        not_observed: list[str] = []
        seen_roots: set[str] = set()

        for instance in project.instances:
            try:
                worktrees = self._observer(instance).worktree_list()
            except GitObservationNotApplicable:
                continue  # a directory has no worktrees, and must never be handed to Git
            except UAMError:
                not_observed.append(instance.workspace_id)
                continue
            for wt in worktrees:
                wt_root = wt["path"]
                if wt_root in seen_roots:
                    continue
                seen_roots.add(wt_root)

                registered_as: str | None = None
                may_read = False
                try:
                    wt_lstat = os.stat(wt_root, follow_symlinks=False)
                    wt_real = str(Path(os.path.realpath(wt_root))) if not stat.S_ISLNK(wt_lstat.st_mode) else ""
                except OSError:
                    wt_lstat = None
                    wt_real = ""
                if wt_lstat is not None and wt_real in registered:
                    cand_ws_id, cand_may_read, cand_identity = registered[wt_real]
                    if (wt_lstat.st_dev, wt_lstat.st_ino) == (cand_identity.dev, cand_identity.ino):
                        try:
                            fd, _ = open_verified_root(cand_identity)
                            os.close(fd)
                        except WorkspaceError:
                            pass
                        else:
                            registered_as = cand_ws_id
                            may_read = cand_may_read
                discovered.append({
                    "path": wt_root,
                    "branch": wt.get("branch"),
                    "head": wt.get("head"),
                    "bare": wt.get("bare", False),
                    "registered_as": registered_as,
                    "content_authorized": registered_as is not None and may_read,
                })

        self.require_generation(generation)
        return WorktreeDiscovery(discovered, not_observed)

    def discover_worktrees(self, project_id: str) -> list[dict[str, Any]]:
        """The worktrees ``worktree_discovery`` found (it also says which instances it could not ask)."""
        return self.worktree_discovery(project_id).worktrees

    def project_reality_snapshot(self, project_id: str) -> dict[str, Any]:
        """Generate a multi-instance reality snapshot with coverage diagnostics.

        The snapshot is built from one registry generation: if the registry is replaced while the
        instances are observed, the snapshot is dropped (``RegistryGenerationChanged``) rather than
        returned with an instance that the new registry no longer declares.
        """
        generation = self.generation()
        project = self.get_project(project_id)
        observed_at = datetime.now(timezone.utc).isoformat()

        instances: list[dict[str, Any]] = []
        roles_observed: set[str] = set()
        has_active_candidate = False

        for instance in project.instances:
            try:
                status = self._observer(instance).status()
            except GitObservationNotApplicable as e:
                # Not a failure of the directory: Git observation simply does not apply.
                instances.append({
                    "workspace_id": instance.workspace_id,
                    "role": instance.role,
                    "lifecycle": instance.lifecycle,
                    "kind": e.kind,
                    "observable": False,
                    "error": str(e),
                })
                continue
            except UAMError as e:
                # This instance only: it stays unobserved, never clean and never "without history".
                instances.append({
                    "workspace_id": instance.workspace_id,
                    "role": instance.role,
                    "lifecycle": instance.lifecycle,
                    "observable": False,
                    "error": str(e)[:200],
                })
                continue
            changed = [l for l in status["status"].splitlines() if l.strip()]
            instances.append({
                "workspace_id": instance.workspace_id,
                "role": instance.role,
                "lifecycle": instance.lifecycle,
                "head": status["head"],
                "branch": status["branch"],
                "head_state": status["head_state"],
                "history_available": status["history_available"],
                "clean": len(changed) == 0,
                "changed_count": len(changed),
                "observable": True,
            })
            roles_observed.add(instance.role)
            if instance.role == "candidate" and instance.lifecycle == "active":
                has_active_candidate = True

        discovery = self.worktree_discovery(project_id)
        worktrees = discovery.worktrees
        unregistered_worktrees = [
            wt for wt in worktrees if not wt["content_authorized"]
        ]

        obs_profile = self.get_observation_profile(project_id)
        coverage = _compute_coverage(
            roles_observed, unregistered_worktrees,
            has_active_candidate, obs_profile,
            unobservable_instances=[i for i in instances if not i["observable"]],
        )

        max_worktrees_shown = 20
        worktrees_truncated = len(worktrees) > max_worktrees_shown

        self.require_generation(generation)
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
            "worktree_discovery": discovery.to_dict(),
            "coverage": coverage,
        }


def _compute_coverage(
    roles_observed: set[str],
    unregistered_worktrees: list[dict[str, Any]],
    has_active_candidate: bool,
    observation_profile: dict[str, Any] | None,
    *,
    unobservable_instances: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute coverage diagnostics for a project.

    Coverage states:
      observed              — UAM can read live data from this surface
      not_observed          — no information available for this surface (including a
                              registered instance whose workspace cannot be read now)
      not_registered        — role exists logically but no instance is authorized
      not_applicable        — surface is not relevant in current project state
      discovered_not_authorized — worktree found but not registered
      externally_verified   — verified via external tool (e.g. GitHub API), not native UAM

    A registered instance that cannot be observed never counts as absent or not
    applicable: its surface stays ``not_observed`` so coverage cannot reach COMPLETE.
    """

    surfaces: dict[str, str] = {}
    unobservable = unobservable_instances or []
    unobservable_roles = {item.get("role") for item in unobservable}

    if "canonical-main" in roles_observed:
        surfaces["canonical_source"] = "observed"
    elif "canonical-main" in unobservable_roles:
        surfaces["canonical_source"] = "not_observed"
    else:
        surfaces["canonical_source"] = "not_registered"

    if has_active_candidate:
        surfaces["active_candidate"] = "observed"
    elif "candidate" in roles_observed:
        surfaces["active_candidate"] = "observed"
    elif "candidate" in unobservable_roles:
        surfaces["active_candidate"] = "not_observed"
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
    if unobservable:
        names = ", ".join(sorted(str(item.get("workspace_id")) for item in unobservable))
        warnings.append(
            f"UNOBSERVABLE_INSTANCES: {len(unobservable)} registered instance(s) "
            f"could not be observed ({names})"
        )
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
