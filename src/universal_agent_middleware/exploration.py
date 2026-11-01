"""Autonomous Exploration layer for UAM (Slice C).

Provides:
- CoverageGapV1: identifies referenced-but-unobserved truth surfaces
- RealityGraphV1: lightweight project/repo/instance relationship graph
- Intent-driven ranking: prioritizes projects relevant to a stated goal
- Selective hydration planning: recommends what to read next
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .descriptor_io import OpenDenied, PathChangedError, open_beneath, open_root, read_bounded
from .discovery import DiscoveryEngine
from .errors import PathPolicyError, UAMError, WorkspaceError
from .path_authority import PathPolicy
from .root_scope import RootScopeRegistry


@dataclass
class CoverageGap:
    project_id: str
    surface: str
    state: str
    evidence_refs: list[str] = field(default_factory=list)
    suggested_scope: str = ""
    authority_state: str = "unknown"
    # One ``{"file", "status", "detail"}`` per fixed file that could not be observed (``reference_check_incomplete``).
    observations: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "project_id": self.project_id,
            "surface": self.surface,
            "state": self.state,
            "evidence_refs": self.evidence_refs,
            "suggested_scope": self.suggested_scope,
            "authority_state": self.authority_state,
        }
        if self.observations:
            body["observations"] = self.observations
        return body


@dataclass
class GraphNode:
    node_type: str
    node_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.node_type, "id": self.node_id, **self.attributes}


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"source": self.source, "target": self.target, "relation": self.relation}
        if self.evidence:
            d["evidence"] = self.evidence
        return d


class RealityGraphV1:
    """Lightweight project identity/instance topology graph.

    Nodes: Project, WorkspaceInstance, Remote
    Edges: instance_of, has_remote, same_remote

    Only represents relationships for which the system has actual evidence.
    Does not infer semantic dependencies between projects.
    """

    def __init__(self) -> None:
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []

    def build_from_inventory(self, inventory: dict[str, Any]) -> None:
        """Populate graph from discovery inventory."""
        seen_remotes: dict[str, str] = {}

        for project in inventory.get("projects", []):
            pid = project["project_id"]
            self.nodes.append(GraphNode(
                node_type="Project", node_id=pid,
                attributes={"status": project["status"], "languages": project.get("languages", [])},
            ))

            remote = project.get("remote_identity", "")
            if remote:
                if remote not in seen_remotes:
                    seen_remotes[remote] = f"remote:{remote}"
                    self.nodes.append(GraphNode(node_type="Remote", node_id=seen_remotes[remote]))
                self.edges.append(GraphEdge(
                    source=pid, target=seen_remotes[remote], relation="has_remote",
                    evidence=remote,
                ))

            for idx, inst in enumerate(project.get("instances", [])):
                inst_id = f"{pid}:inst:{idx}"
                self.nodes.append(GraphNode(
                    node_type="WorkspaceInstance", node_id=inst_id,
                    attributes={"path": inst.get("path", ""), "is_worktree": inst.get("is_worktree", False)},
                ))
                self.edges.append(GraphEdge(source=inst_id, target=pid, relation="instance_of"))

        self._detect_shared_remotes(seen_remotes)

    def _detect_shared_remotes(self, seen_remotes: dict[str, str]) -> None:
        """Find projects sharing the same remote (same_remote edges)."""
        remote_to_projects: dict[str, list[str]] = {}
        for edge in self.edges:
            if edge.relation == "has_remote":
                remote_to_projects.setdefault(edge.target, []).append(edge.source)

        for remote_id, projects in remote_to_projects.items():
            if len(projects) > 1:
                for i in range(len(projects)):
                    for j in range(i + 1, len(projects)):
                        self.edges.append(GraphEdge(
                            source=projects[i], target=projects[j],
                            relation="same_remote", evidence=remote_id,
                        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "reality-graph-v1",
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


_RUNTIME_INDICATORS = frozenset({
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "Procfile", "fly.toml", "render.yaml", "railway.json",
    "vercel.json", "netlify.toml", "wrangler.toml",
})

_FORGE_INDICATORS = frozenset({
    ".github", ".gitlab-ci.yml", ".circleci",
    "Jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml",
})

# Read for runtime hints, in the order the hints are reported. ``.env.example`` is deliberately not here: it is a
# dotenv-family name (refused by the sensitive-name policy), and a "template" is where a real value is most often
# pasted. Compatibility impact: a hint that only ``.env.example`` carried no longer raises a runtime coverage gap.
_RUNTIME_REF_FILES = (
    "pyproject.toml", "package.json", "Makefile",
    "docker-compose.yml", "docker-compose.yaml",
    "README.md",
)
_RUNTIME_REF_MAX_BYTES = 256_000

_RUNTIME_REF_PATTERNS = [
    re.compile(r"~/\.\w+"),
    re.compile(r"\$HOME/\.\w+"),
    re.compile(r"LaunchAgent|launchd|launchctl", re.IGNORECASE),
    re.compile(r"systemd|systemctl", re.IGNORECASE),
    re.compile(r"localhost:\d+"),
    re.compile(r"docker\s+(run|compose|build)", re.IGNORECASE),
    re.compile(r"(OPENAI|ANTHROPIC|OPENROUTER)_API_KEY"),
]

# What happened when UAM tried to look at something. The statuses are different facts and are never merged:
#   DENIED            policy, scope authority or a protected name refused the read; nothing was read
#   UNREADABLE        the operating system refused UAM's account, or the read failed
#   BUDGET_EXCEEDED   the object is larger than the read budget; it was not read
#   NOT_OBSERVED      it could not be observed (it changed under the walk, it is not a regular file, no root to open)
#   OBSERVED_NO_FINDINGS / OBSERVED_WITH_FINDINGS   it WAS observed (an absent optional file is an observation too)
# "Could not look" must never read as "nothing there": only the OBSERVED_* statuses say anything about content.
DENIED = "DENIED"
UNREADABLE = "UNREADABLE"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
NOT_OBSERVED = "NOT_OBSERVED"
OBSERVED_NO_FINDINGS = "OBSERVED_NO_FINDINGS"
OBSERVED_WITH_FINDINGS = "OBSERVED_WITH_FINDINGS"
AUTHORIZED = "AUTHORIZED"  # the authority state of a surface (``source_content``): the scope grants what is needed
_UNRESOLVED = frozenset({DENIED, UNREADABLE, BUDGET_EXCEEDED, NOT_OBSERVED})

REFERENCE_CHECK_INCOMPLETE = "reference_check_incomplete"
CONTENT_READ_NOT_GRANTED = "content_read_not_granted"


@dataclass(frozen=True)
class FileObservation:
    name: str
    status: str
    detail: str = ""  # a fixed short reason (never an OS message, never content)
    text: str | None = None
    size: int | None = None


@dataclass(frozen=True)
class RuntimeRefScan:
    refs: list[str]
    observations: list[FileObservation]  # one per fixed file, in the fixed order; the text is not kept


def _authority_state(unresolved: list[FileObservation]) -> str:
    """The ``authority_state`` of an incomplete reference check: one reason if they agree, else ``not_observed``."""
    reasons = {
        DENIED: "denied_by_policy_or_scope",
        UNREADABLE: "os_refused_or_failed",
        BUDGET_EXCEEDED: "over_read_budget",
    }
    states = {reasons.get(item.status, "not_observed") for item in unresolved}
    return states.pop() if len(states) == 1 else "not_observed"


def _claim_evidence(gaps: list[CoverageGap]) -> dict[str, Any]:
    """What each claim of a coverage assessment rests on, derived only from the gaps that were found.

    ``local_source``       could the project directory be scanned at all
    ``source_content``     does the scope grant reading content (an authority state: ``AUTHORIZED`` or ``DENIED``)
    ``runtime_references`` what is known about runtime references in the fixed project-root files: one of the statuses
                           above, the unresolved files (``unchecked``) and whether anything was found. A claim that
                           has an unresolved file is never ``OBSERVED_NO_FINDINGS``: it is that file's status when
                           they agree, ``NOT_OBSERVED`` when they differ.
    """
    local = [gap for gap in gaps if gap.surface == "local_source"]
    if local:
        scanned = UNREADABLE if any(gap.state == "scan_error" for gap in local) else NOT_OBSERVED
        return {
            "local_source": {"status": scanned},
            "source_content": {"status": NOT_OBSERVED},
            "runtime_references": {"status": NOT_OBSERVED, "findings": False, "unchecked": []},
        }
    content_denied = any(gap.surface == "source_content" for gap in gaps)
    findings = any(gap.surface == "runtime" and gap.state == "referenced_not_observed" for gap in gaps)
    unchecked = [
        dict(observation)
        for gap in gaps if gap.surface == "runtime" and gap.state == REFERENCE_CHECK_INCOMPLETE
        for observation in gap.observations
    ]
    statuses = {item["status"] for item in unchecked}
    if unchecked:
        status = statuses.pop() if len(statuses) == 1 else NOT_OBSERVED
    else:
        status = OBSERVED_WITH_FINDINGS if findings else OBSERVED_NO_FINDINGS
    return {
        "local_source": {"status": OBSERVED_NO_FINDINGS},
        "source_content": {"status": DENIED if content_denied else AUTHORIZED},
        "runtime_references": {"status": status, "findings": findings, "unchecked": unchecked},
    }


class ExplorationEngine:
    """AI-native exploration on top of deterministic discovery."""

    def __init__(self, discovery: DiscoveryEngine, scope_registry: RootScopeRegistry):
        self._discovery = discovery
        self._scopes = scope_registry

    def explain_coverage(self, scope_id: str, project_id: str) -> dict[str, Any]:
        """Explain coverage gaps for a specific project."""
        inventory = self._discovery.scope_inventory(scope_id)
        if "error" in inventory:
            return inventory

        project = None
        for p in inventory.get("projects", []):
            if p["project_id"] == project_id:
                project = p
                break

        if not project:
            return {"error": f"project {project_id} not found in scope {scope_id}"}

        gaps = self._find_coverage_gaps(project, scope_id)
        observed_at = datetime.now(timezone.utc).isoformat()

        return {
            "schema_version": "coverage-explanation-v1",
            "observed_at": observed_at,
            "project_id": project_id,
            "scope_id": scope_id,
            "coverage_gaps": [g.to_dict() for g in gaps],
            "total_gaps": len(gaps),
            "assessment": self._assess_coverage(project, gaps),
        }

    def what_am_i_missing(self, scope_id: str) -> dict[str, Any]:
        """Answer: what truth surfaces are missing across active projects?"""
        inventory = self._discovery.scope_inventory(scope_id)
        if "error" in inventory:
            return inventory

        all_projects = inventory.get("projects", [])
        all_gaps: list[dict[str, Any]] = []
        active_projects = [
            p for p in all_projects
            if p["status"] in ("active", "recent")
        ]

        for project in active_projects:
            gaps = self._find_coverage_gaps(project, scope_id)
            for gap in gaps:
                all_gaps.append(gap.to_dict())

        activity_unknown = sum(
            1 for p in all_projects
            if not p.get("last_activity")
        )
        dormant_or_archived = sum(
            1 for p in all_projects
            if p["status"] in ("dormant", "archived")
        )

        scope_authority = self._resolve_scope_surfaces(scope_id)

        observed_at = datetime.now(timezone.utc).isoformat()
        result: dict[str, Any] = {
            "schema_version": "missing-reality-v2",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "active_projects_analyzed": len(active_projects),
            "inventory_total": len(all_projects),
            "activity_unknown_count": activity_unknown,
            "dormant_or_archived_excluded": dormant_or_archived,
            "total_gaps": len(all_gaps),
            "gaps": all_gaps,
            "scope_surfaces": scope_authority,
            "scope_escalation_suggestions": self._suggest_escalations(all_gaps),
        }

        if not active_projects:
            result["epistemic_warning"] = (
                f"No active/recent projects found among {len(all_projects)} "
                f"inventory entries ({activity_unknown} with unknown activity). "
                "Absence of activity evidence does not prove inactivity; "
                "git enrichment or broader observation may be required."
            )

        return result

    def explore(
        self,
        scope_id: str,
        intent: str = "",
        max_projects: int = 10,
        max_files: int = 50,
        max_bytes: int = 500_000,
    ) -> dict[str, Any]:
        """Intent-driven exploration: rank, relate, plan retrieval.

        Returns ranked projects, relationships, retrieval plan, and coverage gaps
        bounded by resource limits.
        """
        inventory = self._discovery.scope_inventory(scope_id)
        if "error" in inventory:
            return inventory

        projects = inventory.get("projects", [])

        if intent:
            ranked = sorted(
                projects,
                key=lambda p: self._intent_relevance(p, intent),
                reverse=True,
            )[:max_projects]
        else:
            ranked = sorted(
                projects,
                key=lambda p: self._relevance_score(p),
                reverse=True,
            )[:max_projects]

        graph = RealityGraphV1()
        graph.build_from_inventory({"projects": ranked})

        gaps: list[dict[str, Any]] = []
        for p in ranked:
            for gap in self._find_coverage_gaps(p, scope_id):
                gaps.append(gap.to_dict())

        retrieval_plan = self._build_retrieval_plan(
            ranked, max_files, max_bytes,
            scope_id=scope_id,
            scope_root=inventory.get("scope_root", ""),
        )

        observed_at = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": "exploration-result-v1",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "intent": intent or "(no intent — activity-based)",
            "ranked_projects": [
                {
                    "project_id": p["project_id"],
                    "status": p["status"],
                    "relevance_score": (
                        self._intent_relevance(p, intent) if intent
                        else self._relevance_score(p)
                    ),
                    "languages": p.get("languages", []),
                    "instance_count": p.get("instance_count", 1),
                }
                for p in ranked
            ],
            "relationships": graph.to_dict(),
            "coverage_gaps": gaps,
            "retrieval_plan": retrieval_plan,
        }

    def _intent_relevance(self, project: dict[str, Any], intent: str) -> float:
        """Score project relevance to a stated intent (keyword-based)."""
        score = self._relevance_score(project)

        intent_lower = intent.lower()
        tokens = intent_lower.split()

        pid = project.get("project_id", "").lower()
        for token in tokens:
            if token in pid:
                score += 50

        for lang in project.get("languages", []):
            if lang.lower() in intent_lower:
                score += 30

        remote = project.get("remote_identity", "").lower()
        for token in tokens:
            if token in remote:
                score += 20

        return score

    def _build_retrieval_plan(
        self, ranked_projects: list[dict[str, Any]], max_files: int, max_bytes: int,
        scope_id: str = "", scope_root: str = "",
    ) -> dict[str, Any]:
        """Generate a bounded retrieval plan for selective hydration.

        A file is planned only if the Reader could serve it: each candidate is opened under the Reader's rules
        (``_observe_root_file``) and sized by ``fstat`` of the descriptor that was checked. A link to a protected name,
        an unreadable file or a pipe is NOT planned and its size contributes nothing: sizing by ``stat`` through a
        link would hand the size of the target to ``total_bytes_estimate``. What is left out is listed, with its status.
        """
        plan_items: list[dict[str, Any]] = []
        unplanned: list[dict[str, str]] = []
        total_files = 0
        total_bytes = 0

        priority_files = ["README.md", "pyproject.toml", "package.json", "Cargo.toml", "go.mod"]

        for project in ranked_projects:
            if total_files >= max_files:
                break

            canonical = project.get("canonical_path", "")
            if not canonical:
                continue
            path = Path(canonical)
            if not path.is_dir():
                continue

            project_targets: list[str] = []
            try:
                root_real = path.resolve()
                root_fd = open_root(root_real)
            except (OSError, UAMError):
                unplanned.append({"project_id": project["project_id"], "file": ".", "status": NOT_OBSERVED})
                continue
            try:
                for pf in priority_files:
                    observation = self._observe_root_file(root_fd, root_real, pf, read_budget=None)
                    if observation.size is None:
                        if observation.status in _UNRESOLVED:
                            unplanned.append(
                                {"project_id": project["project_id"], "file": pf, "status": observation.status})
                        continue  # absent: there is nothing to plan
                    if total_bytes + observation.size <= max_bytes and total_files < max_files:
                        project_targets.append(pf)
                        total_bytes += observation.size
                        total_files += 1
                    else:
                        unplanned.append({"project_id": project["project_id"], "file": pf, "status": BUDGET_EXCEEDED})
            finally:
                os.close(root_fd)

            if project_targets:
                if scope_root and scope_id:
                    try:
                        rel = str(Path(canonical).relative_to(scope_root))
                        ws_id = f"derived:{scope_id}:{rel}"
                    except ValueError:
                        ws_id = f"derived:{scope_id}:{Path(canonical).name}"
                else:
                    ws_id = f"derived:unknown:{Path(canonical).name}"
                plan_items.append({
                    "project_id": project["project_id"],
                    "workspace_id": ws_id,
                    "files": project_targets,
                })

        return {
            "total_files": total_files,
            "total_bytes_estimate": total_bytes,
            "budget_remaining_files": max_files - total_files,
            "budget_remaining_bytes": max_bytes - total_bytes,
            "items": plan_items,
            "unplanned": unplanned,
        }

    def _find_coverage_gaps(self, project: dict[str, Any], scope_id: str) -> list[CoverageGap]:
        """Identify referenced-but-unobserved surfaces for a project."""
        gaps: list[CoverageGap] = []
        canonical_path = project.get("canonical_path", "")
        if not canonical_path:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="local_source",
                state="no_canonical_path",
                authority_state="unassessable",
            ))
            return gaps

        path = Path(canonical_path)
        if not path.is_dir():
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="local_source",
                state="canonical_path_missing",
                evidence_refs=[canonical_path],
                authority_state="unassessable",
            ))
            return gaps

        has_forge = False
        has_runtime = False
        forge_refs: list[str] = []
        runtime_refs: list[str] = []
        scan_error = False

        try:
            for entry in path.iterdir():
                name = entry.name
                if name in _FORGE_INDICATORS:  # by name only: no stat of an entry, no link followed
                    has_forge = True
                    forge_refs.append(name)
                if name in _RUNTIME_INDICATORS:
                    has_runtime = True
                    runtime_refs.append(name)
        except (PermissionError, OSError):
            scan_error = True

        if scan_error:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="local_source",
                state="scan_error",
                authority_state="permission_denied_or_io_error",
            ))

        scan = self._scan_runtime_refs(path)
        code_runtime_refs = scan.refs
        if code_runtime_refs and not has_runtime:
            has_runtime = True
            runtime_refs.extend(code_runtime_refs)

        if has_forge:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="forge_ci",
                state="referenced_not_observed",
                evidence_refs=forge_refs,
                authority_state="requires_forge_adapter",
            ))

        if has_runtime:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="runtime",
                state="referenced_not_observed",
                evidence_refs=runtime_refs,
                authority_state="requires_runtime_adapter",
            ))

        if project.get("remote_identity") and not has_forge:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="forge_ci",
                state="likely_exists_not_observed",
                evidence_refs=[f"remote: {project['remote_identity']}"],
                authority_state="requires_forge_adapter",
            ))

        if not self._scopes.can_read(path):
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="source_content",
                state=CONTENT_READ_NOT_GRANTED,
                authority_state="scope_denies_content_read",
            ))

        unresolved = [item for item in scan.observations if item.status in _UNRESOLVED]
        if unresolved:
            gaps.append(CoverageGap(
                project_id=project["project_id"],
                surface="runtime",
                state=REFERENCE_CHECK_INCOMPLETE,
                evidence_refs=[f"{item.name}: {item.status}" for item in unresolved],
                authority_state=_authority_state(unresolved),
                observations=[
                    {"file": item.name, "status": item.status, "detail": item.detail} for item in unresolved
                ],
            ))

        return gaps

    def _detect_code_runtime_refs(self, project_root: Path) -> list[str]:
        """The runtime references found in the fixed project-root files (see ``_scan_runtime_refs``)."""
        return self._scan_runtime_refs(project_root).refs

    def _scan_runtime_refs(self, project_root: Path) -> RuntimeRefScan:
        """Bounded root-level config/doc scan for runtime dependency references, with what happened to each file.

        Only examines a fixed set of files at project root (pyproject.toml,
        package.json, Makefile, docker-compose.yml/yaml, README.md). Does NOT
        recursively scan src/, scripts/, config/, etc. Presence of a match
        indicates "declared or likely dependency", not "confirmed running".

        The hint is derived from file content, so each file is read under the same rules as the workspace Reader:
        opened component by component below the project root without following a link out of it, a denied name
        (including one that a link points at) is never opened, the RootScope that governs the file as it really is
        must grant ``content_read``, and the bytes come from the descriptor that was checked. A file that is refused
        or unreadable contributes no hint, and the scan SAYS SO: every fixed file ends as one observation, so "no
        hint" can be told from "could not look" (only the former is ``OBSERVED_NO_FINDINGS``).
        """
        try:
            root_real = project_root.resolve()
            root_fd = open_root(root_real)
        except (OSError, UAMError):
            return RuntimeRefScan(
                [], [FileObservation(name, NOT_OBSERVED, "project_root_not_opened") for name in _RUNTIME_REF_FILES],
            )
        refs: list[str] = []
        observations: list[FileObservation] = []
        try:
            for filename in _RUNTIME_REF_FILES:
                observation = self._observe_root_file(root_fd, root_real, filename, read_budget=_RUNTIME_REF_MAX_BYTES)
                found = False
                if observation.text is not None:
                    for pattern in _RUNTIME_REF_PATTERNS:
                        matches = pattern.findall(observation.text)
                        if matches:
                            sample = matches[0] if isinstance(matches[0], str) else matches[0][0]
                            refs.append(f"{filename}: {sample}")
                            found = True
                            break
                status = OBSERVED_WITH_FINDINGS if found else observation.status
                observations.append(FileObservation(filename, status, observation.detail))
        finally:
            os.close(root_fd)
        return RuntimeRefScan(refs, observations)

    def _observe_root_file(
        self, root_fd: int, root_real: Path, filename: str, *, read_budget: int | None
    ) -> FileObservation:
        """One fixed project-root file under the Reader's rules, judged by the descriptor that was opened.

        ``read_budget`` is the most that may be read; ``None`` asks only for the size (``fstat``) and reads nothing.
        The result says what happened and is never merely "nothing" (see the status vocabulary above). An absent file
        is an observation (``OBSERVED_NO_FINDINGS``, detail ``absent``, no size): there is nothing to find.
        """
        if not self._scopes.can_read(root_real / filename):  # as written: a scope that does not grant reading never sees an open
            return FileObservation(filename, DENIED, "scope")
        try:
            with open_beneath(root_fd, root_real, (filename,), kind="file") as opened:
                # And again for where the name really leads (a link may point into a narrower scope).
                if not self._scopes.can_read(root_real.joinpath(*opened.parts)):
                    return FileObservation(filename, DENIED, "scope")
                try:
                    # Same rule as the Reader: a file with other names may be a denied file under an innocent name.
                    PathPolicy.beneath(self._scopes, root_real).require_single_object_name("read", opened.info)
                except PathPolicyError:
                    return FileObservation(filename, DENIED, "hard_link")
                if read_budget is None:
                    return FileObservation(filename, OBSERVED_NO_FINDINGS, "size_only", size=opened.info.st_size)
                data = read_bounded(opened.fd, read_budget)
        except FileNotFoundError:
            return FileObservation(filename, OBSERVED_NO_FINDINGS, "absent")
        except OpenDenied:  # before the others: it is both a WorkspaceError and a PermissionError
            return FileObservation(filename, UNREADABLE, "os_refused")
        except PathChangedError:
            return FileObservation(filename, NOT_OBSERVED, "changed_during_observation")
        except PathPolicyError:  # a protected name, a link out of the project, a link loop
            return FileObservation(filename, DENIED, "path_policy")
        except WorkspaceError:  # not a regular file (a pipe, a device, a directory): never opened
            return FileObservation(filename, NOT_OBSERVED, "not_a_regular_file")
        except OSError:
            return FileObservation(filename, UNREADABLE, "io_error")
        if data is None:
            return FileObservation(filename, BUDGET_EXCEEDED, "over_budget")
        return FileObservation(filename, OBSERVED_NO_FINDINGS, "read", text=data.decode("utf-8", errors="replace"))

    def _assess_coverage(self, project: dict[str, Any], gaps: list[CoverageGap]) -> dict[str, Any]:
        """Provide a multi-dimensional coverage assessment.

        Verdict vocabulary:
        - SOURCE_OBSERVED: local repo source is fully readable; runtime/forge unobserved
        - PARTIAL: at least one gap in observed surfaces
        - UNASSESSABLE: cannot determine (e.g. no canonical path, scan error)
        """
        structurally_unobserved = ["forge_ci", "runtime", "process", "service_api"]
        gap_surfaces = [g.surface for g in gaps]

        local_source_impaired = "local_source" in gap_surfaces
        local_source_states = [g.state for g in gaps if g.surface == "local_source"]
        # An incomplete reference check scopes ONE claim (runtime references) to UNKNOWN for the files it names; it
        # does not by itself say the source is inaccessible, so it is not what decides the project's verdict.
        deciding = [
            g for g in gaps
            if g.surface != "local_source" and not (g.surface == "runtime" and g.state == REFERENCE_CHECK_INCOMPLETE)
        ]
        evidence = _claim_evidence(gaps)
        unchecked = evidence["runtime_references"]["unchecked"]
        content_denied = evidence["source_content"]["status"] == DENIED

        surfaces_ok: list[str] = []
        if not local_source_impaired:
            surfaces_ok.append("local_source")
        if project.get("instance_count", 0) > 1 and not local_source_impaired:
            surfaces_ok.append("worktrees")

        if local_source_impaired:
            verdict = "UNASSESSABLE"
            note = (
                f"Local source not assessable ({', '.join(local_source_states)}); "
                "remaining surfaces cannot be evaluated"
            )
        elif deciding:
            verdict = "PARTIAL"
            note = (
                f"Local source observable but {len(deciding)} gap(s) detected; "
                "forge/runtime/process surfaces remain structurally unobserved"
            )
            if content_denied:
                note += (
                    "; the scope does not grant content_read, so source content was not observed (DENIED) and "
                    "runtime references are UNKNOWN, not absent"
                )
        else:
            verdict = "SOURCE_OBSERVED"
            note = (
                "Local repo source accessible within the authorized scope. "
                "Forge CI, runtime config, process, and service surfaces are "
                "structurally unobserved — absence of gaps only covers "
                "filesystem-evidence-based detection."
            )
        if unchecked and not local_source_impaired and not content_denied:
            note += (
                f" {len(unchecked)} optional reference check(s) could not be observed "
                f"({', '.join(sorted({item['status'] for item in unchecked}))}): runtime references in "
                "them are UNKNOWN, not absent."
            )

        return {
            "observed": surfaces_ok,
            "missing": list(dict.fromkeys(s for s in gap_surfaces if s != "local_source")),
            "impaired": local_source_states if local_source_impaired else [],
            "structurally_unobserved": structurally_unobserved,
            "verdict": verdict,
            "note": note,
            "evidence": evidence,
        }

    def _relevance_score(self, project: dict[str, Any]) -> float:
        """Compute a relevance score for ranking."""
        score = 0.0
        status = project.get("status", "archived")
        match status:
            case "active":
                score += 100
            case "recent":
                score += 50
            case "dormant":
                score += 10
            case _:
                score += 0

        score += min(project.get("instance_count", 1), 10) * 5

        if project.get("languages"):
            score += 10

        return score

    def _suggest_escalations(self, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Suggest scope escalations based on gaps."""
        suggestions: list[dict[str, Any]] = []
        seen: set[str] = set()

        for gap in gaps:
            surface = gap["surface"]
            if surface in seen:
                continue
            seen.add(surface)

            if surface == "forge_ci":
                suggestions.append({
                    "surface": "forge_ci",
                    "action": "ForgeObservationAdapter needed",
                    "note": "GitHub/GitLab API integration for CI/PR state",
                    "priority": "P2",
                })
            elif surface == "runtime":
                suggestions.append({
                    "surface": "runtime",
                    "action": "RuntimeObservationAdapter needed",
                    "note": "Process, service, container, and config state observation",
                    "priority": "P2",
                })
            elif surface == "source_content":
                suggestions.append({
                    "surface": "source_content",
                    "action": "content_read authority needed on this scope (an owner decision)",
                    "note": "Without it source content is not observed and runtime references stay UNKNOWN",
                    "priority": "P1",
                })

        return suggestions

    def _resolve_scope_surfaces(self, scope_id: str) -> dict[str, str]:
        """Return per-surface observation capability for the scope."""
        scope = None
        for s in self._scopes.list_scopes():
            if s["scope_id"] == scope_id:
                scope = s
                break

        surfaces: dict[str, str] = {
            "repo_discovery": "not_authorized",
            "source_content": "not_authorized",
            "git_metadata": "not_authorized",
            "runtime_config": "adapter_not_available",
            "process": "adapter_not_available",
            "service_api": "adapter_not_available",
            "container": "adapter_not_available",
            "forge_ci": "adapter_not_available",
        }

        if scope:
            auth = scope.get("authority", {})
            if auth.get("discover"):
                surfaces["repo_discovery"] = "observed"
            if auth.get("content_read"):
                surfaces["source_content"] = "observed"
            if auth.get("git_observe"):
                surfaces["git_metadata"] = "observed"

        return surfaces
