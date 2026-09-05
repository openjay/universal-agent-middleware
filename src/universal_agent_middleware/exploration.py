"""Autonomous Exploration layer for UAM (Slice C).

Provides:
- CoverageGapV1: identifies referenced-but-unobserved truth surfaces
- RealityGraphV1: lightweight project/repo/instance relationship graph
- Intent-driven ranking: prioritizes projects relevant to a stated goal
- Selective hydration planning: recommends what to read next
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .discovery import DiscoveredProject, DiscoveryEngine
from .root_scope import RootScopeRegistry


@dataclass
class CoverageGap:
    project_id: str
    surface: str
    state: str
    evidence_refs: list[str] = field(default_factory=list)
    suggested_scope: str = ""
    authority_state: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "surface": self.surface,
            "state": self.state,
            "evidence_refs": self.evidence_refs,
            "suggested_scope": self.suggested_scope,
            "authority_state": self.authority_state,
        }


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

    def rank_projects(self, scope_id: str) -> dict[str, Any]:
        """Rank projects by relevance/activity for selective exploration."""
        inventory = self._discovery.scope_inventory(scope_id)
        if "error" in inventory:
            return inventory

        projects = inventory.get("projects", [])
        ranked = sorted(projects, key=lambda p: self._relevance_score(p), reverse=True)

        observed_at = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": "project-ranking-v1",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "total_projects": len(ranked),
            "ranked": [
                {
                    "project_id": p["project_id"],
                    "status": p["status"],
                    "instance_count": p["instance_count"],
                    "languages": p["languages"],
                    "relevance_score": self._relevance_score(p),
                    "last_activity": p.get("last_activity", ""),
                }
                for p in ranked
            ],
            "summary": {
                "active": sum(1 for p in projects if p["status"] == "active"),
                "recent": sum(1 for p in projects if p["status"] == "recent"),
                "dormant": sum(1 for p in projects if p["status"] == "dormant"),
                "archived": sum(1 for p in projects if p["status"] == "archived"),
            },
        }

    def what_am_i_missing(self, scope_id: str) -> dict[str, Any]:
        """Answer: what truth surfaces are missing across active projects?"""
        inventory = self._discovery.scope_inventory(scope_id)
        if "error" in inventory:
            return inventory

        all_gaps: list[dict[str, Any]] = []
        active_projects = [
            p for p in inventory.get("projects", [])
            if p["status"] in ("active", "recent")
        ]

        for project in active_projects:
            gaps = self._find_coverage_gaps(project, scope_id)
            for gap in gaps:
                all_gaps.append(gap.to_dict())

        observed_at = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": "missing-reality-v1",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "active_projects_analyzed": len(active_projects),
            "total_gaps": len(all_gaps),
            "gaps": all_gaps,
            "scope_escalation_suggestions": self._suggest_escalations(all_gaps),
        }

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
        """Generate a bounded retrieval plan for selective hydration."""
        plan_items: list[dict[str, Any]] = []
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
            for pf in priority_files:
                target = path / pf
                if target.is_file():
                    size = target.stat().st_size
                    if total_bytes + size <= max_bytes and total_files < max_files:
                        project_targets.append(pf)
                        total_bytes += size
                        total_files += 1

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
        }

    def _find_coverage_gaps(self, project: dict[str, Any], scope_id: str) -> list[CoverageGap]:
        """Identify referenced-but-unobserved surfaces for a project."""
        gaps: list[CoverageGap] = []
        canonical_path = project.get("canonical_path", "")
        if not canonical_path:
            return gaps

        path = Path(canonical_path)
        if not path.is_dir():
            return gaps

        has_forge = False
        has_runtime = False
        forge_refs: list[str] = []
        runtime_refs: list[str] = []

        try:
            for entry in path.iterdir():
                name = entry.name
                if name in _FORGE_INDICATORS or (entry.is_dir() and name == ".github"):
                    has_forge = True
                    forge_refs.append(name)
                if name in _RUNTIME_INDICATORS:
                    has_runtime = True
                    runtime_refs.append(name)
        except (PermissionError, OSError):
            pass

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

        return gaps

    def _assess_coverage(self, project: dict[str, Any], gaps: list[CoverageGap]) -> dict[str, Any]:
        """Provide a human-readable coverage assessment."""
        surfaces_ok = ["local_source"]
        if project.get("instance_count", 0) > 1:
            surfaces_ok.append("worktrees")

        return {
            "observed": surfaces_ok,
            "missing": [g.surface for g in gaps],
            "verdict": "PARTIAL" if gaps else "LOCAL_COMPLETE",
            "note": (
                "Local source fully observable; forge/runtime require adapters"
                if gaps else "All locally observable surfaces covered"
            ),
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
                    "note": "Docker/process/service state observation",
                    "priority": "P3",
                })

        return suggestions
