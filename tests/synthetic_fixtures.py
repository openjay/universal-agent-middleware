"""Portable synthetic git and registry fixtures for OSS/public test suites."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry


def init_git_repo(path: Path, *, files: dict[str, str] | None = None) -> None:
    """Create a minimal git repository with optional tracked files."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(path), capture_output=True, timeout=10, check=False)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=str(path), capture_output=True, timeout=5, check=False,
    )
    subprocess.run(
        ["git", "config", "user.name", "UAM Fixture"],
        cwd=str(path), capture_output=True, timeout=5, check=False,
    )
    for rel, content in (files or {"README.md": "# fixture\n"}).items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(path), capture_output=True, timeout=10, check=False)
    subprocess.run(
        ["git", "commit", "-qm", "fixture"],
        cwd=str(path), capture_output=True, timeout=10, check=False,
        env={**os.environ, "GIT_AUTHOR_NAME": "UAM Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
             "GIT_COMMITTER_NAME": "UAM Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"},
    )


def write_workspace_registry(
    path: Path,
    workspaces: list[dict[str, Any]],
    *,
    profile_dir: Path | None = None,
    profiles: dict[str, dict[str, Any]] | None = None,
) -> Path:
    """Write a workspace registry and optional observation profiles."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": workspaces}, indent=2),
        encoding="utf-8",
    )
    if profile_dir is not None and profiles:
        profile_dir.mkdir(parents=True, exist_ok=True)
        for project_id, profile in profiles.items():
            (profile_dir / f"{project_id}.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path


def sample_observation_profile(project_id: str = "sampleproj") -> dict[str, Any]:
    return {
        "project_id": project_id,
        "schema_version": "observation-profile-v1",
        "description": "Sample project observation requirements. Informational only — does NOT grant authority.",
        "requirements": {
            "phase_a_exit_observation": {
                "surfaces": ["canonical_source", "forge_ci", "runtime"],
                "note": "Phase A exit requires canonical, CI, and runtime identity observable",
            },
            "candidate_consideration": {
                "surfaces": ["active_candidate", "canonical_source", "forge_ci"],
                "conditional": {
                    "active_candidate": {
                        "when": "candidate_exists",
                        "accepted": ["observed"],
                        "otherwise": "not_applicable",
                    }
                },
            },
            "merge_consideration": {
                "surfaces": ["active_candidate", "canonical_source", "forge_ci"],
                "conditional": {
                    "active_candidate": {
                        "when": "candidate_exists",
                        "accepted": ["observed"],
                        "otherwise": "not_applicable",
                    }
                },
                "note": "Observation prerequisite only; merge authority is PROJECT_DEFINED",
            },
            "runtime_consideration": {
                "surfaces": ["canonical_source", "runtime"],
                "accepted_states": ["observed", "externally_verified"],
            },
        },
        "authority_policy": {
            "mode": "PROJECT_DEFINED",
            "note": "Project SSOT defines gate semantics. UAM provides observation, not authorization.",
        },
    }


def build_multi_project_scope(tmp_root: Path) -> tuple[RootScopeRegistry, str]:
    """Create a scope registry covering multiple synthetic git projects."""
    alpha = tmp_root / "alpha"
    beta = tmp_root / "beta"
    init_git_repo(alpha, files={"source.py": "class MiddlewareGateway: pass\n"})
    init_git_repo(beta, files={"README.md": "# beta\nimport os\n"})
    registry = RootScopeRegistry()
    registry.add_scope(RootScope(
        scope_id="dev-code",
        root=str(tmp_root),
        authority=RootScopeAuthority(
            discover=True, metadata_read=True, content_read=True,
            text_search=True, git_observe=True, classify=True,
            index=True, relate=True, auto_admit=True,
        ),
    ))
    registry.add_scope(RootScope(
        scope_id="dev-home",
        root=str(tmp_root.parent),
        authority=RootScopeAuthority(discover=True),
    ))
    return registry, "dev-code"


class SyntheticRegistryBundle:
    """Temporary workspace registry with two git repositories."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-synthetic-registry-")
        self.root = Path(self._tmp.name)
        self.repo_a = self.root / "workspace-a"
        self.repo_b = self.root / "workspace-b"
        init_git_repo(self.repo_a, files={"README.md": "# workspace A\nimport json\n", "AGENTS.md": "# agents\n"})
        init_git_repo(self.repo_b, files={"README.md": "# workspace B\nimport sys\n"})
        self.config_dir = self.root / "config"
        self.profile_dir = self.config_dir / "project-observation-profiles"
        context_dir = self.config_dir / "workspace-contexts"
        context_dir.mkdir(parents=True, exist_ok=True)
        (context_dir / "primary.json").write_text(json.dumps({
            "schema_version": "workspace-context-profile-v1",
            "workspace_id": "primary",
            "entrypoints": ["README.md", "AGENTS.md"],
            "bootstrap_limits": {"max_files": 6, "max_total_bytes": 131072},
        }, indent=2), encoding="utf-8")
        self.registry_path = write_workspace_registry(
            self.config_dir / "workspaces.json",
            [
                {
                    "workspace_id": "workspace-a",
                    "project_id": "sampleproj",
                    "role": "canonical-main",
                    "repository_identity": "example/sampleproj",
                    "label": "Sample Project (main)",
                    "root": str(self.repo_a),
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                    "max_file_bytes": 524288,
                    "max_search_files": 5000,
                },
                {
                    "workspace_id": "sampleproj-candidate",
                    "project_id": "sampleproj",
                    "role": "candidate",
                    "lifecycle": "landed",
                    "repository_identity": "example/sampleproj",
                    "label": "Sample Project (candidate)",
                    "root": str(self.repo_b),
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                    "max_file_bytes": 524288,
                    "max_search_files": 5000,
                },
                {
                    "workspace_id": "primary",
                    "project_id": "primary",
                    "role": "canonical-main",
                    "repository_identity": "example/primary",
                    "label": "Primary fixture workspace",
                    "root": str(self.repo_a),
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                    "max_file_bytes": 524288,
                    "max_search_files": 5000,
                },
            ],
            profile_dir=self.profile_dir,
            profiles={"sampleproj": sample_observation_profile("sampleproj")},
        )

    def cleanup(self) -> None:
        self._tmp.cleanup()
