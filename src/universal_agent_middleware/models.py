from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class WorkspaceSpec:
    workspace_id: str
    root: str
    label: str = ""
    kind: str = "git-repository"
    capabilities: list[str] = field(
        default_factory=lambda: ["filesystem.read", "git.observe"]
    )
    max_file_bytes: int = 524_288
    max_search_files: int = 5_000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionContract:
    contract_version: str
    profile: str
    contract_id: str
    workspace_id: str
    base_revision: str
    objective: str
    non_goals: list[str]
    authoritative_paths: list[str]
    allowed_change_paths: list[str]
    constraints: list[str]
    implementation_decision: str
    expected_changes: list[str]
    acceptance_criteria: list[str]
    verification_commands: list[str]
    risk_notes: list[str]
    rollback: list[str]
    open_questions: list[str] = field(default_factory=list)
    created_at: str = ""
    created_by: str = "uam"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutorResult:
    result_version: str
    result_id: str
    contract_id: str
    workspace_id: str
    base_revision: str
    final_revision: str
    changed_paths: list[str]
    verification: list[dict[str, Any]]
    unresolved_risks: list[str]
    executor: str
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
