from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

KIND_GIT_REPOSITORY = "git-repository"
KIND_FILESYSTEM_DIRECTORY = "filesystem-directory"
ROOT_POLICY_VERSION = "S1ReadPolicy/v1"

# Closed world: these are the only workspace kinds that exist and the only capabilities each
# can ever grant. A directory is not a repository: it can never be observed through Git.
KIND_CAPABILITIES: dict[str, frozenset[str]] = {
    KIND_GIT_REPOSITORY: frozenset({"filesystem.read", "git.observe"}),
    KIND_FILESYSTEM_DIRECTORY: frozenset({"filesystem.read"}),
}


@dataclass(frozen=True)
class RootIdentity:
    """Trusted root directory object identity established at authorization time.

    Binds the filesystem device and inode ``(dev, ino)``, the canonical root path
    resolved at authorization time, and the active policy version/generation.
    """

    dev: int
    ino: int
    root: str
    policy_version: str = ROOT_POLICY_VERSION
    policy_generation: str = ""
    git_dev: int | None = None
    git_ino: int | None = None
    git_mode: int | None = None


def is_git_checkout(path: Path) -> bool:
    """A derived path is admitted as a repository exactly when it has a ``.git`` entry.

    One definition, shared by admission and by the search locator, so that the workspace a
    locator names and the workspace admission builds for it cannot disagree about the kind.
    """
    return (path / ".git").exists()


@dataclass(frozen=True)
class WorkspaceSpec:
    workspace_id: str
    root: str
    label: str = ""
    kind: str = KIND_GIT_REPOSITORY
    capabilities: list[str] = field(
        default_factory=lambda: ["filesystem.read", "git.observe"]
    )
    max_file_bytes: int = 524_288
    max_search_files: int = 5_000
    root_identity: RootIdentity | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("root_identity", None)
        return data


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
class ExecutionContractV2:
    """Successor contract schema ``uam-execution-contract-v2`` (profile ``workspace-change-v2``).

    The v1 contract names a Git revision as its baseline and so can only describe a change in a
    repository. v2 states the baseline explicitly (``baseline``) so the same contract can bind a
    change in a plain directory, a repository change that is never committed, or a justified
    "no change". ``baseline`` and ``admission`` are facts UAM observed when it admitted the
    contract; a caller cannot supply them (see ``ContractStore.put_v2``). v1 contracts and their
    validator are unchanged.
    """

    contract_version: str
    profile: str
    contract_id: str
    workspace_id: str
    baseline: dict[str, Any]
    admission: dict[str, Any]
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
