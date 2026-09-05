import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.errors import ContractError, WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway


class GatewayBoundaryTests(unittest.TestCase):
    def make_repo(self, base: Path) -> tuple[Path, str]:
        repo = base / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "UAM Boundary Test"], check=True)
        (repo / "README.md").write_text("truth\n", encoding="utf-8")
        (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        return repo, head

    def registry(self, base: Path, repo: Path) -> Path:
        path = base / "workspaces.json"
        path.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{"workspace_id": "w", "root": str(repo), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}), encoding="utf-8")
        return path

    @staticmethod
    def contract(head: str) -> dict:
        return {
            "profile": "repository-change-v1",
            "contract_id": "task-boundary-001",
            "workspace_id": "w",
            "base_revision": head,
            "objective": "bounded change",
            "non_goals": [],
            "authoritative_paths": ["README.md"],
            "allowed_change_paths": ["README.md"],
            "constraints": [],
            "implementation_decision": "change README only",
            "expected_changes": ["README changed"],
            "acceptance_criteria": ["verification passes"],
            "verification_commands": ["git diff --check"],
            "risk_notes": [],
            "rollback": ["revert patch"],
            "open_questions": [],
        }

    def test_state_dir_must_be_disjoint_from_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, _ = self.make_repo(base)
            registry = self.registry(base, repo)
            with self.assertRaises(WorkspaceError):
                MiddlewareGateway(str(registry), str(repo / ".state"))

    def test_contract_binds_current_head(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, head = self.make_repo(base)
            gateway = MiddlewareGateway(str(self.registry(base, repo)), str(base / "state"))
            payload = self.contract(head)
            payload["base_revision"] = "0" * len(head)
            with self.assertRaises(ContractError):
                gateway.create_contract(payload)

    def test_contract_requires_clean_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, head = self.make_repo(base)
            gateway = MiddlewareGateway(str(self.registry(base, repo)), str(base / "state"))
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(ContractError):
                gateway.create_contract(self.contract(head))

    def test_contract_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, head = self.make_repo(base)
            gateway = MiddlewareGateway(str(self.registry(base, repo)), str(base / "state"))
            payload = self.contract(head)
            payload["allowed_change_paths"] = ["../escape"]
            with self.assertRaises(Exception):
                gateway.create_contract(payload)
            payload = self.contract(head)
            payload["contract_id"] = "task-boundary-002"
            payload["authoritative_paths"] = ["missing.txt"]
            with self.assertRaises(Exception):
                gateway.create_contract(payload)

    def test_authoritative_path_must_be_tracked_by_bound_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, head = self.make_repo(base)
            (repo / "ignored.txt").write_text("local-only truth\n", encoding="utf-8")
            gateway = MiddlewareGateway(str(self.registry(base, repo)), str(base / "state"))
            payload = self.contract(head)
            payload["contract_id"] = "task-boundary-003"
            payload["authoritative_paths"] = ["ignored.txt"]
            with self.assertRaises(ContractError):
                gateway.create_contract(payload)


if __name__ == "__main__":
    unittest.main()
