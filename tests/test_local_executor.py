"""Tests for the local executor adapter."""
from __future__ import annotations

import os
import subprocess
import tempfile
import shutil
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from universal_agent_middleware.executors import LocalExecutor, LocalExecutorConfig


class LocalExecutorTests(unittest.TestCase):
    """Unit tests for LocalExecutor using a disposable git repo."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="uam_exec_test_")
        subprocess.run(["git", "init", self.tmp], capture_output=True, check=True)
        for key, value in (("user.name", "UAM Test"), ("user.email", "test@example.invalid"),
                           ("commit.gpgsign", "false")):
            subprocess.run(["git", "-C", self.tmp, "config", key, value], check=True)
        subprocess.run(
            ["git", "-C", self.tmp, "commit", "--allow-empty", "-m", "init"],
            capture_output=True, check=True,
        )
        self.head = subprocess.run(
            ["git", "-C", self.tmp, "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        readme = Path(self.tmp) / "README.md"
        readme.write_text("# Test\n")
        subprocess.run(
            ["git", "-C", self.tmp, "add", "README.md"],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "-C", self.tmp, "commit", "-m", "add readme"],
            capture_output=True, check=True,
        )
        self.head = subprocess.run(
            ["git", "-C", self.tmp, "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _contract(self, **overrides):
        base = {
            "contract_id": "test-001",
            "workspace_id": "test",
            "base_revision": self.head,
            "allowed_change_paths": ["CHANGELOG.md"],
            "verification_commands": ["test -f CHANGELOG.md"],
        }
        base.update(overrides)
        return base

    def test_successful_execution(self):
        config = LocalExecutorConfig(workspace_root=self.tmp)
        executor = LocalExecutor(config)

        def change_fn(root: Path) -> list[str]:
            (root / "CHANGELOG.md").write_text("# Changelog\n\n## 0.1.0\n- init\n")
            return ["CHANGELOG.md"]

        outcome = executor.execute(
            self._contract(),
            change_fn,
            result_id="result-001",
        )
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.changed_paths, ["CHANGELOG.md"])
        self.assertNotEqual(outcome.final_revision, outcome.base_revision)
        self.assertEqual(len(outcome.verification), 1)
        self.assertEqual(outcome.verification[0]["exit_code"], 0)

    def test_base_revision_mismatch(self):
        config = LocalExecutorConfig(workspace_root=self.tmp)
        executor = LocalExecutor(config)

        outcome = executor.execute(
            self._contract(base_revision="deadbeef" * 5),
            lambda root: [],
            result_id="result-002",
        )
        self.assertFalse(outcome.success)
        self.assertIn("HEAD", outcome.error)

    def test_out_of_scope_paths_rejected(self):
        config = LocalExecutorConfig(workspace_root=self.tmp)
        executor = LocalExecutor(config)

        def change_fn(root: Path) -> list[str]:
            (root / "CHANGELOG.md").write_text("ok\n")
            (root / "EXTRA.md").write_text("bad\n")
            return ["CHANGELOG.md", "EXTRA.md"]

        outcome = executor.execute(
            self._contract(),
            change_fn,
            result_id="result-003",
        )
        self.assertFalse(outcome.success)
        self.assertIn("out-of-scope", outcome.error)

    def test_verification_failure_holds(self):
        config = LocalExecutorConfig(workspace_root=self.tmp)
        executor = LocalExecutor(config)

        def change_fn(root: Path) -> list[str]:
            (root / "CHANGELOG.md").write_text("# Changelog\n")
            return ["CHANGELOG.md"]

        outcome = executor.execute(
            self._contract(verification_commands=["grep -q 'MISSING' CHANGELOG.md"]),
            change_fn,
            result_id="result-004",
        )
        self.assertFalse(outcome.success)
        self.assertIn("verification failed", outcome.error)


if __name__ == "__main__":
    unittest.main()
