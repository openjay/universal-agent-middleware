import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.git_readonly import ReadOnlyGit


class GitReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name, "repo")
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "UAM Test"], check=True)
        Path(self.repo, "a.txt").write_text("one\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "a.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "base"], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _script(self, name):
        marker = Path(self.tmp.name, f"{name}.marker")
        script = Path(self.tmp.name, f"{name}.sh")
        script.write_text(f"#!/bin/sh\necho executed > '{marker}'\nexit 0\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return script, marker

    def test_status_disables_repo_fsmonitor_hook(self):
        script, marker = self._script("fsmonitor")
        subprocess.run(["git", "-C", str(self.repo), "config", "core.fsmonitor", str(script)], check=True)
        ReadOnlyGit(str(self.repo)).status()
        self.assertFalse(marker.exists(), "untrusted fsmonitor hook executed")

    def test_diff_disables_external_diff(self):
        script, marker = self._script("external-diff")
        subprocess.run(["git", "-C", str(self.repo), "config", "diff.external", str(script)], check=True)
        Path(self.repo, "a.txt").write_text("two\n")
        result = ReadOnlyGit(str(self.repo)).diff()
        self.assertIn("two", result["diff"])
        self.assertFalse(marker.exists(), "untrusted external diff executed")


if __name__ == "__main__":
    unittest.main()
