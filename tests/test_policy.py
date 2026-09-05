import os
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.errors import PathPolicyError
from universal_agent_middleware.policy import resolve_safe_path


class PolicyTests(unittest.TestCase):
    def test_traversal_and_absolute_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "a.txt").write_text("ok")
            with self.assertRaises(PathPolicyError):
                resolve_safe_path(td, "../outside")
            with self.assertRaises(PathPolicyError):
                resolve_safe_path(td, "/etc/passwd")

    def test_secret_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, ".env").write_text("TOKEN=secret")
            with self.assertRaises(PathPolicyError):
                resolve_safe_path(td, ".env")

    def test_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            Path(outside, "secret.txt").write_text("outside")
            link = Path(td, "escape")
            try:
                link.symlink_to(Path(outside, "secret.txt"))
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(PathPolicyError):
                resolve_safe_path(td, "escape")


if __name__ == "__main__":
    unittest.main()
