import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.errors import PathPolicyError
from universal_agent_middleware.policy import (
    _is_denied_component, ensure_relative_path, resolve_safe_path, should_hide_path,
)


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

    def test_protected_names_do_not_depend_on_letter_case(self):
        # The default macOS filesystem is case-insensitive: `.SSH` is the `.ssh` directory.
        for name in (".ssh", ".SSH", ".Ssh", ".AWS", ".GIT", "ID_RSA", "Credentials", ".ENV", "Server.PEM"):
            with self.subTest(name=name):
                self.assertTrue(_is_denied_component(name))
                with self.assertRaises(PathPolicyError):
                    ensure_relative_path(f"project/{name}/inner.txt")

    def test_ordinary_names_stay_readable(self):
        for name in ("README.md", "docs", "credential-model.md", "environment.md", "keys.md", "sshd_notes.txt"):
            with self.subTest(name=name):
                self.assertFalse(_is_denied_component(name))

    def test_differently_cased_alias_of_a_protected_directory_is_rejected_on_disk(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, ".ssh").mkdir()
            Path(td, ".ssh", "config").write_text("Host example\n")
            if not Path(td, ".SSH", "config").exists():
                self.skipTest("case-sensitive filesystem: `.SSH` is not an alias of `.ssh`")
            with self.assertRaises(PathPolicyError):
                resolve_safe_path(td, ".SSH/config")
            self.assertTrue(should_hide_path(td, Path(td, ".SSH")))


if __name__ == "__main__":
    unittest.main()
