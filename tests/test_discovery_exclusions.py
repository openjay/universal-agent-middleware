"""Tests for macOS TCC-safe discovery directory exclusions."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from universal_agent_middleware.discovery import (
    DiscoveryEngine,
    _MACOS_HOME_SKIP_DIRS,
    _MACOS_TCC_DIRS,
    _denied_paths_circuit_breaker,
    _normalize_path_key,
    _record_denied_path,
    _should_proactively_skip_path,
    _should_skip_directory,
    clear_denied_paths_circuit_breaker,
)
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from synthetic_fixtures import init_git_repo


class TestShouldSkipDirectory(unittest.TestCase):
    def test_skips_tcc_dirs_at_any_depth(self):
        scan_root = Path("/Users/example")
        for name in ("Containers", "Group Containers", "Application Support"):
            entry = Path(f"/Users/example/Library/{name}")
            self.assertTrue(
                _should_skip_directory(entry, scan_root=scan_root, parent_depth=2),
                f"expected skip for {name}",
            )

    def test_skips_home_system_dirs_at_root(self):
        scan_root = Path("/Users/example")
        for name in _MACOS_HOME_SKIP_DIRS:
            entry = scan_root / name
            self.assertTrue(
                _should_skip_directory(entry, scan_root=scan_root, parent_depth=0),
                f"expected home-root skip for {name}",
            )

    def test_does_not_skip_home_system_dirs_when_nested(self):
        scan_root = Path("/Users/example")
        entry = scan_root / "code" / "some-app" / "Library"
        self.assertFalse(
            _should_skip_directory(entry, scan_root=scan_root, parent_depth=3),
        )

    def test_skips_noise_and_hidden_dirs(self):
        scan_root = Path("/Users/example/code")
        self.assertTrue(
            _should_skip_directory(
                scan_root / "proj" / "node_modules",
                scan_root=scan_root,
                parent_depth=1,
            ),
        )
        self.assertTrue(
            _should_skip_directory(
                scan_root / "proj" / ".venv",
                scan_root=scan_root,
                parent_depth=1,
            ),
        )
        self.assertTrue(
            _should_skip_directory(
                scan_root / "proj" / ".cache",
                scan_root=scan_root,
                parent_depth=1,
            ),
        )

    def test_allows_code_directory_at_home_root(self):
        scan_root = Path("/Users/example")
        entry = scan_root / "code"
        self.assertFalse(
            _should_skip_directory(entry, scan_root=scan_root, parent_depth=0),
        )


class TestDiscoverySkipsTccPaths(unittest.TestCase):
    """Discovery must not descend into TCC-protected or system directories."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-tcc-exclusion-")
        self.home = Path(self._tmp.name)
        self._build_home_layout()

        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope(
            scope_id="test-home",
            root=str(self.home),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=False,
            ),
        ))
        self.engine = DiscoveryEngine(self.registry)

    def tearDown(self):
        self._tmp.cleanup()

    def _build_home_layout(self) -> None:
        init_git_repo(self.home / "code" / "visible-repo", files={"README.md": "# ok\n"})

        library = self.home / "Library"
        containers = library / "Containers"
        containers.mkdir(parents=True)
        init_git_repo(containers / "com.example.app" / "Data" / "hidden-repo",
                      files={"README.md": "# should not appear\n"})

        for name in _MACOS_TCC_DIRS:
            (library / name).mkdir(parents=True, exist_ok=True)

        for name in _MACOS_HOME_SKIP_DIRS:
            if name == "Library":
                continue
            (self.home / name).mkdir(parents=True, exist_ok=True)

    def test_discovers_code_but_not_library_containers(self):
        result = self.engine.discover_scope("test-home")
        self.assertNotIn("error", result)
        project_ids = {p["project_id"] for p in result["projects"]}
        self.assertIn("visible-repo", project_ids)
        self.assertNotIn("hidden-repo", project_ids)
        self.assertEqual(result["total_repositories"], 1)

    def test_walk_never_calls_iterdir_on_tcc_paths(self):
        original_iterdir = Path.iterdir
        tcc_paths: set[str] = set()

        def tracking_iterdir(self_path: Path):
            rel = str(self_path)
            for name in _MACOS_TCC_DIRS:
                if f"/Library/{name}" in rel or rel.endswith(f"/{name}"):
                    tcc_paths.add(rel)
            if rel.endswith("/Containers") or "/Containers/" in rel:
                tcc_paths.add(rel)
            return original_iterdir(self_path)

        with mock.patch.object(Path, "iterdir", tracking_iterdir):
            self.engine.discover_scope("test-home")

        self.assertEqual(tcc_paths, set(), f"iterdir called on TCC paths: {tcc_paths}")

    def test_walk_never_calls_is_dir_on_tcc_paths(self):
        original_is_dir = Path.is_dir
        tcc_paths: set[str] = set()

        def tracking_is_dir(self_path: Path):
            rel = str(self_path)
            for name in _MACOS_TCC_DIRS:
                if f"/Library/{name}" in rel or rel.endswith(f"/{name}"):
                    tcc_paths.add(rel)
            if rel.endswith("/Library") or rel.endswith("/Containers"):
                tcc_paths.add(rel)
            for name in _MACOS_HOME_SKIP_DIRS:
                if rel.endswith(f"/{name}"):
                    tcc_paths.add(rel)
            return original_is_dir(self_path)

        with mock.patch.object(Path, "is_dir", tracking_is_dir):
            self.engine.discover_scope("test-home")

        self.assertEqual(tcc_paths, set(), f"is_dir called on TCC paths: {tcc_paths}")

    def test_proactive_skip_blocks_library_before_iterdir(self):
        library = self.home / "Library"
        self.assertTrue(
            _should_proactively_skip_path(library, scan_root=self.home),
        )

    def test_circuit_breaker_skips_previously_denied_paths(self):
        clear_denied_paths_circuit_breaker()
        blocked = self.home / "code" / "denied-zone"
        blocked.mkdir(parents=True)
        init_git_repo(blocked / "secret-repo", files={"README.md": "# secret\n"})
        _record_denied_path(blocked)

        original_iterdir = Path.iterdir
        probed: list[str] = []

        def tracking_iterdir(self_path: Path):
            key = _normalize_path_key(self_path)
            if key in _denied_paths_circuit_breaker:
                probed.append(key)
            return original_iterdir(self_path)

        with mock.patch.object(Path, "iterdir", tracking_iterdir):
            result = self.engine.discover_scope("test-home")

        self.assertNotIn("error", result)
        project_ids = {p["project_id"] for p in result["projects"]}
        self.assertIn("visible-repo", project_ids)
        self.assertNotIn("secret-repo", project_ids)
        self.assertNotIn(_normalize_path_key(blocked), probed)
        clear_denied_paths_circuit_breaker()

    def test_permission_error_during_is_dir_is_skipped(self):
        clear_denied_paths_circuit_breaker()
        repo = self.home / "code" / "blocked"
        repo.mkdir(parents=True)
        init_git_repo(repo, files={"README.md": "# blocked\n"})

        original_is_dir = Path.is_dir
        blocked_is_dir_calls: list[Path] = []

        def flaky_is_dir(self_path: Path):
            if self_path.name == "blocked":
                blocked_is_dir_calls.append(self_path)
                raise PermissionError("EPERM")
            return original_is_dir(self_path)

        with mock.patch.object(Path, "is_dir", flaky_is_dir):
            result = self.engine.discover_scope("test-home")

        self.assertNotIn("error", result)
        project_ids = {p["project_id"] for p in result["projects"]}
        self.assertIn("visible-repo", project_ids)
        self.assertNotIn("blocked", project_ids)
        self.assertIn(_normalize_path_key(repo), _denied_paths_circuit_breaker)
        self.assertGreaterEqual(len(blocked_is_dir_calls), 1)

        blocked_is_dir_calls.clear()
        with mock.patch.object(Path, "is_dir", flaky_is_dir):
            self.engine.discover_scope("test-home")

        self.assertEqual(blocked_is_dir_calls, [])
        clear_denied_paths_circuit_breaker()


if __name__ == "__main__":
    unittest.main()
