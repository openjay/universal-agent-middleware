"""Filesystem fixtures for the ``filesystem-directory`` workspace kind tests.

One disposable world per test case::

    <root>/config/    registry (and, on request, root_scopes.json)
    <root>/state/     UAM state directory (audit, index)
    <root>/data/      the RootScope ``data-scope``
        plain-docs/   ordinary, non-Git directory under test
        git-repo/     a Git repository (``docs/`` inside it is a plain subdirectory)
        restricted/   plain directory a nested scope will deny
        vault.key/    plain directory whose own name is a protected pattern
        .ssh/         plain directory whose own name is protected
    <root>/outside/   not covered by any scope

``control_plane_inside_data=True`` moves ``config/`` and ``state/`` under ``data/`` so the
control-plane disjointness rule can be exercised.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority

from synthetic_fixtures import init_git_repo, write_workspace_registry

SCOPE_ID = "data-scope"
PLAIN = "plain-docs"
PLAIN_ID = f"derived:{SCOPE_ID}:{PLAIN}"
OUTSIDE_SECRET = "OUTSIDE-SECRET"

_FULL_AUTHORITY: dict[str, bool] = {
    "discover": True, "metadata_read": True, "content_read": True, "text_search": True,
    "git_observe": True, "classify": True, "index": True, "relate": True,
    "auto_admit": True, "directory_admit": True,
}


def authority(**overrides: bool) -> RootScopeAuthority:
    """Full read-only authority with ``overrides`` applied (default: directory_admit on)."""
    return RootScopeAuthority(**{**_FULL_AUTHORITY, **overrides})


def authority_dict(**overrides: bool) -> dict[str, bool]:
    return {**_FULL_AUTHORITY, **overrides}


def derived_id(rel_path: str) -> str:
    return f"derived:{SCOPE_ID}:{rel_path}"


def static_directory(workspace_id: str, root: Path, **extra: Any) -> dict[str, Any]:
    """A registry entry for a static ``filesystem-directory`` workspace."""
    return {
        "workspace_id": workspace_id, "root": str(root), "kind": "filesystem-directory",
        "capabilities": ["filesystem.read"], **extra,
    }


def static_repository(workspace_id: str, root: Path, **extra: Any) -> dict[str, Any]:
    return {
        "workspace_id": workspace_id, "root": str(root), "kind": "git-repository",
        "capabilities": ["filesystem.read", "git.observe"], **extra,
    }


def fingerprint(root: Path) -> dict[str, tuple[Any, ...]]:
    """Byte-level fingerprint of a tree that never opens special files.

    Directories and symlinks are fingerprinted by metadata/target; only regular files are
    read. ``atime`` is excluded on purpose: reading a file may update it on some filesystems.
    """
    result: dict[str, tuple[Any, ...]] = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(current) / name
            info = os.lstat(path)
            rel = path.relative_to(root).as_posix()
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            elif stat.S_ISLNK(info.st_mode):
                digest = "->" + os.readlink(path)
            else:
                digest = "-"
            result[rel] = (stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns, digest)
    return result


class DirectoryWorld:
    """A disposable filesystem plus a gateway builder."""

    def __init__(self, *, control_plane_inside_data: bool = False) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-fsdir-")
        self.root = Path(self._tmp.name).resolve()
        self.data = self.root / "data"
        self.outside = self.root / "outside"
        if control_plane_inside_data:
            self.config = self.data / "uam-config"
            self.state = self.data / "uam-state"
        else:
            self.config = self.root / "config"
            self.state = self.root / "state"
        self.plain = self.data / PLAIN
        self.repo = self.data / "git-repo"
        self.registry_path = self.config / "workspaces.json"
        self._build()

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def _build(self) -> None:
        self.config.mkdir(parents=True)
        self.outside.mkdir(parents=True)
        (self.outside / "secret.txt").write_text(f"{OUTSIDE_SECRET}\n", encoding="utf-8")

        (self.plain / "notes").mkdir(parents=True)
        (self.plain / "README.md").write_text("# Plain directory\nneedle-markdown\n", encoding="utf-8")
        (self.plain / "tool.py").write_text("def main():\n    return 'needle-python'\n", encoding="utf-8")
        (self.plain / "config.json").write_text('{"key": "needle-json"}\n', encoding="utf-8")
        (self.plain / "notes" / "nested.md").write_text("nested needle-nested\n", encoding="utf-8")
        (self.plain / ".env").write_text("API_KEY=do-not-leak\n", encoding="utf-8")
        (self.plain / ".ssh").mkdir()
        (self.plain / ".ssh" / "config").write_text("Host leaked-host\n", encoding="utf-8")
        (self.plain / "server.pem").write_text("FAKE-PEM-do-not-leak\n", encoding="utf-8")
        (self.plain / "big.txt").write_text("needle-big\n" + "x" * 600_000, encoding="utf-8")
        (self.plain / "blob.bin").write_bytes(b"needle-bin\x00\x01\x02")
        os.symlink(self.outside, self.plain / "link-out")
        os.symlink(self.outside / "secret.txt", self.plain / "link-file")
        os.symlink("README.md", self.plain / "link-in")

        init_git_repo(self.repo, files={
            "README.md": "# repo\n", "docs/guide.md": "guide needle-guide\n",
        })
        for rel, name, text in (
            ("restricted", "secret.txt", "restricted content\n"),
            ("vault.key", "inner.txt", "inside a protected-name directory\n"),
            (".ssh", "config", "Host top-level-leak\n"),
        ):
            (self.data / rel).mkdir()
            (self.data / rel / name).write_text(text, encoding="utf-8")

    def scope(self, **overrides: bool) -> RootScope:
        return RootScope(scope_id=SCOPE_ID, root=str(self.data), authority=authority(**overrides))

    def write_scope_file(self, **overrides: bool) -> Path:
        """Write ``root_scopes.json`` next to the registry (what a real deployment does)."""
        path = self.config / "root_scopes.json"
        path.write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{
                "scope_id": SCOPE_ID, "root": str(self.data),
                "authority": authority_dict(**overrides), "description": "fixture scope",
            }],
            "overrides": {},
        }, indent=2), encoding="utf-8")
        return path

    def write_registry(self, workspaces: list[dict[str, Any]] | None = None) -> Path:
        return write_workspace_registry(self.registry_path, workspaces or [])

    def gateway(
        self,
        workspaces: list[dict[str, Any]] | None = None,
        *,
        scope: RootScope | None | bool = True,
    ) -> MiddlewareGateway:
        """Gateway over this world; ``scope=True`` adds the default scope, ``False`` none."""
        self.write_registry(workspaces)
        gateway = MiddlewareGateway(str(self.registry_path), str(self.state))
        if scope is True:
            gateway.scopes.add_scope(self.scope())
        elif isinstance(scope, RootScope):
            gateway.scopes.add_scope(scope)
        return gateway

    def target_fingerprint(self) -> dict[str, dict[str, tuple[Any, ...]]]:
        """Everything a read-only observer must leave byte-identical."""
        return {
            "plain": fingerprint(self.plain),
            "restricted": fingerprint(self.data / "restricted"),
            "vault": fingerprint(self.data / "vault.key"),
            "outside": fingerprint(self.outside),
            "data_top_level": {
                name: () for name in sorted(os.listdir(self.data))
            },
        }


class WorldTestCase(unittest.TestCase):
    """Builds a fresh :class:`DirectoryWorld` per test and tears it down."""

    control_plane_inside_data = False

    def setUp(self) -> None:
        self.world = DirectoryWorld(control_plane_inside_data=self.control_plane_inside_data)
        self.addCleanup(self.world.cleanup)

    def diagnostic_of(self, exc: BaseException) -> dict[str, Any]:
        diagnostic = getattr(exc, "diagnostic", None)
        self.assertIsInstance(diagnostic, dict, f"no diagnostic on {exc!r}")
        return diagnostic
