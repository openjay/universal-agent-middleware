from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
from universal_agent_middleware.errors import (
    ScopeAuthorityError,
    WorkspaceError,
    WorkspaceUnavailableError,
)
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.git_readonly import ReadOnlyGit
from universal_agent_middleware.git_snapshot import (
    HARD_LINK,
    OVER_BUDGET,
    REFUSED_NAME,
    SCOPE_DENIED,
    UNMERGED,
    UNSAFE_PATH,
    UNSUPPORTED_ENTRY,
    DiffBudgets,
    build_unstaged_diff,
)
from universal_agent_middleware.models import WorkspaceSpec
from universal_agent_middleware.path_authority import PathPolicy
from universal_agent_middleware.project import RegistryGenerationChanged
from universal_agent_middleware.root_scope import RootScopeRegistry
from universal_agent_middleware.workspace import WorkspaceReader, WorkspaceRegistry


def _git(cwd: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd.parent),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        cwd=str(cwd),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=True,
    )


def _init_repo(
    repo: Path,
    files: dict[str, str] | None = None,
    *,
    branch: str | None = None,
) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    if branch:
        _git(repo, "init", "-q", "-b", branch)
    else:
        _git(repo, "init", "-q")
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "base.txt").write_text("base\n", encoding="utf-8")
    (repo / "README.md").write_text("# readme\n", encoding="utf-8")
    if files:
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial")


def _hash_blob(repo: Path, content: bytes) -> str:
    cp = _git(repo, "hash-object", "-w", "--stdin", input_bytes=content)
    return cp.stdout.decode("ascii").strip()


def _write_registry_and_scopes(
    config_dir: Path,
    workspaces: list[dict[str, Any]],
    scopes: list[dict[str, Any]] | None = None,
) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    reg_path = config_dir / "workspaces.json"
    reg_path.write_text(
        json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": workspaces}),
        encoding="utf-8",
    )
    if scopes is not None:
        (config_dir / "root_scopes.json").write_text(
            json.dumps({"schema_version": "root-scopes-v1", "scopes": scopes}),
            encoding="utf-8",
        )
    return reg_path


def _full_authority(**overrides: bool) -> dict[str, bool]:
    base = {
        "discover": True,
        "metadata_read": True,
        "content_read": True,
        "text_search": True,
        "git_observe": True,
        "classify": True,
        "index": True,
        "relate": True,
        "auto_admit": True,
        "directory_admit": True,
    }
    base.update(overrides)
    return base


async def _call_mcp_tool(server: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    raw = await server.call_tool(name, arguments)
    if hasattr(raw, "content"):
        blocks = raw.content
    elif isinstance(raw, tuple) and len(raw) == 2:
        blocks = raw[0]
    else:
        blocks = raw
    text = blocks[0].text if blocks else "{}"
    return json.loads(text)


# ============================================================================
# R3.1-01 — Root Identity Binding
# ============================================================================


class TestR3101RootIdentityBinding(unittest.TestCase):
    """Counterexamples and regression checks for R3.1-01 (Root Identity Binding)."""

    def test_r31_01_root_replaced_by_external_symlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            ws = tmp_path / "authorized_ws"
            ws.mkdir()
            (ws / "safe.txt").write_text("SAFE_CONTENT\n", encoding="utf-8")

            outside = tmp_path / "outside_target"
            outside.mkdir()
            (outside / "safe.txt").write_text("OUTSIDE_SECRET_PAYLOAD\n", encoding="utf-8")

            reg_path = _write_registry_and_scopes(
                tmp_path / "config",
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            registry = WorkspaceRegistry(reg_path)
            spec = registry.get("ws")
            reader = WorkspaceReader(spec)
            self.assertEqual(reader.read_file("safe.txt")["content"], "SAFE_CONTENT")

            # Replace authorized root with a symlink to outside_target
            shutil.rmtree(ws)
            ws.symlink_to(outside)

            with self.assertRaises(WorkspaceError):
                reader.read_file("safe.txt")
            with self.assertRaises(WorkspaceError):
                reader.tree()
            with self.assertRaises(WorkspaceError):
                reader.search_text("OUTSIDE")
            with self.assertRaises(WorkspaceError):
                reader.file_digest("safe.txt")

            self.assertFalse(registry.has("ws"))
            unavail = {item["workspace_id"]: item["reason"] for item in registry.unavailable()}
            self.assertIn("ws", unavail)
            with self.assertRaises(WorkspaceUnavailableError):
                registry.get("ws")

    def test_r31_01_root_directory_replaced_by_new_directory_inode_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            ws = tmp_path / "ws_swap"
            ws.mkdir()
            (ws / "data.txt").write_text("ORIGINAL\n", encoding="utf-8")

            reg_path = _write_registry_and_scopes(
                tmp_path / "config",
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            registry = WorkspaceRegistry(reg_path)
            spec = registry.get("ws")
            reader = WorkspaceReader(spec)
            self.assertTrue(registry.has("ws"))

            # Move original directory aside and create a brand-new directory at the same path
            ws_backup = tmp_path / "ws_swap_old"
            ws.rename(ws_backup)
            ws.mkdir()
            (ws / "data.txt").write_text("SWAPPED_INODE_SECRET\n", encoding="utf-8")

            with self.assertRaises(WorkspaceError):
                reader.read_file("data.txt")
            with self.assertRaises(WorkspaceError):
                reader.tree()

            self.assertFalse(registry.has("ws"))
            unavail = {item["workspace_id"]: item["reason"] for item in registry.unavailable()}
            self.assertEqual(unavail.get("ws"), "root_identity_changed")
            with self.assertRaises(WorkspaceUnavailableError):
                registry.get("ws")

    def test_r31_01_parent_directory_renamed_and_replaced_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            parent = tmp_path / "parent_dir"
            ws = parent / "project"
            ws.mkdir(parents=True)
            (ws / "note.txt").write_text("TRUSTED_PROJECT\n", encoding="utf-8")

            attacker_parent = tmp_path / "attacker_parent"
            attacker_ws = attacker_parent / "project"
            attacker_ws.mkdir(parents=True)
            (attacker_ws / "note.txt").write_text("ATTACKER_REPLACEMENT\n", encoding="utf-8")

            reg_path = _write_registry_and_scopes(
                tmp_path / "config",
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            registry = WorkspaceRegistry(reg_path)
            spec = registry.get("ws")
            reader = WorkspaceReader(spec)
            self.assertEqual(reader.read_file("note.txt")["content"], "TRUSTED_PROJECT")

            # Swap parent directory
            moved_parent = tmp_path / "parent_dir_moved"
            parent.rename(moved_parent)
            attacker_parent.rename(parent)

            with self.assertRaises(WorkspaceError):
                reader.read_file("note.txt")

            self.assertFalse(registry.has("ws"))
            unavail = {item["workspace_id"]: item["reason"] for item in registry.unavailable()}
            self.assertEqual(unavail.get("ws"), "root_identity_changed")

    def test_r31_01_permission_revocation_and_return_stage_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            ws = tmp_path / "ws_perm"
            ws.mkdir(mode=0o700)
            (ws / "doc.txt").write_text("CONFIDENTIAL_DOC\n", encoding="utf-8")

            reg_path = _write_registry_and_scopes(
                tmp_path / "config",
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            gw = MiddlewareGateway(str(reg_path), str(tmp_path / "state"))
            self.assertEqual(gw.read_file("ws", "doc.txt")["content"], "CONFIDENTIAL_DOC")

            # OS permission revocation (chmod 000) must make the workspace unavailable and fail-closed
            os.chmod(ws, 0)
            try:
                self.assertFalse(gw.registry.has("ws"))
                with self.assertRaises((WorkspaceError, WorkspaceUnavailableError)):
                    gw.read_file("ws", "doc.txt")
            finally:
                os.chmod(ws, 0o700)

    def test_r31_01_return_stage_detects_mid_operation_root_swap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            ws = tmp_path / "ws_mid"
            ws.mkdir()
            (ws / "item.txt").write_text("MID_READ_DATA\n", encoding="utf-8")
            reg_path = _write_registry_and_scopes(
                tmp_path / "config",
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read"],
                    }
                ],
            )
            registry = WorkspaceRegistry(reg_path)
            reader = WorkspaceReader(registry.get("ws"))
            root_id = getattr(reader, "root_identity", None)
            self.assertIsNotNone(root_id, "WorkspaceReader must bind root_identity at authorization time")
            self.assertGreater(root_id.dev, 0)
            self.assertGreater(root_id.ino, 0)

            orig_verify = getattr(reader, "_verify_return_stage", None)
            self.assertTrue(callable(orig_verify), "WorkspaceReader must validate root identity at return stage")

            ws_moved = tmp_path / "ws_mid_moved"
            ws_fake = tmp_path / "ws_mid_fake"
            ws_fake.mkdir()

            def swap_then_verify(root_fd: int, root_real: Path) -> None:
                ws.rename(ws_moved)
                ws_fake.rename(ws)
                orig_verify(root_fd, root_real)

            reader._verify_return_stage = swap_then_verify  # type: ignore[method-assign]
            with self.assertRaises(WorkspaceError):
                reader.read_file("item.txt")


# ============================================================================
# R3.1-02 — Git Unmerged Authorization
# ============================================================================


class TestR3102GitUnmergedAuthorization(unittest.TestCase):
    """Counterexamples and negative tests for R3.1-02 (Git Unmerged Authorization)."""

    def test_r31_02_unmerged_in_denied_scope_and_sensitive_name_never_disclosed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_unmerged"
            _init_repo(repo)
            (repo / "denied_dir").mkdir()

            sha1 = _hash_blob(repo, b"base version\n")
            sha2 = _hash_blob(repo, b"ours version\n")
            sha3 = _hash_blob(repo, b"theirs version\n")

            index_lines = []
            for path_str in ("denied_dir/secret_conflict.txt", "src/.env", "src/ok_conflict.txt"):
                (repo / path_str).parent.mkdir(parents=True, exist_ok=True)
                (repo / path_str).write_text("worktree conflict\n", encoding="utf-8")
                index_lines.append(f"100644 {sha1} 1\t{path_str}")
                index_lines.append(f"100644 {sha2} 2\t{path_str}")
                index_lines.append(f"100644 {sha3} 3\t{path_str}")
            _git(repo, "update-index", "--index-info", input_bytes=("\n".join(index_lines) + "\n").encode("utf-8"))

            scopes_file = tmp_path / "root_scopes.json"
            scopes_file.write_text(
                json.dumps(
                    {
                        "schema_version": "root-scopes-v1",
                        "scopes": [
                            {"scope_id": "root", "root": str(repo), "authority": _full_authority()},
                            {
                                "scope_id": "denied-sub",
                                "root": str(repo / "denied_dir"),
                                "authority": _full_authority(
                                    content_read=False,
                                    metadata_read=False,
                                    text_search=False,
                                    git_observe=False,
                                ),
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scopes = RootScopeRegistry(scopes_file)
            policy = PathPolicy.beneath(scopes, repo)
            snap = ReadOnlyGit(str(repo), path_policy=policy).diff()

            omitted_paths = set(snap["omitted"]["paths"])
            reasons = snap["omitted"]["reasons"]
            serialized = json.dumps(snap)

            # Denied scope path and central sensitive path must NEVER appear anywhere in output
            self.assertNotIn("denied_dir/secret_conflict.txt", omitted_paths)
            self.assertNotIn("secret_conflict.txt", serialized)
            self.assertNotIn("denied_dir", serialized)
            self.assertNotIn("src/.env", omitted_paths)
            self.assertNotIn(".env", serialized)

            # Authorized conflict file IS reported as unmerged
            self.assertIn("src/ok_conflict.txt", omitted_paths)
            self.assertGreaterEqual(reasons.get(SCOPE_DENIED, 0), 1)
            self.assertGreaterEqual(reasons.get(REFUSED_NAME, 0), 1)
            self.assertEqual(reasons.get(UNMERGED, 0), 1)
            self.assertFalse(snap["complete"])

    def test_r31_02_unmerged_symlinks_hardlinks_deletions_and_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_unmerged_edges"
            _init_repo(repo)
            (repo / "denied_area").mkdir()
            (repo / "denied_area" / "secret.txt").write_text("TOP_SECRET\n", encoding="utf-8")
            (repo / ".env").write_text("API_KEY=FAKE\n", encoding="utf-8")

            sha1 = _hash_blob(repo, b"stage1\n")
            sha2 = _hash_blob(repo, b"stage2\n")

            (repo / "src" / "link_to_env").symlink_to("../.env")
            (repo / "src" / "link_to_denied").symlink_to("../denied_area/secret.txt")

            hl_target = repo / "src" / "hardlinked.txt"
            hl_target.write_text("hardlink content\n", encoding="utf-8")
            os.link(hl_target, repo / "src" / "hardlinked_peer.txt")

            (repo / "src" / "swapped_parent").symlink_to("../denied_area")

            entries = [
                "src/link_to_env",
                "src/link_to_denied",
                "src/hardlinked.txt",
                "denied_area/deleted_conflict.txt",
                "src/deleted_conflict.txt",
                "src/swapped_parent/child.txt",
            ]
            lines = []
            for p in entries:
                lines.append(f"100644 {sha1} 1\t{p}")
                lines.append(f"100644 {sha2} 2\t{p}")
            _git(repo, "update-index", "--index-info", input_bytes=("\n".join(lines) + "\n").encode("utf-8"))

            scopes_file = tmp_path / "root_scopes.json"
            scopes_file.write_text(
                json.dumps(
                    {
                        "schema_version": "root-scopes-v1",
                        "scopes": [
                            {"scope_id": "root", "root": str(repo), "authority": _full_authority()},
                            {
                                "scope_id": "denied-area",
                                "root": str(repo / "denied_area"),
                                "authority": _full_authority(
                                    content_read=False,
                                    metadata_read=False,
                                    text_search=False,
                                    git_observe=False,
                                ),
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scopes = RootScopeRegistry(scopes_file)
            policy = PathPolicy.beneath(scopes, repo)
            snap = ReadOnlyGit(str(repo), path_policy=policy).diff()

            omitted_paths = set(snap["omitted"]["paths"])
            reasons = snap["omitted"]["reasons"]
            serialized = json.dumps(snap)

            self.assertNotIn("denied_area/deleted_conflict.txt", omitted_paths)
            self.assertNotIn("denied_area", serialized)
            self.assertNotIn(".env", serialized)
            self.assertNotIn("src/link_to_env", omitted_paths)
            self.assertNotIn("src/link_to_denied", omitted_paths)

            self.assertIn("src/deleted_conflict.txt", omitted_paths)
            self.assertGreaterEqual(reasons.get(REFUSED_NAME, 0), 1)
            self.assertGreaterEqual(reasons.get(SCOPE_DENIED, 0), 2)
            self.assertGreaterEqual(reasons.get(HARD_LINK, 0), 1)


# ============================================================================
# R3.1-03 — Git Old Blob and Output Budget
# ============================================================================


class TestR3103GitOldBlobAndOutputBudget(unittest.TestCase):
    """Counterexamples and boundary tests for R3.1-03 (Git Old Blob and Output Budget)."""

    def test_r31_03_oversized_old_blob_deletion_checked_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_old_blob"
            _init_repo(repo)

            big_file = repo / "src" / "big_deleted.txt"
            big_file.write_text(("A" * 63 + "\n") * 512, encoding="utf-8")  # 32,768 bytes
            _git(repo, "add", "src/big_deleted.txt")
            _git(repo, "commit", "-q", "-m", "add big file")
            big_file.unlink()

            orig_index_bytes = (repo / ".git" / "index").read_bytes()

            budgets = DiffBudgets(max_file_bytes=4096, max_total_bytes=16384)
            snap = ReadOnlyGit(str(repo), budgets=budgets).diff()

            self.assertEqual(snap["omitted"]["reasons"].get(OVER_BUDGET, 0), 1)
            self.assertIn("src/big_deleted.txt", snap["omitted"]["paths"])
            self.assertFalse(snap["complete"])
            self.assertNotIn("big_deleted.txt", snap["diff"])
            self.assertEqual((repo / ".git" / "index").read_bytes(), orig_index_bytes)

    def test_r31_03_cumulative_old_and_new_blob_budget_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_cum_budget"
            _init_repo(repo)

            for name in ("a.txt", "b.txt", "c.txt"):
                (repo / "src" / name).write_text("X" * 3000 + "\n", encoding="utf-8")
            _git(repo, "add", "src/a.txt", "src/b.txt", "src/c.txt")
            _git(repo, "commit", "-q", "-m", "three files")

            # Delete a.txt (old=3001, new=0), delete b.txt (old=3001, new=0), modify c.txt (old=3001, new=3005)
            (repo / "src" / "a.txt").unlink()
            (repo / "src" / "b.txt").unlink()
            (repo / "src" / "c.txt").write_text("Y" * 3004 + "\n", encoding="utf-8")

            budgets = DiffBudgets(max_file_bytes=4000, max_total_bytes=6500)
            snap = ReadOnlyGit(str(repo), budgets=budgets).diff()

            self.assertGreaterEqual(snap["omitted"]["reasons"].get(OVER_BUDGET, 0), 1)
            self.assertFalse(snap["complete"])

    def test_r31_03_zlib_zero_blob_sparse_file_binary_and_abnormal_object(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_special_blobs"
            _init_repo(repo)

            # 1. Highly compressible 1 MiB zero blob in Git index, deleted in worktree
            zero_sha = _hash_blob(repo, b"\x00" * (1024 * 1024))
            _git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{zero_sha},src/zero_blob.bin",
            )

            # 2. Sparse file in worktree (2 MiB apparent size)
            sparse_path = repo / "src" / "sparse.bin"
            sparse_sha = _hash_blob(repo, b"small\n")
            _git(repo, "update-index", "--add", "--cacheinfo", f"100644,{sparse_sha},src/sparse.bin")
            with open(sparse_path, "wb") as f:
                f.truncate(2 * 1024 * 1024)

            # 3. Abnormal Git object: index entry pointing to HEAD's tree SHA with mode 100644
            tree_sha = _git(repo, "rev-parse", "HEAD^{tree}").stdout.decode("ascii").strip()
            (repo / "src" / "bad_obj.txt").write_text("modified\n", encoding="utf-8")
            _git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{tree_sha},src/bad_obj.txt",
            )

            budgets = DiffBudgets(max_file_bytes=65536, max_total_bytes=131072)
            snap = ReadOnlyGit(str(repo), budgets=budgets).diff()

            omitted_paths = set(snap["omitted"]["paths"])
            reasons = snap["omitted"]["reasons"]
            self.assertIn("src/zero_blob.bin", omitted_paths)
            self.assertIn("src/sparse.bin", omitted_paths)
            self.assertIn("src/bad_obj.txt", omitted_paths)
            self.assertGreaterEqual(reasons.get(OVER_BUDGET, 0), 2)
            self.assertFalse(snap["complete"])

    def test_r31_03_streaming_diff_output_budget_marks_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_diff_stream"
            _init_repo(repo)
            # Write a 600 KiB modification (under 4 MiB max_file_bytes, but > 200,000 MAX_DIFF_CHARS)
            (repo / "src" / "base.txt").write_text(
                ("M" * 99 + "\n") * 6200,
                encoding="utf-8",
            )
            # In r3.1, DiffBudgets supports max_diff_bytes and build_unstaged_diff streams diff output
            # with a bounded byte cap rather than capturing the entire stdout into memory via subprocess.run.
            try:
                budgets = DiffBudgets(max_file_bytes=1 << 20, max_total_bytes=2 << 20, max_diff_bytes=4096)
                expected_cap = 4096
            except TypeError:
                budgets = DiffBudgets(max_file_bytes=1 << 20, max_total_bytes=2 << 20)
                expected_cap = 4096
            snap = ReadOnlyGit(str(repo), budgets=budgets).diff()
            self.assertLessEqual(len(snap["diff"].encode("utf-8")), expected_cap)
            self.assertTrue(snap["truncated"])
            self.assertFalse(snap["complete"])


# ============================================================================
# R3.1-04 — UTF-8 Byte Budget
# ============================================================================


class TestR3104Utf8ByteBudget(unittest.TestCase):
    """Counterexamples and boundary tests for R3.1-04 (UTF-8 Byte Budget in mcp_sdk.py)."""

    def test_r31_04_session_bootstrap_enforces_utf8_byte_budget_on_chinese_and_emoji(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            ws = tmp_path / "ws_utf8"
            _init_repo(ws)
            # 10,000 Chinese chars = 30,000 UTF-8 bytes; 4,000 fire emojis = 16,000 UTF-8 bytes
            (ws / "README.md").write_text("中" * 10000, encoding="utf-8")
            (ws / "AGENTS.md").write_text("🔥" * 4000, encoding="utf-8")
            (ws / "CLAUDE.md").write_text("e\u0301" * 5000 + "\n", encoding="utf-8")

            config_dir = tmp_path / "config"
            reg_path = _write_registry_and_scopes(
                config_dir,
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            (config_dir / "workspace-contexts").mkdir(parents=True, exist_ok=True)
            (config_dir / "workspace-contexts" / "ws.json").write_text(
                json.dumps(
                    {
                        "schema_version": "workspace-context-profile-v1",
                        "workspace_id": "ws",
                        "entrypoints": ["README.md", "AGENTS.md", "CLAUDE.md"],
                        "max_files": 4,
                        "max_total_bytes": 24000,
                    }
                ),
                encoding="utf-8",
            )

            server = create_session_read_server(str(reg_path), str(tmp_path / "state"))
            payload = asyncio.run(
                _call_mcp_tool(
                    server,
                    "uam_session_bootstrap",
                    {"workspace_id": "ws", "max_bytes": 8000},
                )
            )

            entrypoints = payload["context_profile"]["entrypoints"]
            self.assertGreaterEqual(len(entrypoints), 1)
            total_utf8_bytes = 0
            for ep in entrypoints:
                encoded = ep["content"].encode("utf-8")
                self.assertLessEqual(len(encoded), 8000)
                self.assertNotIn("\ufffd", ep["content"])
                total_utf8_bytes += len(encoded)

            self.assertLessEqual(total_utf8_bytes, 8000)
            self.assertTrue(entrypoints[0]["truncated"])
            self.assertTrue(payload["context_profile"].get("truncated"))

    def test_r31_04_session_bootstrap_boundary_lengths_and_omitted_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            for delta, expect_ep_trunc in ((-1, False), (0, False), (1, True)):
                ws = tmp_path / f"ws_bound_{delta}"
                _init_repo(ws)
                budget = 300
                prefix = "中" * 99  # 297 bytes
                tail = {
                    -1: "ab",
                    0: "abc",
                    1: "abcd",
                }[delta]
                (ws / "README.md").write_text(prefix + tail, encoding="utf-8")

                config_dir = tmp_path / f"config_{delta}"
                reg_path = _write_registry_and_scopes(
                    config_dir,
                    [
                        {
                            "workspace_id": "ws",
                            "root": str(ws),
                            "kind": "git-repository",
                            "capabilities": ["filesystem.read", "git.observe"],
                        }
                    ],
                )
                (config_dir / "workspace-contexts").mkdir(parents=True, exist_ok=True)
                (config_dir / "workspace-contexts" / "ws.json").write_text(
                    json.dumps(
                        {
                            "schema_version": "workspace-context-profile-v1",
                            "workspace_id": "ws",
                            "entrypoints": ["README.md"],
                            "max_files": 4,
                            "max_total_bytes": 24000,
                        }
                    ),
                    encoding="utf-8",
                )

                server = create_session_read_server(str(reg_path), str(tmp_path / f"state_{delta}"))
                payload = asyncio.run(
                    _call_mcp_tool(
                        server,
                        "uam_session_bootstrap",
                        {"workspace_id": "ws", "max_bytes": budget},
                    )
                )
                ep = payload["context_profile"]["entrypoints"][0]
                self.assertLessEqual(len(ep["content"].encode("utf-8")), budget)
                self.assertEqual(ep["truncated"], expect_ep_trunc)
                self.assertEqual(bool(payload["context_profile"].get("truncated")), expect_ep_trunc)

            # Exact budget exhaustion before subsequent existing entrypoint must mark truncated = True
            ws_exhaust = tmp_path / "ws_exhaust"
            _init_repo(ws_exhaust)
            (ws_exhaust / "README.md").write_text("A" * 4000, encoding="utf-8")
            (ws_exhaust / "AGENTS.md").write_text("B" * 4000, encoding="utf-8")
            (ws_exhaust / "CLAUDE.md").write_text("C" * 100, encoding="utf-8")

            config_ex = tmp_path / "config_ex"
            reg_ex = _write_registry_and_scopes(
                config_ex,
                [
                    {
                        "workspace_id": "ws",
                        "root": str(ws_exhaust),
                        "kind": "git-repository",
                        "capabilities": ["filesystem.read", "git.observe"],
                    }
                ],
            )
            (config_ex / "workspace-contexts").mkdir(parents=True, exist_ok=True)
            (config_ex / "workspace-contexts" / "ws.json").write_text(
                json.dumps(
                    {
                        "schema_version": "workspace-context-profile-v1",
                        "workspace_id": "ws",
                        "entrypoints": ["README.md", "AGENTS.md", "CLAUDE.md"],
                        "max_files": 4,
                        "max_total_bytes": 8000,
                    }
                ),
                encoding="utf-8",
            )
            server_ex = create_session_read_server(str(reg_ex), str(tmp_path / "state_ex"))
            payload_ex = asyncio.run(
                _call_mcp_tool(
                    server_ex,
                    "uam_session_bootstrap",
                    {"workspace_id": "ws", "max_bytes": 8000},
                )
            )
            eps = payload_ex["context_profile"]["entrypoints"]
            self.assertEqual(sum(len(e["content"].encode("utf-8")) for e in eps), 8000)
            self.assertEqual(len(eps), 2)
            self.assertTrue(payload_ex["context_profile"].get("truncated"))


# ============================================================================
# R3.1-05 — Compatibility & Evidence Errata
# ============================================================================


class TestR3105CompatibilityAndErrata(unittest.TestCase):
    """Tests for R3.1-05 (gitlink skipped cleanly vs unsupported_entry)."""

    def test_r31_05_gitlink_skipped_cleanly_and_complete_true(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_gitlink"
            _init_repo(repo)
            commit_sha = _git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
            _git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{commit_sha},src/submod",
            )

            snap = ReadOnlyGit(str(repo)).diff()
            self.assertEqual(snap["omitted"]["reasons"].get(UNSUPPORTED_ENTRY, 0), 0)
            self.assertTrue(snap["complete"])

    def test_r31_05_unsupported_index_mode_marks_incomplete_after_auth(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            repo = tmp_path / "repo_unsupported_mode"
            _init_repo(repo)
            sha = _hash_blob(repo, b"content\n")

            # Construct synthetic ls-files -s -z --debug listing with mode 100600 on both an allowed and a denied path
            listing = (
                f"100600 {sha} 0\tsrc/base.txt\0"
                "  ctime: 1:0\n  mtime: 1:0\n  dev: 1\tino: 1\n  uid: 1\tgid: 1\n  size: 5\tflags: 0\n"
                f"100600 {sha} 0\tdenied_dir/secret.txt\0"
                "  ctime: 1:0\n  mtime: 1:0\n  dev: 1\tino: 2\n  uid: 1\tgid: 1\n  size: 5\tflags: 0\n"
            ).encode("utf-8")

            (repo / "denied_dir").mkdir()
            scopes_file = tmp_path / "root_scopes.json"
            scopes_file.write_text(
                json.dumps(
                    {
                        "schema_version": "root-scopes-v1",
                        "scopes": [
                            {"scope_id": "root", "root": str(repo), "authority": _full_authority()},
                            {
                                "scope_id": "denied-sub",
                                "root": str(repo / "denied_dir"),
                                "authority": _full_authority(
                                    content_read=False,
                                    metadata_read=False,
                                    text_search=False,
                                    git_observe=False,
                                ),
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scopes = RootScopeRegistry(scopes_file)
            policy = PathPolicy.beneath(scopes, repo)
            built = build_unstaged_diff(
                root=repo,
                listing=listing,
                index_mtime_ns=None,
                git_command=["git"],
                environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                objects_dir=repo / ".git" / "objects",
                object_format="sha1",
                policy=policy,
                budgets=DiffBudgets(),
            )
            report = built.omissions.report()
            self.assertNotIn("denied_dir/secret.txt", report["paths"])
            self.assertEqual(report["reasons"].get(SCOPE_DENIED, 0), 1)
            self.assertIn("src/base.txt", report["paths"])
            self.assertEqual(report["reasons"].get(UNSUPPORTED_ENTRY, 0), 1)


# ============================================================================
# R3.1-06 — Project-Level Git RootIdentity Wiring & Subprocess Open Closure
# ============================================================================


class TestR3106ProjectLevelGitRootIdentityClosure(unittest.TestCase):
    """Tests for R3.1-06: project-level Git RootIdentity binding, live authority
    re-verification, and subprocess workspace-open path replacement protection
    across project_reality, project_instances, bootstrap sibling, and discovery.
    """

    def _setup_two_instance_project(
        self, tmp_path: Path,
    ) -> tuple[Path, Path, Path, Path, MiddlewareGateway]:
        main_repo = tmp_path / "main_repo"
        cand_repo = tmp_path / "cand_repo"
        evil_repo = tmp_path / "evil_repo"

        _init_repo(main_repo, {"README.md": "main readme\n"}, branch="main")
        _init_repo(cand_repo, {"README.md": "cand readme\n"}, branch="cand-legit")
        _init_repo(evil_repo, {"README.md": "evil secret\n"}, branch="evil-branch")

        reg_path = _write_registry_and_scopes(
            tmp_path / "cfg",
            [
                {
                    "workspace_id": "ws-main",
                    "root": str(main_repo),
                    "label": "Main",
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                    "project_id": "proj-alpha",
                    "role": "canonical-main",
                    "lifecycle": "active",
                },
                {
                    "workspace_id": "ws-cand",
                    "root": str(cand_repo),
                    "label": "Candidate",
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                    "project_id": "proj-alpha",
                    "role": "candidate",
                    "lifecycle": "active",
                },
            ],
        )
        gw = MiddlewareGateway(str(reg_path), str(tmp_path / "state"))
        return main_repo, cand_repo, evil_repo, reg_path, gw

    def test_r31_06_project_observer_wires_bound_root_identity_and_live_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, _evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            inst = gw.projects.get_instance("ws-cand")
            self.assertIsNotNone(inst)
            assert inst is not None

            observer = gw.projects._observer(inst)
            spec = gw.registry.get("ws-cand")
            self.assertIsNotNone(spec.root_identity)
            self.assertEqual(observer.root_identity, spec.root_identity)
            self.assertIsNotNone(observer._authority_check)

            # Fail-closed when root_identity is missing on the WorkspaceSpec
            unbound_spec = replace(spec, root_identity=None)
            with mock.patch.object(gw.registry, "require_capability", return_value=unbound_spec):
                with self.assertRaises(WorkspaceError):
                    gw.projects._observer(inst)

            # Fail-closed when ReadOnlyGit is called with require_bound_identity=True but missing binding
            with self.assertRaises(WorkspaceError):
                ReadOnlyGit(str(cand_repo), require_bound_identity=True)

    def test_r31_06_project_reality_blocks_root_replacement_symlink_and_revocation(self) -> None:
        # 1. Root replaced between require_capability and ReadOnlyGit construction
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            evil_head = _git(evil_repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()

            orig_req = gw.registry.require_capability

            def swap_root_after_cap(workspace_id: str, capability: str):
                spec = orig_req(workspace_id, capability)
                retired = tmp_path / "cand_retired"
                if workspace_id == "ws-cand" and not retired.exists():
                    cand_repo.rename(retired)
                    evil_repo.rename(cand_repo)
                return spec

            with mock.patch.object(gw.registry, "require_capability", side_effect=swap_root_after_cap):
                reality = gw.project_reality("proj-alpha")

            by_id = {item["workspace_id"]: item for item in reality["instances"]}
            self.assertTrue(by_id["ws-main"]["observable"])
            self.assertFalse(by_id["ws-cand"]["observable"])
            self.assertEqual(reality["coverage"]["status"], "PARTIAL")
            self.assertEqual(reality["coverage"]["surfaces"]["active_candidate"], "not_observed")
            self.assertNotIn("evil-branch", json.dumps(reality))
            self.assertNotIn(evil_head, json.dumps(reality))

        # 2. External symlink swap between require_capability and ReadOnlyGit construction
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_req = gw.registry.require_capability

            def symlink_swap_after_cap(workspace_id: str, capability: str):
                spec = orig_req(workspace_id, capability)
                retired = tmp_path / "cand_retired_sym"
                if workspace_id == "ws-cand" and not retired.exists():
                    cand_repo.rename(retired)
                    cand_repo.symlink_to(evil_repo)
                return spec

            with mock.patch.object(gw.registry, "require_capability", side_effect=symlink_swap_after_cap):
                reality = gw.project_reality("proj-alpha")

            by_id = {item["workspace_id"]: item for item in reality["instances"]}
            self.assertFalse(by_id["ws-cand"]["observable"])
            self.assertNotIn("evil-branch", json.dumps(reality))

        # 3. Subprocess workspace-open replacement & .git swap mid-observation (after ReadOnlyGit.__init__)
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_run = subprocess.run
            swapped = False

            def swap_during_git_open(cmd, *args, **kwargs):
                nonlocal swapped
                if (
                    not swapped
                    and isinstance(cmd, list)
                    and "-C" in cmd
                    and cmd[cmd.index("-C") + 1] == str(cand_repo)
                    and "status" in cmd
                ):
                    swapped = True
                    # Replace .git inside cand_repo right as git status subprocess opens the workspace
                    retired_git = tmp_path / "cand_git_retired"
                    (cand_repo / ".git").rename(retired_git)
                    shutil.copytree(evil_repo / ".git", cand_repo / ".git")
                return orig_run(cmd, *args, **kwargs)

            with mock.patch("subprocess.run", side_effect=swap_during_git_open):
                reality = gw.project_reality("proj-alpha")

            self.assertTrue(swapped)
            by_id = {item["workspace_id"]: item for item in reality["instances"]}
            self.assertFalse(by_id["ws-cand"]["observable"])
            self.assertNotIn("evil-branch", json.dumps(reality))

        # 4. Capability / permission revocation between ReadOnlyGit.__init__ and status()
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            main_repo, cand_repo, _evil_repo, reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_status = ReadOnlyGit.status

            def revoke_before_status(git_self: ReadOnlyGit):
                if git_self.root == str(cand_repo):
                    reg_path.write_text(
                        json.dumps(
                            {
                                "registry_version": "uam-workspace-registry-v1",
                                "workspaces": [
                                    {
                                        "workspace_id": "ws-main",
                                        "root": str(main_repo),
                                        "label": "Main",
                                        "kind": "git-repository",
                                        "capabilities": ["filesystem.read", "git.observe"],
                                        "project_id": "proj-alpha",
                                        "role": "canonical-main",
                                        "lifecycle": "active",
                                    },
                                    {
                                        "workspace_id": "ws-cand",
                                        "root": str(cand_repo),
                                        "label": "Candidate",
                                        "kind": "git-repository",
                                        "capabilities": ["filesystem.read"],
                                        "project_id": "proj-alpha",
                                        "role": "candidate",
                                        "lifecycle": "active",
                                    },
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                return orig_status(git_self)

            with mock.patch.object(ReadOnlyGit, "status", revoke_before_status):
                # v0.6.1 (F-G2-2): a registry that is replaced while an answer is being assembled drops that answer
                # (ask again) instead of returning a half-revoked list. What the revoked capability guards is still
                # never returned, and the next answer is the revoked view.
                with self.assertRaises(RegistryGenerationChanged) as dropped:
                    gw.project_reality("proj-alpha")
            self.assertNotIn("cand-legit", str(dropped.exception))

            reality = gw.project_reality("proj-alpha")
            by_id = {item["workspace_id"]: item for item in reality["instances"]}
            self.assertTrue(by_id["ws-main"]["observable"])
            self.assertFalse(by_id["ws-cand"]["observable"])
            self.assertNotIn("cand-legit", json.dumps(reality))

    def test_r31_06_project_instances_blocks_root_replacement_symlink_and_revocation(self) -> None:
        # 1. Root replacement between require_capability and ReadOnlyGit in worktree_discovery
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_req = gw.registry.require_capability

            def swap_cand_root(workspace_id: str, capability: str):
                spec = orig_req(workspace_id, capability)
                retired = tmp_path / "cand_old"
                if workspace_id == "ws-cand" and not retired.exists():
                    cand_repo.rename(retired)
                    evil_repo.rename(cand_repo)
                return spec

            with mock.patch.object(gw.registry, "require_capability", side_effect=swap_cand_root):
                info = gw.project_instances("proj-alpha")

            self.assertIn("ws-cand", info["worktree_discovery"]["not_observed_instances"])
            self.assertFalse(info["worktree_discovery"]["complete"])
            self.assertNotIn("evil-branch", json.dumps(info))

        # 2. External symlink replacement in worktree_discovery
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_req = gw.registry.require_capability

            def symlink_cand_root(workspace_id: str, capability: str):
                spec = orig_req(workspace_id, capability)
                retired = tmp_path / "cand_old_sym"
                if workspace_id == "ws-cand" and not retired.exists():
                    cand_repo.rename(retired)
                    cand_repo.symlink_to(evil_repo)
                return spec

            with mock.patch.object(gw.registry, "require_capability", side_effect=symlink_cand_root):
                info = gw.project_instances("proj-alpha")

            self.assertIn("ws-cand", info["worktree_discovery"]["not_observed_instances"])
            self.assertFalse(info["worktree_discovery"]["complete"])
            self.assertNotIn("evil-branch", json.dumps(info))

        # 3. Permission revocation (chmod 0o000) during worktree_list subprocess execution
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, _evil_repo, _reg_path, gw = self._setup_two_instance_project(tmp_path)
            orig_run = subprocess.run

            def chmod_during_worktree_list(cmd, *args, **kwargs):
                res = orig_run(cmd, *args, **kwargs)
                if (
                    isinstance(cmd, list)
                    and "-C" in cmd
                    and cmd[cmd.index("-C") + 1] == str(cand_repo)
                    and "worktree" in cmd
                ):
                    os.chmod(cand_repo, 0o000)
                return res

            try:
                with mock.patch("subprocess.run", side_effect=chmod_during_worktree_list):
                    info = gw.project_instances("proj-alpha")
                self.assertIn("ws-cand", info["worktree_discovery"]["not_observed_instances"])
                self.assertFalse(info["worktree_discovery"]["complete"])
                self.assertNotIn("cand-legit", json.dumps(info["discovered_worktrees"]))
            finally:
                os.chmod(cand_repo, 0o755)

    def test_r31_06_bootstrap_sibling_blocks_root_replacement_symlink_and_revocation(self) -> None:
        # 1. Bootstrap on ws-main while sibling ws-cand root is replaced after require_capability
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, reg_path, _gw = self._setup_two_instance_project(tmp_path)
            server = create_session_read_server(str(reg_path), str(tmp_path / "state_mcp1"))
            orig_req = WorkspaceRegistry.require_capability

            def swap_sibling_root(reg_self: WorkspaceRegistry, workspace_id: str, capability: str):
                spec = orig_req(reg_self, workspace_id, capability)
                if workspace_id == "ws-cand" and cand_repo.exists() and not (tmp_path / "cand_gone").exists():
                    cand_repo.rename(tmp_path / "cand_gone")
                    evil_repo.rename(cand_repo)
                return spec

            with mock.patch.object(WorkspaceRegistry, "require_capability", swap_sibling_root):
                payload = asyncio.run(
                    _call_mcp_tool(server, "uam_session_bootstrap", {"workspace_id": "ws-main"})
                )

            proj_ctx = payload["project"]
            self.assertEqual(proj_ctx["coverage"]["status"], "PARTIAL")
            self.assertEqual(proj_ctx["coverage"]["surfaces"]["active_candidate"], "not_observed")
            siblings = {s["workspace_id"]: s for s in proj_ctx["other_instances"]}
            self.assertFalse(siblings["ws-cand"]["observable"])
            self.assertEqual(siblings["ws-cand"]["head"], "")
            self.assertNotIn("evil-branch", json.dumps(payload))

        # 2. Bootstrap on ws-main while sibling ws-cand is replaced with an external symlink
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, evil_repo, reg_path, _gw = self._setup_two_instance_project(tmp_path)
            server = create_session_read_server(str(reg_path), str(tmp_path / "state_mcp2"))
            orig_req = WorkspaceRegistry.require_capability

            def symlink_sibling_root(reg_self: WorkspaceRegistry, workspace_id: str, capability: str):
                spec = orig_req(reg_self, workspace_id, capability)
                if workspace_id == "ws-cand" and not cand_repo.is_symlink():
                    cand_repo.rename(tmp_path / "cand_gone_sym")
                    cand_repo.symlink_to(evil_repo)
                return spec

            with mock.patch.object(WorkspaceRegistry, "require_capability", symlink_sibling_root):
                payload = asyncio.run(
                    _call_mcp_tool(server, "uam_session_bootstrap", {"workspace_id": "ws-main"})
                )

            proj_ctx = payload["project"]
            self.assertEqual(proj_ctx["coverage"]["status"], "PARTIAL")
            siblings = {s["workspace_id"]: s for s in proj_ctx["other_instances"]}
            self.assertFalse(siblings["ws-cand"]["observable"])
            self.assertEqual(siblings["ws-cand"]["head"], "")
            self.assertNotIn("evil-branch", json.dumps(payload))

        # 3. Bootstrap on ws-main while sibling ws-cand has permissions revoked during status subprocess
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            _main_repo, cand_repo, _evil_repo, reg_path, _gw = self._setup_two_instance_project(tmp_path)
            server = create_session_read_server(str(reg_path), str(tmp_path / "state_mcp3"))
            orig_run = subprocess.run

            def revoke_sibling_perm(cmd, *args, **kwargs):
                res = orig_run(cmd, *args, **kwargs)
                if (
                    isinstance(cmd, list)
                    and "-C" in cmd
                    and cmd[cmd.index("-C") + 1] == str(cand_repo)
                    and "status" in cmd
                ):
                    os.chmod(cand_repo, 0o000)
                return res

            try:
                with mock.patch("subprocess.run", side_effect=revoke_sibling_perm):
                    payload = asyncio.run(
                        _call_mcp_tool(server, "uam_session_bootstrap", {"workspace_id": "ws-main"})
                    )
                proj_ctx = payload["project"]
                self.assertEqual(proj_ctx["coverage"]["status"], "PARTIAL")
                siblings = {s["workspace_id"]: s for s in proj_ctx["other_instances"]}
                self.assertFalse(siblings["ws-cand"]["observable"])
                self.assertEqual(siblings["ws-cand"]["head"], "")
                self.assertNotIn("cand-legit", json.dumps(proj_ctx["other_instances"]))
            finally:
                os.chmod(cand_repo, 0o755)

    def test_r31_06_discovery_git_enrichment_binds_root_identity_and_blocks_swap_or_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td).resolve()
            scope_root = tmp_path / "code"
            scope_root.mkdir()
            repo_a = scope_root / "repo_a"
            evil_repo = tmp_path / "evil_outside"
            _init_repo(repo_a, {"README.md": "a\n"}, branch="legit-a")
            _init_repo(evil_repo, {"README.md": "evil\n"}, branch="evil-discovered")

            reg_path = _write_registry_and_scopes(
                tmp_path / "cfg_disc",
                [],
                [
                    {"scope_id": "code", "root": str(scope_root), "authority": _full_authority()},
                ],
            )
            gw = MiddlewareGateway(
                str(reg_path),
                str(tmp_path / "state"),
            )

            # Swap repo_a with evil_repo right after status() starts during discovery enrichment
            orig_status = ReadOnlyGit.status

            def swap_during_discovery_status(git_self: ReadOnlyGit):
                res = orig_status(git_self)
                if git_self.root == str(repo_a):
                    repo_a.rename(tmp_path / "repo_a_retired")
                    evil_repo.rename(repo_a)
                return res

            with mock.patch.object(ReadOnlyGit, "status", swap_during_discovery_status):
                inv = gw.discovery.discover_scope("code", enrich_git=True)

            self.assertNotIn("evil-discovered", json.dumps(inv))
            self.assertNotIn("legit-a", json.dumps(inv))
            self.assertEqual(inv["git_enrichment"]["enriched_instances"], 0)
            self.assertTrue(inv["git_enrichment"]["partial"])

