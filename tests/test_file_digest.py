"""``file_digest``: the raw-byte SHA-256 of a file the caller may read, and nothing else.

The digest answers "is this the file I was shown?" for evidence that must not be read as text (a
binary, a file over the read limit, a preserved artifact). It is held to the standard of the read
it stands in for:

* authorised exactly like ``read_file`` (same path rules, secret names, nested-scope authority and
  revocation), because a digest is a fact about the content;
* streamed in bounded chunks, bounded in bytes and in time, so a huge or slow file cannot hold the
  service;
* change-detecting: a digest is only claimed for a file that was the same file, with the same size
  and modification time, before, during and after hashing. Otherwise the answer says it is
  incomplete and why, and carries no digest at all.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from universal_agent_middleware import file_digest
from universal_agent_middleware.errors import PathPolicyError, ScopeAuthorityError, WorkspaceError
from universal_agent_middleware.file_digest import CHUNK_BYTES, digest_file
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.models import WorkspaceSpec
from universal_agent_middleware.root_scope import RootScopeAuthority
from universal_agent_middleware.workspace import WorkspaceReader

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

RAW = b"\x00\xff\xfe binary \x80 evidence \n\r\n" * 700
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
PARENT = dict(
    discover=True, metadata_read=True, content_read=True, text_search=True,
    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
)
SECRET_PATHS = [".env", ".env.production", "id_rsa", "secrets.json", "keys/server.pem", ".git/config", "a/.ssh/known_hosts"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TemporaryCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()

    def write(self, rel: str, data: bytes) -> Path:
        target = self.base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target


class ClockStub:
    """A monotonic clock that advances by a fixed step every time it is read."""

    def __init__(self, step: float) -> None:
        self.now, self.step = 0.0, step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


class DigestContentTests(TemporaryCase):
    def test_the_digest_is_the_sha256_of_the_raw_bytes(self) -> None:
        target = self.write("evidence.bin", RAW)
        result = digest_file(target)
        self.assertIs(result["complete"], True)
        self.assertEqual(result["sha256"], sha256(RAW))
        self.assertEqual(result["algorithm"], "sha256")
        self.assertEqual((result["size_bytes"], result["bytes_hashed"]), (len(RAW), len(RAW)))
        self.assertIsNone(result["reason"])

    def test_an_empty_file_has_the_well_known_digest(self) -> None:
        result = digest_file(self.write("empty", b""))
        self.assertEqual((result["complete"], result["sha256"], result["size_bytes"]), (True, EMPTY_SHA256, 0))

    def test_the_modification_time_is_the_one_the_filesystem_reports(self) -> None:
        target = self.write("evidence.bin", RAW)
        os.utime(target, ns=(1_700_000_000_123_456_789, 1_700_000_000_123_456_789))
        result = digest_file(target)
        self.assertEqual(result["mtime_ns"], 1_700_000_000_123_456_789)
        self.assertEqual(datetime.fromisoformat(result["modified_at"]),
                         datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=timezone.utc))

    def test_no_content_is_ever_returned(self) -> None:
        result = digest_file(self.write("evidence.bin", RAW))
        self.assertEqual(set(result), {"algorithm", "complete", "sha256", "size_bytes", "bytes_hashed", "mtime_ns",
                                       "modified_at", "permission_check", "reason"})
        self.assertNotIn(RAW[:20].decode("latin-1"), json.dumps(result))

    def test_a_file_larger_than_a_chunk_is_streamed_in_bounded_reads(self) -> None:
        one_mib = 1024 * 1024  # stated here, not taken from the module: the bound is the property under test
        data = os.urandom(3 * one_mib + 17)
        target = self.write("big.bin", data)
        sizes: list[int] = []
        real = file_digest._read_chunk

        def spy(descriptor: int, size: int) -> bytes:
            sizes.append(size)
            return real(descriptor, size)

        with mock.patch.object(file_digest, "_read_chunk", spy):
            result = digest_file(target)
        self.assertEqual(result["sha256"], sha256(data))
        self.assertGreaterEqual(len(sizes), 4)
        self.assertLessEqual(max(sizes), one_mib)


class DigestBoundsTests(TemporaryCase):
    def test_a_file_known_to_exceed_the_byte_limit_is_not_read_at_all(self) -> None:
        target = self.write("big.bin", b"x" * 5000)
        with mock.patch.object(file_digest, "_read_chunk", side_effect=AssertionError("must not read")):
            result = digest_file(target, max_bytes=1000)
        self.assertEqual((result["complete"], result["sha256"], result["reason"]), (False, None, "byte_limit"))
        self.assertEqual((result["size_bytes"], result["bytes_hashed"]), (5000, 0))

    def test_a_file_that_grows_past_the_byte_limit_while_hashing_is_cut_off(self) -> None:
        target = self.write("grow.bin", b"x" * 100)
        with mock.patch.object(file_digest, "_read_chunk", side_effect=[b"y" * 200, b""]):
            result = digest_file(target, max_bytes=150)
        self.assertEqual((result["complete"], result["sha256"], result["reason"]), (False, None, "byte_limit"))

    def test_a_file_exactly_at_the_byte_limit_is_hashed(self) -> None:
        data = b"x" * 1000
        result = digest_file(self.write("exact.bin", data), max_bytes=1000)
        self.assertEqual((result["complete"], result["sha256"]), (True, sha256(data)))

    def test_hashing_stops_at_the_time_limit_and_claims_no_digest(self) -> None:
        target = self.write("slow.bin", os.urandom(3 * CHUNK_BYTES))
        result = digest_file(target, max_seconds=10.0, clock=ClockStub(4.0))
        self.assertEqual((result["complete"], result["sha256"], result["reason"]), (False, None, "time_limit"))
        self.assertLess(result["bytes_hashed"], 3 * CHUNK_BYTES)

    def test_a_fast_read_under_the_time_limit_completes(self) -> None:
        data = os.urandom(2 * CHUNK_BYTES)
        result = digest_file(self.write("fast.bin", data), max_seconds=10.0, clock=ClockStub(0.001))
        self.assertEqual((result["complete"], result["sha256"]), (True, sha256(data)))


class ChangeDetectionTests(TemporaryCase):
    """A digest is claimed only for a file that did not change while it was being hashed."""

    def after_first_chunk(self, action) -> Any:
        real = file_digest._read_chunk
        calls = {"n": 0}

        def read(descriptor: int, size: int) -> bytes:
            chunk = real(descriptor, size)
            calls["n"] += 1
            if calls["n"] == 1:
                action()
            return chunk

        return mock.patch.object(file_digest, "_read_chunk", read)

    def assert_changed(self, result: dict[str, Any]) -> None:
        self.assertEqual((result["complete"], result["sha256"], result["reason"]),
                         (False, None, "changed_while_hashing"))

    def test_an_append_during_hashing_is_detected(self) -> None:
        target = self.write("log.bin", os.urandom(2 * CHUNK_BYTES))

        def append() -> None:
            with target.open("ab") as handle:
                handle.write(b"late")

        with self.after_first_chunk(append):
            self.assert_changed(digest_file(target))

    def test_a_same_size_rewrite_during_hashing_is_detected_by_the_modification_time(self) -> None:
        data = os.urandom(2 * CHUNK_BYTES)
        target = self.write("same.bin", data)
        before = target.stat()

        def rewrite_same_size() -> None:
            target.write_bytes(bytes(len(data)))
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))

        with self.after_first_chunk(rewrite_same_size):
            self.assert_changed(digest_file(target))

    def test_a_replacement_by_rename_during_hashing_is_detected(self) -> None:
        data = os.urandom(2 * CHUNK_BYTES)
        target = self.write("swap.bin", data)
        before = target.stat()

        def replace_with_identical_copy() -> None:
            copy = self.write("swap.new", data)
            os.utime(copy, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(copy, target)

        with self.after_first_chunk(replace_with_identical_copy):
            self.assert_changed(digest_file(target))

    def test_a_replacement_between_the_stat_and_the_open_is_detected(self) -> None:
        data = os.urandom(CHUNK_BYTES // 2)
        target = self.write("swap.bin", data)
        before = target.stat()
        real_open = file_digest._open_readonly

        def replace_then_open(path: Path) -> int:
            copy = self.write("swap.new", data)
            os.utime(copy, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(copy, path)
            return real_open(path)

        with mock.patch.object(file_digest, "_open_readonly", replace_then_open), \
                mock.patch.object(file_digest, "_read_chunk", side_effect=AssertionError("must not read")):
            self.assert_changed(digest_file(target))

    def test_a_file_replaced_by_a_fifo_before_the_open_is_not_read(self) -> None:
        target = self.write("pipe.bin", b"data")
        real_open = file_digest._open_readonly

        def fifo_then_open(path: Path) -> int:
            path.unlink()
            os.mkfifo(path)
            return real_open(path)

        with mock.patch.object(file_digest, "_open_readonly", fifo_then_open), \
                mock.patch.object(file_digest, "_read_chunk", side_effect=AssertionError("must not read")):
            self.assert_changed(digest_file(target))

    def test_a_file_removed_while_it_was_being_hashed_is_a_change_not_a_crash(self) -> None:
        target = self.write("vanish.bin", os.urandom(2 * CHUNK_BYTES))
        with self.after_first_chunk(target.unlink):
            self.assert_changed(digest_file(target))

    def test_a_premature_end_of_file_is_not_a_complete_digest(self) -> None:
        data = os.urandom(2 * CHUNK_BYTES)
        target = self.write("short.bin", data)
        real = file_digest._read_chunk
        calls = {"n": 0}

        def stop_after_one_chunk(descriptor: int, size: int) -> bytes:
            calls["n"] += 1
            return real(descriptor, size) if calls["n"] == 1 else b""

        with mock.patch.object(file_digest, "_read_chunk", stop_after_one_chunk):
            result = digest_file(target)
        self.assert_changed(result)
        self.assertEqual(result["bytes_hashed"], CHUNK_BYTES)

    def test_a_file_deleted_before_it_is_opened_is_a_change_not_a_crash(self) -> None:
        target = self.write("gone.bin", b"data")
        real_open = file_digest._open_readonly

        def delete_then_open(path: Path) -> int:
            path.unlink()
            return real_open(path)

        with mock.patch.object(file_digest, "_open_readonly", delete_then_open):
            self.assert_changed(digest_file(target))

    def test_a_symlink_swapped_in_before_the_open_is_not_followed(self) -> None:
        outside = self.write("outside/secret.bin", b"outside")
        target = self.write("inside/file.bin", b"inside")
        real_open = file_digest._open_readonly

        def link_then_open(path: Path) -> int:
            path.unlink()
            path.symlink_to(outside)
            return real_open(path)

        with mock.patch.object(file_digest, "_open_readonly", link_then_open):
            result = digest_file(target)
        self.assert_changed(result)
        self.assertNotEqual(result["sha256"], sha256(b"outside"))

    def test_a_stable_file_is_complete(self) -> None:
        data = os.urandom(2 * CHUNK_BYTES)
        result = digest_file(self.write("stable.bin", data))
        self.assertEqual((result["complete"], result["sha256"], result["reason"]), (True, sha256(data), None))


@unittest.skipIf(os.geteuid() == 0, "root ignores file modes")
class OsPermissionTests(TemporaryCase):
    def test_an_unreadable_file_reports_its_size_and_the_permission_result_without_a_digest(self) -> None:
        target = self.write("locked.bin", RAW)
        target.chmod(0)
        self.addCleanup(target.chmod, stat.S_IRUSR | stat.S_IWUSR)
        result = digest_file(target)
        self.assertEqual((result["complete"], result["sha256"], result["reason"]),
                         (False, None, "os_permission_denied"))
        self.assertEqual(result["permission_check"], {"os_read": "denied"})
        self.assertEqual(result["size_bytes"], len(RAW))

    def test_a_readable_file_reports_the_os_read_as_allowed(self) -> None:
        result = digest_file(self.write("open.bin", RAW))
        self.assertEqual(result["permission_check"], {"os_read": "allowed"})


class ReaderAuthorityTests(TemporaryCase):
    """The reader authorises a digest exactly like a read."""

    def reader(self) -> WorkspaceReader:
        init_git_repo(self.base / "repo", files={"README.md": "# repo\n"})
        root = self.base / "repo"
        for rel in SECRET_PATHS:
            target = root / rel
            if rel.startswith(".git/"):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"top secret")
        (root / "evidence.bin").write_bytes(RAW)
        (root / "sub").mkdir()
        spec = WorkspaceSpec(workspace_id="w", root=str(root), label="", kind="git-repository",
                             capabilities=["filesystem.read"], max_file_bytes=1024)
        return WorkspaceReader(spec)

    def test_a_binary_file_over_the_read_limit_has_a_digest_though_it_has_no_text_read(self) -> None:
        reader = self.reader()
        with self.assertRaises(WorkspaceError):
            reader.read_file("evidence.bin")
        result = reader.file_digest("evidence.bin")
        self.assertEqual((result["path"], result["complete"], result["sha256"]), ("evidence.bin", True, sha256(RAW)))
        self.assertEqual(result["permission_check"], {"authority": "allowed", "os_read": "allowed"})

    def test_every_path_a_read_refuses_for_its_name_a_digest_refuses_too(self) -> None:
        reader = self.reader()
        for rel in SECRET_PATHS:
            with self.subTest(path=rel):
                with self.assertRaises(PathPolicyError):
                    reader.read_file(rel)
                with self.assertRaises(PathPolicyError):
                    reader.file_digest(rel)

    def test_traversal_and_absolute_paths_are_refused(self) -> None:
        reader = self.reader()
        for rel in ("../outside.bin", "/etc/hosts", "sub/../../x", "~/x"):
            with self.subTest(path=rel):
                with self.assertRaises(PathPolicyError):
                    reader.file_digest(rel)

    def test_a_symlink_that_escapes_the_workspace_is_refused(self) -> None:
        reader = self.reader()
        outside = self.write("outside.bin", b"outside")
        (self.base / "repo" / "link.bin").symlink_to(outside)
        with self.assertRaises(PathPolicyError):
            reader.file_digest("link.bin")

    def test_a_symlink_inside_the_workspace_digests_its_target(self) -> None:
        reader = self.reader()
        (self.base / "repo" / "alias.bin").symlink_to(self.base / "repo" / "evidence.bin")
        self.assertEqual(reader.file_digest("alias.bin")["sha256"], sha256(RAW))

    def test_a_directory_and_a_missing_path_are_errors(self) -> None:
        reader = self.reader()
        with self.assertRaises(WorkspaceError):
            reader.file_digest("sub")
        with self.assertRaises(WorkspaceError):
            reader.file_digest("no-such-file.bin")

    def test_a_fifo_is_not_a_file_and_is_never_opened(self) -> None:
        reader = self.reader()
        os.mkfifo(self.base / "repo" / "pipe")
        with self.assertRaises(WorkspaceError):
            reader.file_digest("pipe")

    def test_a_workspace_without_filesystem_read_cannot_digest(self) -> None:
        spec = WorkspaceSpec(workspace_id="w", root=str(self.base), label="", kind="git-repository",
                             capabilities=["git.observe"])
        with self.assertRaises(WorkspaceError):
            WorkspaceReader(spec)


class GatewayCase(TemporaryCase):
    """A readable parent Git project with an ``evidence`` directory that has its own scope."""

    def setUp(self) -> None:
        super().setUp()
        state = tempfile.TemporaryDirectory(prefix="uam-digest-state-")
        self.addCleanup(state.cleanup)
        self.code = self.base / "code"
        self.repo = self.code / "proj"
        init_git_repo(self.repo, files={"README.md": "# proj\n", "src/app.py": "x = 1\n"})
        (self.repo / "evidence").mkdir()
        (self.repo / "evidence" / "raw.bin").write_bytes(RAW)
        (self.repo / "src" / "blob.bin").write_bytes(b"\x00public blob")
        self.config = self.base / "config"
        self.registry = write_workspace_registry(self.config / "workspaces.json", [])
        self.state_dir = state.name
        self.write_scopes(("evidence", "evidence", {}))
        self.gw = MiddlewareGateway(str(self.registry), self.state_dir)
        self.ws = "derived:code:proj"

    def write_scopes(self, *nested: tuple[str, str, dict[str, bool]]) -> None:
        scopes: list[dict[str, Any]] = [
            {"scope_id": "code", "root": str(self.code), "authority": RootScopeAuthority(**PARENT).to_dict()},
        ]
        for scope_id, rel, flags in nested:
            scopes.append({"scope_id": scope_id, "root": str(self.repo / rel),
                           "authority": RootScopeAuthority(**flags).to_dict()})
        (self.config / "root_scopes.json").write_text(
            json.dumps({"schema_version": "root-scope-registry-v1", "scopes": scopes}), encoding="utf-8")

    def audit_rows(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.gw.audit.path.read_text().splitlines()]


class GatewayAuthorityTests(GatewayCase):
    """Nested-scope authority, revocation and audit, through the real gateway."""

    def test_an_allowed_digest_is_audited_with_its_digest_and_without_content(self) -> None:
        result = self.gw.file_digest(self.ws, "src/blob.bin")
        self.assertEqual(result["sha256"], sha256(b"\x00public blob"))
        row = self.audit_rows()[-1]
        self.assertEqual((row["action"], row["outcome"]), ("file_digest", "PASS"))
        self.assertEqual(row["details"]["path"], "src/blob.bin")
        self.assertEqual(row["details"]["sha256"], result["sha256"])
        self.assertNotIn("public blob", self.gw.audit.path.read_text())

    def test_a_nested_scope_that_denies_reading_denies_the_digest(self) -> None:
        for rel in ("evidence/raw.bin", "evidence/not-there.bin"):
            with self.subTest(path=rel):
                with self.assertRaises(ScopeAuthorityError) as caught:
                    self.gw.file_digest(self.ws, rel)
                self.assertEqual(caught.exception.code, "SCOPE_AUTHORITY_DENIED")
        row = self.audit_rows()[-1]
        self.assertEqual((row["action"], row["outcome"]), ("file_digest", "DENIED"))
        self.assertNotIn("sha256", row["details"])

    @unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
    def test_a_hard_link_to_a_denied_file_does_not_give_its_digest(self) -> None:
        os.link(self.repo / "evidence" / "raw.bin", self.repo / "src" / "alias.bin")
        with self.assertRaises(ScopeAuthorityError) as caught:
            self.gw.file_digest(self.ws, "src/alias.bin")
        self.assertEqual((caught.exception.code, caught.exception.reason),
                         ("SCOPE_AUTHORITY_DENIED", "hard_linked_file"))
        row = self.audit_rows()[-1]
        self.assertEqual((row["action"], row["outcome"]), ("file_digest", "DENIED"))
        self.assertNotIn("sha256", row["details"])

    @unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
    def test_a_hard_linked_file_is_digested_when_no_nested_scope_denies_reading(self) -> None:
        self.write_scopes(("evidence", "evidence", {"metadata_read": True, "content_read": True}))
        os.link(self.repo / "evidence" / "raw.bin", self.repo / "src" / "alias.bin")
        self.assertEqual(self.gw.file_digest(self.ws, "src/alias.bin")["sha256"], sha256(RAW))

    def test_a_scope_that_only_lists_does_not_grant_a_digest(self) -> None:
        self.write_scopes(("evidence", "evidence", {"metadata_read": True}))
        with self.assertRaises(ScopeAuthorityError):
            self.gw.file_digest(self.ws, "evidence/raw.bin")

    def test_a_scope_that_grants_reading_grants_the_digest(self) -> None:
        self.write_scopes(("evidence", "evidence", {"metadata_read": True, "content_read": True}))
        self.assertEqual(self.gw.file_digest(self.ws, "evidence/raw.bin")["sha256"], sha256(RAW))

    def test_revocation_takes_effect_on_the_next_call(self) -> None:
        self.write_scopes(("evidence", "evidence", {"metadata_read": True, "content_read": True}))
        self.assertTrue(self.gw.file_digest(self.ws, "evidence/raw.bin")["complete"])
        self.write_scopes(("evidence", "evidence", {}))
        with self.assertRaises(ScopeAuthorityError):
            self.gw.file_digest(self.ws, "evidence/raw.bin")

    def test_the_absolute_path_handle_is_guarded_like_the_derived_handle(self) -> None:
        with self.assertRaises(ScopeAuthorityError):
            self.gw.file_digest(str(self.repo), "evidence/raw.bin")


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpSurfaceTests(GatewayCase):
    def tools(self) -> dict[str, Any]:
        return create_session_read_server(str(self.registry), self.state_dir)._tool_manager._tools

    def call(self, **kwargs: Any) -> dict[str, Any]:
        return json.loads(asyncio.run(self.tools()["uam_file_digest"].fn(ctx=None, **kwargs)))

    def test_the_tool_is_read_only_and_listed(self) -> None:
        tool = self.tools()["uam_file_digest"]
        annotations = tool.annotations if isinstance(tool.annotations, dict) else tool.annotations.model_dump()
        self.assertTrue(annotations.get("readOnlyHint", annotations.get("read_only_hint")))
        self.assertFalse(annotations.get("destructiveHint", annotations.get("destructive_hint")))

    def test_the_tool_answers_with_a_relative_path_and_no_host_path(self) -> None:
        payload = self.call(workspace_id=self.ws, path="src/blob.bin")
        self.assertEqual(payload["relative_path"], "src/blob.bin")
        self.assertNotIn("path", payload)
        self.assertEqual(payload["sha256"], sha256(b"\x00public blob"))
        self.assertNotIn(str(self.base), json.dumps(payload))

    def test_git_internals_are_refused_with_the_same_message_as_a_read(self) -> None:
        payload = self.call(workspace_id=self.ws, path=".git/config")
        self.assertEqual(payload["error"], "direct .git/ reads are denied; use git observation tools")
        self.assertNotIn("sha256", payload)

    def test_a_missing_file_is_an_error_answer_not_a_crash(self) -> None:
        payload = self.call(workspace_id=self.ws, path="src/no-such-file.bin")
        self.assertEqual(payload["error"], "path does not exist")
        self.assertNotIn("sha256", payload)

    def test_a_denied_digest_is_a_machine_readable_error(self) -> None:
        payload = self.call(workspace_id=self.ws, path="evidence/raw.bin")
        self.assertEqual(payload["error_code"], "SCOPE_AUTHORITY_DENIED")
        self.assertNotIn("sha256", payload)

    def test_the_description_states_the_limits_the_code_enforces(self) -> None:
        description = self.tools()["uam_file_digest"].description
        self.assertIn(f"{file_digest.DEFAULT_MAX_BYTES // (1024 * 1024)} MiB", description)
        self.assertIn(f"{file_digest.DEFAULT_MAX_SECONDS:g} s", description)
        for reason in ("byte_limit", "time_limit", "changed_while_hashing", "os_permission_denied"):
            with self.subTest(reason=reason):
                self.assertIn(reason, description)

    def test_the_reviewed_tool_contract_pins_the_tool(self) -> None:
        reviewed = json.loads((Path(file_digest.__file__).parent / "tool_contract.json").read_text())
        self.assertIn("uam_file_digest", reviewed)


if __name__ == "__main__":
    unittest.main()
