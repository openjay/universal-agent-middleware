"""R3-05: errors of the descriptor walk are typed, coded and name-free, and a tool answers them instead of raising.

r2 left ``PathChangedError`` an ``OSError`` that the tool bodies do not catch, and ``OpenDenied`` (the operating system
refused UAM's own account) a ``PermissionError`` that ``read_file`` does not catch. Both then leave the tool body as an
unexpected exception: the client gets an opaque tool failure, the server logs a traceback that names the entry, and an
SDK that echoes ``str(exc)`` would hand the client ``[Errno 62] ... 'entry-name'`` as well.

Each case runs two ways: the tool body (an exception that escapes it is reported as ``RAISED``) and a real MCP client
session over the in-memory transport (so the result envelope and the SDK's own handling are observed too).

A refusal also repeats the path the caller sent and no other name: the target of a link inside the workspace is a name
the caller did not send, and a refusal that spells it out tells the caller what an innocent-looking link points at
(``LinkTargetNameTests``; r2 and the first r3 freeze did, the final r3 does not).
"""
from __future__ import annotations

import errno
import os
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from universal_agent_middleware.descriptor_io import OpenDenied, PathChangedError
from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from universal_agent_middleware.policy import resolve_safe_path

from r3_world import STATIC_ID, ProtocolWorld, call_direct, call_protocol, create_session_read_server, decode, run

ENTRY_NAME = "entry-name-that-must-not-travel.txt"
PROTECTED_FILE = ".secrets.env"
PROTECTED_DIR = ".ssh"
RESOLVED_REFUSAL = "denied resolved path component"


@contextmanager
def swapped_when_opened(target: Path):
    """The first time the walk opens ``target`` by name, replace it with a symbolic link (a classic path race)."""
    real_open = os.open
    armed = [True]

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        if armed[0] and dir_fd is not None and path == target.name:
            armed[0] = False
            if target.is_dir() and not target.is_symlink():
                moved = target.with_name(target.name + "_moved")
                os.rename(target, moved)
                os.symlink(moved.name, target)
            else:
                moved = target.parent / "other.txt"
                target.unlink()
                os.symlink(moved.name, target)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with mock.patch("os.open", racing_open):
        yield armed


class ErrorTypeTests(unittest.TestCase):
    def test_the_walk_errors_are_workspace_errors_with_a_code_and_never_carry_the_entry_name(self) -> None:
        for error in (PathChangedError(ENTRY_NAME), OpenDenied(errno.EACCES, "Permission denied", ENTRY_NAME)):
            with self.subTest(error=type(error).__name__):
                self.assertIsInstance(error, WorkspaceError)
                self.assertIsInstance(getattr(error, "code", None), str)
                for text in (str(error), repr(error), " ".join(str(arg) for arg in error.args)):
                    self.assertNotIn(ENTRY_NAME, text)
                    self.assertNotIn("Errno", text)

    def test_the_walk_errors_are_still_os_errors_for_the_callers_that_treat_any_io_failure_alike(self) -> None:
        self.assertIsInstance(PathChangedError(ENTRY_NAME), OSError)
        self.assertIsInstance(OpenDenied(errno.EACCES, "Permission denied", ENTRY_NAME), PermissionError)

    def test_the_two_codes_differ_and_are_stable_identifiers(self) -> None:
        changed = PathChangedError(ENTRY_NAME).code
        denied = OpenDenied(errno.EACCES, "Permission denied", ENTRY_NAME).code
        self.assertEqual((changed, denied), ("PATH_CHANGED", "PATH_UNREADABLE"))


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ToolAnswersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = ProtocolWorld()
        self.addCleanup(self.world.cleanup)
        self.server = self.world.server()

    def test_control_an_unraced_read_answers_with_the_content(self) -> None:
        answer = decode(run(call_direct(self.server, "uam_read_file", workspace_id=STATIC_ID, path="notes.txt")))
        self.assertNotIn("error", answer)
        self.assertIn("visible note", str(answer))

    def test_a_file_replaced_by_a_link_while_it_is_opened_is_a_coded_retryable_answer(self) -> None:
        for tool in ("uam_read_file", "uam_file_digest"):
            with self.subTest(tool=tool):
                world = ProtocolWorld()
                self.addCleanup(world.cleanup)
                with swapped_when_opened(world.repo / "notes.txt") as armed:
                    output = run(call_direct(world.server(), tool, workspace_id=STATIC_ID, path="notes.txt"))
                self.assertFalse(armed[0], "the race was never triggered: the test would prove nothing")
                answer = decode(output)
                self.assertEqual(answer.get("error_code"), "PATH_CHANGED", output)
                self.assertNotIn("notes.txt", answer["error"])
                self.assertNotIn("Errno", output)
                self.assertNotIn("symbolic", output.lower())

    def test_a_directory_replaced_by_a_link_while_it_is_opened_is_a_coded_retryable_answer(self) -> None:
        for tool, arguments in (("uam_tree", {"path": "src"}), ("uam_search_text", {"path": "src", "query": "visible"})):
            with self.subTest(tool=tool):
                world = ProtocolWorld()
                self.addCleanup(world.cleanup)
                with swapped_when_opened(world.repo / "src") as armed:
                    output = run(call_direct(world.server(), tool, workspace_id=STATIC_ID, **arguments))
                self.assertFalse(armed[0], "the race was never triggered: the test would prove nothing")
                answer = decode(output)
                self.assertEqual(answer.get("error_code"), "PATH_CHANGED", output)
                self.assertNotIn("Errno", output)

    def test_a_missing_path_or_a_file_used_as_a_directory_is_an_answer_not_an_exception(self) -> None:
        cases = (
            ("uam_read_file", {"path": "no-such-file.txt"}),
            ("uam_read_file", {"path": "notes.txt/below"}),
            ("uam_file_digest", {"path": "no-such-file.txt"}),
            ("uam_tree", {"path": "no-such-dir"}),
            ("uam_tree", {"path": "notes.txt/below"}),
            ("uam_search_text", {"path": "no-such-dir", "query": "visible"}),
        )
        for tool, arguments in cases:
            with self.subTest(tool=tool, path=arguments["path"]):
                output = run(call_direct(self.server, tool, workspace_id=STATIC_ID, **arguments))
                answer = decode(output)
                self.assertEqual(answer.get("error"), "path does not exist", output)
                self.assertNotIn("Errno", output)

    def test_over_a_real_mcp_session_a_race_is_a_normal_coded_result_not_a_tool_failure(self) -> None:
        with swapped_when_opened(self.world.repo / "notes.txt") as armed:
            is_error, text = run(call_protocol(self.server, "uam_read_file", workspace_id=STATIC_ID, path="notes.txt"))
        self.assertFalse(armed[0])
        self.assertFalse(is_error, f"the race surfaced as a tool failure: {text[:160]!r}")
        answer = decode(text)
        self.assertEqual(answer.get("error_code"), "PATH_CHANGED", text)
        self.assertNotIn("Errno", text)

    def test_a_file_the_operating_system_refuses_is_a_coded_answer_and_its_digest_stays_a_result(self) -> None:
        locked = self.world.repo / "locked.txt"
        locked.write_text("body the account cannot read\n", encoding="utf-8")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)
        output = run(call_direct(self.server, "uam_read_file", workspace_id=STATIC_ID, path="locked.txt"))
        answer = decode(output)
        self.assertEqual(answer.get("error_code"), "PATH_UNREADABLE", output)
        self.assertNotIn("Errno", output)
        self.assertNotIn("Permission denied", output)
        digest = decode(run(call_direct(self.server, "uam_file_digest", workspace_id=STATIC_ID, path="locked.txt")))
        self.assertNotIn("error", digest)  # unchanged contract: an OS refusal is a digest result, not an error

    def test_over_a_real_mcp_session_an_unreadable_file_is_a_normal_coded_result(self) -> None:
        locked = self.world.repo / "locked.txt"
        locked.write_text("body the account cannot read\n", encoding="utf-8")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)
        is_error, text = run(call_protocol(self.server, "uam_read_file", workspace_id=STATIC_ID, path="locked.txt"))
        self.assertFalse(is_error, text[:160])
        self.assertEqual(decode(text).get("error_code"), "PATH_UNREADABLE", text)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class LinkTargetNameTests(unittest.TestCase):
    """A refusal repeats the path the caller sent and no other name.

    Whoever made a link wrote its target; the caller only sent the link's own name. Spelling the target out in the
    refusal ("denied resolved path component: .secrets.env") discloses what the link points at, although the same call
    refuses to read it and a listing omits it. The refusal says that the resolved path was denied, not what it was called.
    """

    CASES = (
        ("uam_read_file", {"path": "innocent-file"}),
        ("uam_file_digest", {"path": "innocent-file"}),
        ("uam_git_diff", {"path": "innocent-file"}),
        ("uam_tree", {"path": "innocent-dir"}),
        ("uam_search_text", {"path": "innocent-dir", "query": "Host"}),
        ("uam_read_file", {"path": "innocent-dir/config"}),
    )

    def setUp(self) -> None:
        self.world = ProtocolWorld()
        self.addCleanup(self.world.cleanup)
        repo = self.world.repo
        (repo / PROTECTED_FILE).write_text("SECRET_VALUE=fictional\n", encoding="utf-8")
        (repo / PROTECTED_DIR).mkdir()
        (repo / PROTECTED_DIR / "config").write_text("Host fictional\n", encoding="utf-8")
        os.symlink(PROTECTED_FILE, repo / "innocent-file")
        os.symlink(PROTECTED_DIR, repo / "innocent-dir")
        os.symlink("notes.txt", repo / "link-to-notes")
        self.server = self.world.server()

    def test_a_refused_link_is_refused_without_naming_its_target(self) -> None:
        for tool, arguments in self.CASES:
            with self.subTest(tool=tool, path=arguments["path"]):
                output = run(call_direct(self.server, tool, workspace_id=STATIC_ID, **arguments))
                self.assertEqual(decode(output).get("error"), RESOLVED_REFUSAL, output)
                for text in (PROTECTED_FILE, PROTECTED_DIR, "fictional"):
                    self.assertNotIn(text, output)

    def test_over_a_real_mcp_session_the_refusal_is_a_normal_result_that_names_no_target(self) -> None:
        for tool, arguments in self.CASES:
            with self.subTest(tool=tool, path=arguments["path"]):
                is_error, text = run(call_protocol(self.server, tool, workspace_id=STATIC_ID, **arguments))
                self.assertFalse(is_error, text[:160])
                self.assertEqual(decode(text).get("error"), RESOLVED_REFUSAL, text)
                for name in (PROTECTED_FILE, PROTECTED_DIR):
                    self.assertNotIn(name, text)

    def test_the_policy_function_refuses_a_link_to_a_protected_name_without_naming_it(self) -> None:
        for raw in ("innocent-file", "innocent-dir/config"):
            with self.subTest(path=raw):
                with self.assertRaises(PathPolicyError) as raised:
                    resolve_safe_path(self.world.repo, raw, must_exist=False)
                self.assertEqual(str(raised.exception), RESOLVED_REFUSAL)

    def test_control_a_link_to_an_allowed_target_is_read_through(self) -> None:
        answer = decode(run(call_direct(self.server, "uam_read_file", workspace_id=STATIC_ID, path="link-to-notes")))
        self.assertNotIn("error", answer)
        self.assertIn("visible note", str(answer))

    def test_control_a_refusal_of_a_name_the_caller_sent_repeats_that_spelling_and_nothing_else(self) -> None:
        for sent, component in ((".secrets.env", ".secrets.env"), (".SECRETS.ENV", ".SECRETS.ENV"), (".ssh/config", ".ssh")):
            with self.subTest(sent=sent):
                answer = decode(run(call_direct(self.server, "uam_read_file", workspace_id=STATIC_ID, path=sent)))
                self.assertEqual(answer.get("error"), f"denied path component: {component}")


if __name__ == "__main__":
    unittest.main()
