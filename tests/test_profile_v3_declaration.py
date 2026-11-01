"""READ_ONLY_SESSION_PROFILE_V3 is declared, and the declaration is what this source tree advertises.

``docs/oss/profile-v3-declaration.json`` binds the complete tool set, the per-tool contract digest, the
input / output / safety / description fingerprints and the full metadata difference against the V2
baseline (the 19 tools of the production release source). These tests fail when the server and the
declaration disagree, in either direction, and they check the statements the successor contract
(``docs/oss/public-profile-contract-v3.md``) makes about serving and defaults. After an *intended* change
to a tool's description or schema, refresh the declaration with
``python tests/profile_declaration.py write`` and review the diff: a changed description is a
client-visible change (``client_refresh_needed``).

The historical 19-tool contract of v0.5.1rc1 (``docs/oss/public-profile-contract.md``) is not touched
by any of this.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import unittest
from unittest import mock

import profile_declaration
from profile_declaration import (
    ADOPTION,
    BASELINE_PROFILE,
    DECLARATION_PATH,
    DESCRIPTION_BASIS,
    DOCSTRINGS_DEDENTED_AT_COMPILE_TIME,
    FINGERPRINT_ROLES,
    PROFILE,
    REPOSITORY,
    SAFETY,
    build,
    field_digests,
    load,
    run_probe,
    side,
    without_description_digests,
)

from universal_agent_middleware.release_probe import contract_sha256, diff_tool_fields
from universal_agent_middleware.root_scope import RootScopeAuthority

try:
    import mcp  # noqa: F401  (the SDK adapter, and so the probe, needs it)
except ImportError:
    mcp = None

PACKAGE = REPOSITORY / "src" / "universal_agent_middleware"
# An sdist ships tests but not docs/: without that directory there is nothing to compare. With docs/
# present, a missing declaration is an error, never a skip.
DOCUMENTS_SHIPPED = (REPOSITORY / "docs").is_dir()
NO_DOCUMENTS = "the repository documents are not part of this tree (an sdist ships tests, not docs/)"
TOOL_CONTRACT = PACKAGE / "tool_contract.json"
DIGEST_TOOL = "uam_file_digest"
# Current (not historical) documents that state how many tools the profile serves.
CURRENT_DOCUMENTS = ("README.md", "docs/adapters/MCP.md", "docs/SSOT.md")
SUCCESSOR_CONTRACT = REPOSITORY / "docs" / "oss" / "public-profile-contract-v3.md"
HISTORICAL_MARKERS = ("v0.5.1rc1", "V2", "published")
NINETEEN_TOOLS = re.compile(r"\b19\b[- ](?:(?:read-only|MCP|session) )*tools?\b|19-tool", re.IGNORECASE)


INDENTATION_DEPENDS_ON_THE_INTERPRETER = (
    "this interpreter keeps docstring indentation, so the advertised description text and its digest differ "
    "from the declared ones (Python 3.13 or later reproduces them); every other digest is still compared"
)


def digest(value: object) -> str:
    """The probe's own digest of one JSON value (kept in step with ``release_probe.PROBE_SOURCE``)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode()).hexdigest()


def two_line_docstring() -> None:
    """First line.

    Second line, indented in the source.
    """


@unittest.skipUnless(DOCUMENTS_SHIPPED, NO_DOCUMENTS)
@unittest.skipIf(mcp is None, "MCP SDK unavailable")
class DeclarationMatchesTheServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.declared = load()
        cls.probe = run_probe()

    def test_the_declared_candidate_is_exactly_what_the_server_advertises(self) -> None:
        declared, live = self.declared["candidate"], side(self.probe)
        if not DOCSTRINGS_DEDENTED_AT_COMPILE_TIME:
            declared, live = without_description_digests(declared), without_description_digests(live)
        self.assertEqual(
            declared, live,
            "the declaration is stale: review the metadata difference, then run "
            "`python tests/profile_declaration.py write` (Python 3.13 or later)",
        )

    @unittest.skipUnless(DOCSTRINGS_DEDENTED_AT_COMPILE_TIME, INDENTATION_DEPENDS_ON_THE_INTERPRETER)
    def test_the_whole_declaration_is_reproducible_from_its_baseline_and_the_live_listing(self) -> None:
        self.assertEqual(self.declared, build(self.declared["baseline"], self.probe))

    def test_the_committed_tool_contract_is_the_declared_contract(self) -> None:
        committed = json.loads(TOOL_CONTRACT.read_text(encoding="utf-8"))
        declared = {name: entry["contract"] for name, entry in self.declared["candidate"]["fingerprints"].items()}
        self.assertEqual(committed, declared)
        self.assertEqual(contract_sha256(committed), self.declared["candidate"]["contract_sha256"])

    def test_every_live_tool_is_read_only_exactly_as_declared(self) -> None:
        expected = digest(SAFETY)  # the probe's own digest function, applied to the declared annotations
        for name, fields in self.probe["fields"].items():
            with self.subTest(tool=name):
                self.assertEqual(fields["annotations"], expected)

    def test_every_tool_binds_its_name_input_output_safety_and_description(self) -> None:
        self.assertEqual(self.declared["fingerprint_roles"], FINGERPRINT_ROLES)
        for name, entry in self.declared["candidate"]["fingerprints"].items():
            with self.subTest(tool=name):
                self.assertLessEqual({"name", *FINGERPRINT_ROLES.values()}, set(entry["fields"]))


@unittest.skipUnless(DOCUMENTS_SHIPPED, NO_DOCUMENTS)
class V3IsV2PlusTheDigestToolTests(unittest.TestCase):
    """Facts about the declaration itself; they need no server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.declared = load()
        cls.baseline = cls.declared["baseline"]
        cls.candidate = cls.declared["candidate"]

    def test_the_profile_names_are_the_ones_the_documents_use(self) -> None:
        self.assertEqual((self.declared["profile"], self.declared["extends"]), (PROFILE, BASELINE_PROFILE))
        self.assertEqual(self.baseline["profile"], BASELINE_PROFILE)

    def test_it_is_adopted_locally_and_says_where_and_in_which_release(self) -> None:
        self.assertEqual(self.declared["status"], "ADOPTED_LOCALLY")
        self.assertIs(self.declared["adopted_in_production"], True)
        self.assertEqual(self.declared["adoption"], ADOPTION)

    def test_the_tool_set_is_the_nineteen_of_v2_plus_the_digest_tool(self) -> None:
        self.assertEqual((self.baseline["tool_count"], self.candidate["tool_count"]), (19, 20))
        self.assertEqual(self.candidate["tools"], sorted({*self.baseline["tools"], DIGEST_TOOL}))
        self.assertNotIn(DIGEST_TOOL, self.baseline["tools"])
        self.assertEqual(len(self.candidate["tools"]), len(set(self.candidate["tools"])))
        self.assertEqual(set(self.candidate["fingerprints"]), set(self.candidate["tools"]))

    def test_no_contract_digest_of_a_v2_tool_changed(self) -> None:
        for name in self.baseline["tools"]:
            with self.subTest(tool=name):
                self.assertEqual(
                    self.baseline["fingerprints"][name]["contract"], self.candidate["fingerprints"][name]["contract"],
                )

    def test_the_metadata_difference_is_complete_and_recomputable(self) -> None:
        recomputed = diff_tool_fields(field_digests(self.baseline), field_digests(self.candidate))
        self.assertEqual(self.declared["metadata_diff_vs_baseline"], recomputed)
        self.assertEqual(recomputed["added"], [DIGEST_TOOL])
        self.assertEqual(recomputed["removed"], [])
        self.assertIs(recomputed["client_refresh_needed"], True)

    def test_only_descriptions_changed_never_an_input_an_output_or_a_safety_field(self) -> None:
        changed = self.declared["metadata_diff_vs_baseline"]["changed"]
        self.assertTrue(changed, "no description changed: then client_refresh_needed would be wrong")
        for name, keys in changed.items():
            with self.subTest(tool=name):
                self.assertEqual(keys, ["description"])

    def test_every_tool_carries_the_one_declared_read_only_safety_fingerprint(self) -> None:
        expected = digest(SAFETY)
        self.assertEqual(self.declared["safety"], SAFETY)
        for side_name in ("baseline", "candidate"):
            for name, entry in self.declared[side_name]["fingerprints"].items():
                with self.subTest(side=side_name, tool=name):
                    self.assertEqual(entry["fields"]["annotations"], expected)

    def test_the_digest_tool_is_served_by_the_sdk_adapter_only(self) -> None:
        self.assertEqual(self.declared["serving"][DIGEST_TOOL]["served_by"], ["mcp_sdk_adapter"])
        for module in ("mcp.py", "openapi.py", "server.py"):
            with self.subTest(adapter=module):
                self.assertNotIn("file_digest", (PACKAGE / module).read_text(encoding="utf-8"))
        self.assertIn(DIGEST_TOOL, (PACKAGE / "adapters" / "mcp_sdk.py").read_text(encoding="utf-8"))

    def test_directory_admission_is_off_by_default(self) -> None:
        self.assertIs(self.declared["defaults"]["directory_admit"], False)
        self.assertIs(RootScopeAuthority().directory_admit, False)

    def test_the_description_digest_says_which_interpreter_it_is_the_digest_for(self) -> None:
        self.assertEqual(self.declared["description_digest_basis"], DESCRIPTION_BASIS)
        self.assertIn("Python 3.13", DESCRIPTION_BASIS)

    def test_the_dedent_switch_is_what_this_interpreter_actually_does_to_a_docstring(self) -> None:
        # Decided here from this module's own function, not from profile_declaration's.
        dedented = "\n    Second line" not in (two_line_docstring.__doc__ or "")
        self.assertIs(DOCSTRINGS_DEDENTED_AT_COMPILE_TIME, dedented)

    def test_dropping_description_digests_drops_nothing_else_and_leaves_its_argument_alone(self) -> None:
        before = json.dumps(self.candidate, sort_keys=True)
        stripped = without_description_digests(self.candidate)
        self.assertEqual(json.dumps(self.candidate, sort_keys=True), before)
        for name, entry in self.candidate["fingerprints"].items():
            with self.subTest(tool=name):
                fields = dict(entry["fields"])
                del fields[FINGERPRINT_ROLES["description"]]
                self.assertEqual(stripped["fingerprints"][name], {"contract": entry["contract"], "fields": fields})
        self.assertEqual(
            {key: value for key, value in stripped.items() if key != "fingerprints"},
            {key: value for key, value in self.candidate.items() if key != "fingerprints"},
        )

    def test_an_interpreter_that_keeps_docstring_indentation_can_neither_write_nor_check_the_declaration(self) -> None:
        committed = DECLARATION_PATH.read_bytes()
        for action in ("write", "check"):
            with self.subTest(action=action):
                with (
                    mock.patch.object(profile_declaration, "DOCSTRINGS_DEDENTED_AT_COMPILE_TIME", False),
                    mock.patch("sys.stderr", new_callable=io.StringIO),
                    self.assertRaises(SystemExit) as raised,
                ):
                    profile_declaration.main([action])
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(DECLARATION_PATH.read_bytes(), committed)


@unittest.skipUnless(DOCUMENTS_SHIPPED, NO_DOCUMENTS)
class DocumentsAgreeOnTheProfileTests(unittest.TestCase):
    def test_current_documents_do_not_describe_the_profile_as_nineteen_tools(self) -> None:
        for relative in CURRENT_DOCUMENTS:
            lines = (REPOSITORY / relative).read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines, start=1):
                if NINETEEN_TOOLS.search(line) and not any(marker in line for marker in HISTORICAL_MARKERS):
                    self.fail(f"{relative}:{number} states a 19-tool profile without marking it historical: {line!r}")

    def test_the_successor_contract_states_what_it_is_and_what_it_is_not(self) -> None:
        text = SUCCESSOR_CONTRACT.read_text(encoding="utf-8")
        for required in (
            PROFILE, "ADOPTED LOCALLY", "Adopted locally", "Published", "uam_file_digest", "SDK adapter only",
            "directory_admit", "independent", "Unverified", "profile-v3-declaration.json", "public-profile-contract.md",
            "description_digest_basis", "Python 3.13",
        ):
            with self.subTest(statement=required):
                self.assertIn(required, text)
        self.assertTrue(DECLARATION_PATH.is_file())

    def test_the_current_documents_name_the_profile_and_the_successor(self) -> None:
        for relative in ("docs/adapters/MCP.md", "docs/SSOT.md"):
            with self.subTest(document=relative):
                text = (REPOSITORY / relative).read_text(encoding="utf-8")
                self.assertIn(PROFILE, text)
                self.assertIn("public-profile-contract-v3.md", text)


if __name__ == "__main__":
    unittest.main()
