"""R3-01: a Context Profile is selected by the trusted resolved identity, never by the raw selector, and is validated.

r2 built ``<config>/workspace-contexts/<selector>.json`` from the string the client sent. So:

* an absolute selector replaced the store directory (``Path(store) / "/abs/x.json"`` is ``/abs/x.json``): a JSON file
  beside a repository, outside the store, became that repository's profile;
* on a case-insensitive volume a name alias (``repo`` for a registered ``Repo``) opened the file of another identity;
* a literal derived handle was a file name;
* a corrupt, non-UTF-8, oversized, foreign or unversioned profile was either taken as configured or crashed the tool
  (``UnicodeDecodeError`` is not caught), and a corrupt profile read exactly like an unconfigured one;
* the raw ``entrypoints`` were echoed and the limits were never validated.

r3: only a statically registered identity has a profile; it is found by the exact entry name in the store directory,
opened without following links, size-bounded, strictly validated (schema, declared owner, entrypoint paths, limits) and
reported as NOT_CONFIGURED, CONFIGURED or INVALID (with a fixed problem code, never content).
"""
from __future__ import annotations

import json
import os
import unittest
from typing import Any

from directory_fixtures import static_repository
from synthetic_fixtures import init_git_repo

from r3_world import STATIC_ID, ProtocolWorld, call_direct, call_protocol, create_session_read_server, decode, run

SCHEMA = "workspace-context-profile-v1"
LEAK = "LEAK-MARKER-0042"


def profile(key: str = STATIC_ID, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": SCHEMA, "workspace_id": key, "entrypoints": ["README.md"],
        "bootstrap_limits": {"max_files": 4, "max_total_bytes": 4096},
    }
    body.update(overrides)
    return body


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ProfileCase(unittest.TestCase):
    extra_workspaces: tuple[dict[str, Any], ...] = ()

    def setUp(self) -> None:
        self.world = ProtocolWorld(extra_workspaces=self.extra_workspaces)
        self.addCleanup(self.world.cleanup)
        self.store = self.world.config / "workspace-contexts"
        self.store.mkdir()

    def write(self, name: str, body: Any = None, *, raw: bytes | None = None) -> None:
        path = self.store / name
        path.write_bytes(raw if raw is not None else json.dumps(body).encode("utf-8"))

    def snapshot(self, selector: str = STATIC_ID) -> dict[str, Any]:
        return decode(run(call_direct(self.world.server(), "uam_workspace_snapshot", workspace_id=selector)))

    def bootstrap(self, selector: str = STATIC_ID, **arguments: Any) -> dict[str, Any]:
        output = run(call_direct(self.world.server(), "uam_session_bootstrap", workspace_id=selector, **arguments))
        return decode(output)


class ProfileSelectionTests(ProfileCase):
    def test_control_a_registered_workspace_uses_its_own_profile(self) -> None:
        self.write(f"{STATIC_ID}.json", profile())
        snapshot = self.snapshot()
        self.assertEqual(snapshot["resolution_kind"], "static")
        self.assertTrue(snapshot["context_profile"]["configured"])
        self.assertEqual(snapshot["context_profile"]["entrypoints"], ["README.md"])
        pack = self.bootstrap()
        self.assertIn("visible readme line", json.dumps(pack["context_profile"]))

    def test_an_absolute_selector_never_reaches_a_file_outside_the_store(self) -> None:
        # ``Path(store) / "/abs/repo.json"`` is ``/abs/repo.json``: this sibling of the repository became its profile.
        (self.world.data / "repo.json").write_text(
            json.dumps(profile("anything", entrypoints=[f"{LEAK}.txt"])), encoding="utf-8")
        snapshot = self.snapshot(str(self.world.repo))
        self.assertEqual(snapshot["resolution_kind"], "absolute_path", "the selector must resolve as a path here")
        self.assertFalse(snapshot["context_profile"]["configured"], snapshot["context_profile"])
        self.assertEqual(snapshot["context_profile"]["entrypoints"], [])
        self.assertNotIn(LEAK, json.dumps(snapshot))
        pack = self.bootstrap(str(self.world.repo))
        self.assertFalse(pack["context_profile"]["configured"])
        self.assertNotIn(LEAK, json.dumps(pack))

    def test_a_literal_derived_handle_is_not_a_profile_name(self) -> None:
        self.write("derived:data-scope:repo.json", profile("derived:data-scope:repo", entrypoints=[f"{LEAK}.txt"]))
        snapshot = self.snapshot("derived:data-scope:repo")
        self.assertEqual(snapshot["resolution_kind"], "derived")
        self.assertFalse(snapshot["context_profile"]["configured"], snapshot["context_profile"])
        self.assertNotIn(LEAK, json.dumps(snapshot))

    def test_a_derived_workspace_is_never_configured_even_when_a_registered_one_has_a_profile(self) -> None:
        self.write(f"{STATIC_ID}.json", profile())
        for selector in ("repo", "REPO", "derived:data-scope:repo", str(self.world.repo)):
            with self.subTest(selector=selector):
                snapshot = self.snapshot(selector)
                self.assertNotEqual(snapshot["resolution_kind"], "static")
                self.assertFalse(snapshot["context_profile"]["configured"], snapshot["context_profile"])


class AliasInheritanceTests(ProfileCase):
    """A registered ``Repo`` and the name alias ``repo`` of another workspace must not share a file on this volume."""

    def setUp(self) -> None:
        self.extra_workspaces = ()
        super().setUp()
        self.second = self.world.data / "repo2"
        init_git_repo(self.second, files={"README.md": "# second\n"})
        # a second registration whose id differs from the project-name alias ``repo`` only by letter case
        self.world.registry_path.write_text(json.dumps({
            "registry_version": "uam-workspace-registry-v1",
            "workspaces": [static_repository(STATIC_ID, self.world.repo), static_repository("Repo", self.second)],
        }), encoding="utf-8")

    def test_a_name_alias_does_not_open_the_profile_of_a_registered_identity_that_differs_by_case(self) -> None:
        self.write("Repo.json", profile("Repo", entrypoints=[f"{LEAK}.txt"]))
        if not (self.store / "repo.json").exists():
            self.skipTest("NOT_RUN: this volume is case-sensitive, so the alias cannot reach the other file")
        registered = self.snapshot("Repo")
        self.assertEqual(registered["resolution_kind"], "static")
        self.assertTrue(registered["context_profile"]["configured"])
        alias = self.snapshot("repo")
        self.assertNotEqual(alias["resolution_kind"], "static", "the alias must resolve to a different identity")
        self.assertFalse(alias["context_profile"]["configured"], alias["context_profile"])
        self.assertNotIn(LEAK, json.dumps(alias))


class ProfileStateTests(ProfileCase):
    def test_no_profile_is_not_configured(self) -> None:
        context = self.snapshot()["context_profile"]
        self.assertFalse(context["configured"])
        self.assertEqual(context["state"], "NOT_CONFIGURED")
        self.assertNotIn("problem", context)

    def test_a_missing_store_directory_is_not_configured_either(self) -> None:
        self.store.rmdir()
        context = self.snapshot()["context_profile"]
        self.assertEqual((context["configured"], context["state"]), (False, "NOT_CONFIGURED"))

    def test_a_valid_profile_reports_configured_state(self) -> None:
        self.write(f"{STATIC_ID}.json", profile())
        context = self.snapshot()["context_profile"]
        self.assertEqual((context["configured"], context["state"]), (True, "CONFIGURED"))
        self.assertNotIn("problem", context)

    def test_each_kind_of_damage_is_invalid_never_unconfigured_and_never_echoes_content(self) -> None:
        cases: dict[str, dict[str, Any]] = {
            "corrupt_json": {"raw": b"{not json " + LEAK.encode()},
            "not_utf8": {"raw": b"\xff\xfe{\"schema_version\": \"" + LEAK.encode() + b"\"}"},
            "top_level_list": {"body": [LEAK]},
            "oversized": {"body": profile(padding=" " * 70_000 + LEAK)},
            "unknown_schema": {"body": profile(schema_version=f"{LEAK}-v9")},
            "missing_schema": {"body": {k: v for k, v in profile().items() if k != "schema_version"}},
            "foreign_owner": {"body": profile(workspace_id=f"{LEAK}-other")},
            "missing_owner": {"body": {k: v for k, v in profile().items() if k != "workspace_id"}},
            "entrypoints_not_a_list": {"body": profile(entrypoints=f"{LEAK}.md")},
            "entrypoint_not_a_string": {"body": profile(entrypoints=["README.md", 7])},
            "entrypoint_denied_name": {"body": profile(entrypoints=["README.md", ".env"])},
            "entrypoint_traversal": {"body": profile(entrypoints=[f"../{LEAK}.txt"])},
            "entrypoint_absolute": {"body": profile(entrypoints=[f"/{LEAK}/hosts"])},
            "entrypoint_nul": {"body": profile(entrypoints=[f"a\u0000{LEAK}"])},
            "entrypoint_too_long": {"body": profile(entrypoints=["a" * 600 + LEAK])},
            "too_many_entrypoints": {"body": profile(entrypoints=[f"f{i}.md" for i in range(40)])},
            "limits_not_an_object": {"body": profile(bootstrap_limits=[LEAK])},
            "limit_negative": {"body": profile(bootstrap_limits={"max_files": -1})},
            "limit_zero": {"body": profile(bootstrap_limits={"max_files": 0})},
            "limit_not_an_integer": {"body": profile(bootstrap_limits={"max_total_bytes": f"{LEAK}"})},
            "limit_bool": {"body": profile(bootstrap_limits={"max_files": True})},
            "limit_far_too_large": {"body": profile(bootstrap_limits={"max_total_bytes": 10**12})},
            "deeply_nested": {"raw": b"[" * 5000 + b"]" * 5000},
        }
        for label, case in cases.items():
            with self.subTest(case=label):
                self.write(f"{STATIC_ID}.json", case.get("body"), raw=case.get("raw"))
                snapshot = self.snapshot()
                context = snapshot["context_profile"]
                self.assertEqual(context.get("state"), "INVALID", context)
                self.assertIs(context["configured"], False)
                self.assertEqual(context["entrypoints"], [])
                self.assertIsInstance(context.get("problem"), str)
                self.assertNotIn(LEAK, json.dumps(snapshot))
                pack = self.bootstrap()
                self.assertEqual(pack["context_profile"].get("state"), "INVALID")
                self.assertEqual(pack["context_profile"]["entrypoints"], [])
                self.assertNotIn(LEAK, json.dumps(pack))
                self.assertIn("repository", pack, "an invalid profile must not take the rest of the pack down")

    def test_a_profile_that_is_a_link_is_invalid_not_followed(self) -> None:
        outside = self.world.base / "outside-profile.json"
        outside.write_text(json.dumps(profile(entrypoints=[f"{LEAK}.txt"])), encoding="utf-8")
        os.symlink(outside, self.store / f"{STATIC_ID}.json")
        snapshot = self.snapshot()
        self.assertEqual(snapshot["context_profile"].get("state"), "INVALID", snapshot["context_profile"])
        self.assertNotIn(LEAK, json.dumps(snapshot))

    def test_a_store_directory_that_is_a_link_is_invalid_not_followed(self) -> None:
        elsewhere = self.world.base / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / f"{STATIC_ID}.json").write_text(json.dumps(profile(entrypoints=[f"{LEAK}.txt"])), encoding="utf-8")
        self.store.rmdir()
        os.symlink(elsewhere, self.store)
        snapshot = self.snapshot()
        self.assertEqual(snapshot["context_profile"].get("state"), "INVALID", snapshot["context_profile"])
        self.assertNotIn(LEAK, json.dumps(snapshot))

    def test_a_profile_shared_by_hard_link_belongs_to_nobody_but_its_declared_owner(self) -> None:
        self.write("alias-one.json", profile("alias-one"))
        os.link(self.store / "alias-one.json", self.store / f"{STATIC_ID}.json")
        context = self.snapshot()["context_profile"]
        self.assertEqual(context.get("state"), "INVALID", context)

    def test_unknown_keys_are_tolerated_and_never_echoed(self) -> None:
        self.write(f"{STATIC_ID}.json", profile(note=LEAK, extra={"nested": LEAK}))
        snapshot = self.snapshot()
        self.assertEqual(snapshot["context_profile"].get("state"), "CONFIGURED")
        self.assertNotIn(LEAK, json.dumps(snapshot))
        self.assertNotIn(LEAK, json.dumps(self.bootstrap()))


class BootstrapLimitTests(ProfileCase):
    def test_the_configured_file_limit_is_enforced(self) -> None:
        self.write(f"{STATIC_ID}.json", profile(entrypoints=["README.md", "notes.txt", "other.txt"],
                                                bootstrap_limits={"max_files": 1, "max_total_bytes": 4096}))
        entries = self.bootstrap()["context_profile"]["entrypoints"]
        self.assertEqual([entry["path"] for entry in entries], ["README.md"])

    def test_the_byte_budget_is_enforced_and_the_request_can_only_lower_it(self) -> None:
        self.write(f"{STATIC_ID}.json", profile(entrypoints=["README.md", "notes.txt"],
                                                bootstrap_limits={"max_files": 4, "max_total_bytes": 4096}))
        entries = self.bootstrap(max_bytes=10)["context_profile"]["entrypoints"]
        self.assertLessEqual(sum(len(entry.get("content", "").encode()) for entry in entries), 10)

    def test_an_entrypoint_that_cannot_be_read_is_reported_without_a_reason_that_names_it(self) -> None:
        self.write(f"{STATIC_ID}.json", profile(entrypoints=["README.md", "missing-file.md"]))
        entries = self.bootstrap()["context_profile"]["entrypoints"]
        self.assertEqual([entry["path"] for entry in entries], ["README.md", "missing-file.md"])
        self.assertEqual(entries[1].get("error"), "not accessible")


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ProtocolTests(ProfileCase):
    def test_over_a_real_mcp_session_a_damaged_profile_is_a_result_with_a_state(self) -> None:
        self.write(f"{STATIC_ID}.json", raw=b"\xff\xfe not utf-8")
        for tool in ("uam_workspace_snapshot", "uam_session_bootstrap"):
            with self.subTest(tool=tool):
                is_error, text = run(call_protocol(self.world.server(), tool, workspace_id=STATIC_ID))
                self.assertFalse(is_error, text[:160])
                self.assertEqual(decode(text)["context_profile"].get("state"), "INVALID")


if __name__ == "__main__":
    unittest.main()
