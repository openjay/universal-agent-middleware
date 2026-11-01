"""The Context Profile loader (``context_profile``), below the tool surface: key, lookup, opening, validation, hygiene.

The tool-level behaviour (what a client sees, what r2 got wrong) is in ``test_r3_context_profile``; this module pins the
loader's own contract so that a refactor of either layer is caught at the layer that broke.
"""
from __future__ import annotations

import errno
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, get_args
from unittest import mock

from universal_agent_middleware import context_profile
from universal_agent_middleware.context_profile import (
    CONFIGURED, INVALID, MAX_PROFILE_BYTES, NOT_CONFIGURED, PROFILE_SCHEMA_VERSION, ContextProfile,
    load_context_profile, profile_key,
)
from universal_agent_middleware.resolver import ResolutionKind

STATIC = "static"


def body(key: str = "alpha", **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {"schema_version": PROFILE_SCHEMA_VERSION, "workspace_id": key, "entrypoints": ["README.md"]}
    document.update(overrides)
    return document


def open_descriptors() -> int:
    return len(os.listdir("/dev/fd"))


class KeyTests(unittest.TestCase):
    def test_the_registered_kind_is_the_resolvers_kind(self) -> None:
        self.assertIn(context_profile.REGISTERED_RESOLUTION_KIND, get_args(ResolutionKind))

    def test_only_a_registered_identity_with_a_registry_grammar_id_has_a_key(self) -> None:
        self.assertEqual(profile_key("alpha", STATIC), "alpha")
        self.assertEqual(profile_key("Alpha.v2-x_1", STATIC), "Alpha.v2-x_1")
        for kind in ("derived", "absolute_path", "project_name"):
            with self.subTest(kind=kind):
                self.assertIsNone(profile_key("alpha", kind))

    def test_no_string_that_could_steer_a_path_is_a_key(self) -> None:
        hostile = (
            "", ".", "..", "../x", "a/b", "/abs/path", "a\\b", "derived:scope:repo", "-lead", ".hidden", "a" * 65,
            "a b", "a\x00b", "caf\u00e9", "alpha.json/..",
        )
        for text in hostile:
            with self.subTest(text=text):
                self.assertIsNone(profile_key(text, STATIC))


class LoaderCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-r3-profile-")
        self.addCleanup(self._tmp.cleanup)
        self.config = Path(self._tmp.name).resolve() / "config"
        self.store = self.config / "workspace-contexts"
        self.store.mkdir(parents=True)

    def put(self, name: str, document: Any = None, *, raw: bytes | None = None) -> Path:
        path = self.store / name
        path.write_bytes(raw if raw is not None else json.dumps(document).encode("utf-8"))
        return path

    def load(self, key: str = "alpha", kind: str = STATIC) -> ContextProfile:
        return load_context_profile(self.config, workspace_id=key, resolution_kind=kind)


class StateTests(LoaderCase):
    def test_absent_is_not_configured_and_carries_no_problem(self) -> None:
        result = self.load()
        self.assertEqual((result.state, result.problem, result.configured), (NOT_CONFIGURED, None, False))

    def test_a_valid_profile_is_configured_with_normalised_entrypoints_and_default_limits(self) -> None:
        self.put("alpha.json", body(entrypoints=["./README.md", "docs//guide.md"]))
        result = self.load()
        self.assertEqual(result.state, CONFIGURED)
        self.assertEqual(result.entrypoints, ("README.md", "docs/guide.md"))
        self.assertEqual((result.max_files, result.max_total_bytes), (8, 131_072))

    def test_a_profile_without_entrypoints_is_valid_and_empty(self) -> None:
        document = body()
        del document["entrypoints"]
        self.put("alpha.json", document)
        self.assertEqual((self.load().state, self.load().entrypoints), (CONFIGURED, ()))

    def test_a_non_registered_kind_never_reads_the_store(self) -> None:
        self.put("alpha.json", body())
        with mock.patch("os.scandir", side_effect=AssertionError("the store must not be listed")):
            self.assertEqual(self.load(kind="derived").state, NOT_CONFIGURED)

    def test_the_report_has_a_stable_shape_and_never_a_problem_for_a_good_state(self) -> None:
        self.put("alpha.json", body())
        good = self.load().report()
        self.assertEqual(set(good), {"configured", "state", "entrypoints"})
        bad = self.load("beta-without-file").report()
        self.assertEqual(bad["state"], NOT_CONFIGURED)
        self.put("beta.json", raw=b"{")
        broken = self.load("beta").report()
        self.assertEqual(set(broken), {"configured", "state", "entrypoints", "problem"})
        self.assertEqual((broken["configured"], broken["state"], broken["entrypoints"]), (False, INVALID, []))

    def test_report_can_carry_read_results_in_place_of_the_names(self) -> None:
        self.put("alpha.json", body())
        self.assertEqual(self.load().report([{"path": "README.md"}])["entrypoints"], [{"path": "README.md"}])


class LookupTests(LoaderCase):
    def test_the_entry_is_matched_by_its_exact_listed_name_not_by_a_name_the_volume_folds(self) -> None:
        self.put("alpha.json", body("alpha"))
        self.assertEqual(self.load("alpha").state, CONFIGURED)
        self.assertEqual(self.load("Alpha").state, NOT_CONFIGURED)  # even where the volume would open alpha.json for it
        self.assertEqual(self.load("ALPHA").state, NOT_CONFIGURED)

    def test_a_directory_in_place_of_the_file_is_invalid(self) -> None:
        (self.store / "alpha.json").mkdir()
        self.assertEqual((self.load().state, self.load().problem), (INVALID, "profile_not_a_regular_file"))

    def test_a_missing_config_directory_is_not_configured(self) -> None:
        result = load_context_profile(self.config / "gone", workspace_id="alpha", resolution_kind=STATIC)
        self.assertEqual(result.state, NOT_CONFIGURED)

    def test_a_store_with_too_many_entries_is_refused_not_guessed(self) -> None:
        with mock.patch.object(context_profile, "MAX_STORE_ENTRIES_SCANNED", 3):
            for index in range(5):
                self.put(f"other-{index}.json", body(f"other-{index}"))
            result = self.load()
        self.assertEqual((result.state, result.problem), (INVALID, "store_too_large"))

    def test_a_listing_failure_is_invalid_not_unconfigured(self) -> None:
        self.put("alpha.json", body())
        with mock.patch("os.scandir", side_effect=PermissionError(errno.EACCES, "denied")):
            result = self.load()
        self.assertEqual((result.state, result.problem), (INVALID, "store_unreadable"))

    def test_an_unreadable_profile_is_invalid_not_unconfigured(self) -> None:
        path = self.put("alpha.json", body())
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        result = self.load()
        self.assertEqual((result.state, result.problem), (INVALID, "profile_unreadable"))


class RaceTests(LoaderCase):
    def test_a_profile_swapped_for_a_link_between_listing_and_opening_is_not_followed(self) -> None:
        marker = "RACE-MARKER-0042"
        outside = self.config.parent / "outside.json"
        outside.write_text(json.dumps(body(entrypoints=[f"{marker}.txt"])), encoding="utf-8")
        path = self.put("alpha.json", body())
        real_open = os.open
        swapped: list[bool] = []

        def racing_open(name, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is not None and name == "alpha.json" and not swapped:
                swapped.append(True)
                path.unlink()
                os.symlink(outside, path)
            return real_open(name, flags, mode) if dir_fd is None else real_open(name, flags, mode, dir_fd=dir_fd)

        with mock.patch("os.open", racing_open):
            result = self.load()
        self.assertTrue(swapped, "the race never ran")
        self.assertEqual((result.state, result.problem), (INVALID, "profile_not_a_regular_file"))
        self.assertEqual(result.entrypoints, ())


class ValidationTests(LoaderCase):
    def invalid(self, problem: str, **kwargs: Any) -> None:
        self.put("alpha.json", **kwargs)
        result = self.load()
        self.assertEqual((result.state, result.problem), (INVALID, problem))
        self.assertEqual((result.entrypoints, result.configured), ((), False))

    def test_encoding_syntax_and_shape(self) -> None:
        self.invalid("profile_encoding", raw=b"\xff\xfe{}")
        self.invalid("profile_syntax", raw=b"{ nope")
        self.invalid("profile_syntax", raw=b"\xef\xbb\xbf" + json.dumps(body()).encode())  # a BOM is not JSON
        self.invalid("profile_syntax", raw=b'{"schema_version": NaN}')
        self.invalid("profile_not_an_object", document=[body()])

    def test_deeply_nested_input_is_invalid_and_never_a_crash(self) -> None:
        # Which refusal it gets depends on the interpreter (older ones raise RecursionError, newer ones parse a list).
        self.put("alpha.json", raw=b"[" * 5000 + b"]" * 5000)
        result = self.load()
        self.assertEqual(result.state, INVALID)
        self.assertIn(result.problem, {"profile_syntax", "profile_not_an_object"})

    def test_the_size_budget_is_counted_on_the_bytes_read(self) -> None:
        self.invalid("profile_too_large", raw=b" " * (MAX_PROFILE_BYTES + 1) + json.dumps(body()).encode())
        self.put("alpha.json", raw=json.dumps(body(pad="x" * (MAX_PROFILE_BYTES - 200))).encode())
        self.assertEqual(self.load().state, CONFIGURED)  # just under the budget is accepted

    def test_schema_and_owner(self) -> None:
        self.invalid("profile_schema", document=body(schema_version="workspace-context-profile-v2"))
        self.invalid("profile_schema", document={k: v for k, v in body().items() if k != "schema_version"})
        self.invalid("profile_owner", document=body("beta"))
        self.invalid("profile_owner", document=body(workspace_id=None))
        self.invalid("profile_owner", document=body(workspace_id="ALPHA"))  # exact, not folded

    def test_entrypoints(self) -> None:
        for entrypoints in (
            "README.md", [1], [None], [""], ["."], ["/etc/hosts"], ["../x"], ["a/../../x"], [".env"], ["docs/.ssh/config"],
            ["a\x00b"], ["x" * 513], [f"f{index}.md" for index in range(33)], {"a": 1},
        ):
            with self.subTest(entrypoints=str(entrypoints)[:40]):
                self.invalid("profile_entrypoints", document=body(entrypoints=entrypoints))

    def test_limits(self) -> None:
        for limits in (
            [], "x", None, {"max_files": 0}, {"max_files": 33}, {"max_files": -1}, {"max_files": 1.5}, {"max_files": True},
            {"max_total_bytes": 0}, {"max_total_bytes": 1_048_577}, {"max_total_bytes": "9"}, {"max_total_bytes": None},
        ):
            with self.subTest(limits=str(limits)):
                self.invalid("profile_limits", document=body(bootstrap_limits=limits))

    def test_limits_at_the_boundaries_are_accepted_and_extras_are_ignored(self) -> None:
        self.put("alpha.json", body(bootstrap_limits={"max_files": 32, "max_total_bytes": 1_048_576, "extra": "ignored"},
                                    unknown="ignored"))
        result = self.load()
        self.assertEqual((result.state, result.max_files, result.max_total_bytes), (CONFIGURED, 32, 1_048_576))

    def test_a_hard_link_under_another_name_is_not_a_profile_for_that_name(self) -> None:
        path = self.put("alpha.json", body("alpha"))
        os.link(path, self.store / "beta.json")
        self.assertEqual(self.load("alpha").state, CONFIGURED)
        self.assertEqual((self.load("beta").state, self.load("beta").problem), (INVALID, "profile_owner"))


class HygieneTests(LoaderCase):
    def test_no_outcome_leaks_a_descriptor(self) -> None:
        self.put("alpha.json", body())
        self.put("broken.json", raw=b"{")
        (self.store / "dir.json").mkdir()
        before = open_descriptors()
        for key in ("alpha", "broken", "dir", "absent", "Alpha"):
            for _ in range(5):
                self.load(key)
        self.assertEqual(open_descriptors(), before)


if __name__ == "__main__":
    unittest.main()
