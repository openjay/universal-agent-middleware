"""The scope search decides authority before it reads: a denied file is never opened.

``uam_search_scope`` used to hand ripgrep the scope root and a list of exclusion globs, then drop the
hits that authority did not allow. The globs are anchored to ripgrep's working directory, not to the
scope root, so they excluded nothing: ripgrep opened and read every denied file, and only the answer
was filtered. "Filter the output" is a second layer, not authorisation.

These tests watch the *process*, not just the response, with three independent sentinels (see
``scope_search_instruments``): a file's access time, the operands and descriptors ripgrep is given,
and the objects Python itself opens or lists. They also pin that the response is the same whatever a
denied or secret path contains, so it is not an oracle for that content.

Each test uses a fresh tree; "the control" is an allowed file the search must find, which proves the
sentinel could see a read (otherwise the test is skipped, never passed).
"""
from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from directory_fixtures import SCOPE_ID, WorldTestCase, authority
from scope_search_instruments import (
    DESCRIPTOR_OPERAND,
    AtimeSentinel,
    OpenSpy,
    RunRecorder,
    identity_of,
)

TOKEN = "UAM-BOUNDARY-TOKEN"
SCOPE = "search"


class BoundaryCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-scope-boundary-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.sentinel = AtimeSentinel()

    def write(self, relative: str, text: str, *, root: Path | None = None) -> Path:
        path = (root or self.root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def registry(
        self, *, deny: tuple[str, ...] = (), allow: tuple[str, ...] = (), root: Path | None = None,
        scope_root: Path | None = None,
    ) -> RootScopeRegistry:
        base = root or self.root
        scopes = RootScopeRegistry()
        scopes.add_scope(RootScope(
            scope_id=SCOPE, root=str(scope_root or base), authority=RootScopeAuthority(text_search=True),
        ))
        for relative in deny:
            scopes.add_scope(RootScope(
                scope_id=f"deny:{relative}", root=str(base / relative), authority=RootScopeAuthority(),
            ))
        for relative in allow:
            scopes.add_scope(RootScope(
                scope_id=f"allow:{relative}", root=str(base / relative),
                authority=RootScopeAuthority(text_search=True),
            ))
        return scopes

    def observe(
        self, registry: RootScopeRegistry, query: str = TOKEN, *, before_run: Any = None,
    ) -> tuple[dict[str, Any], RunRecorder, OpenSpy]:
        engine = DiscoveryEngine(registry)
        engine.scope_inventory(SCOPE)  # attribution reads the inventory: warm it outside the measurement
        recorder = RunRecorder(before_run=before_run)
        spy = OpenSpy()
        with recorder.patch(), spy.patch():
            result = engine.search_scope(SCOPE, query)
        return result, recorder, spy

    @staticmethod
    def paths(result: dict[str, Any]) -> list[str]:
        """The distinct hit paths: repetition is pinned by its own test, not folded into each property."""
        return sorted({hit["path"] for hit in result["results"]})


class EveryHitIsReportedOnceTests(BoundaryCase):
    def test_a_file_is_reported_once_however_the_scope_is_carved_up(self) -> None:
        self.write("public/control.txt", f"{TOKEN} control\n")
        self.write("allowed/ok.txt", f"{TOKEN} ok\n")
        self.write("denied/pocket/open.txt", f"{TOKEN} pocket\n")
        registry = self.registry(deny=("denied", "allowed/denied-child"), allow=("denied/pocket",))

        result, _recorder, _spy = self.observe(registry)

        reported = [hit["path"] for hit in result["results"]]
        self.assertEqual(sorted(reported), sorted(set(reported)), "a file was reported more than once")
        self.assertEqual(result["total_matches"], len(set(reported)))


class DeniedZonesAreNeverReadTests(BoundaryCase):
    def test_a_denied_child_of_an_allowed_area_is_never_read(self) -> None:
        child = self.write("allowed/denied-child/x.txt", f"{TOKEN} child\n")
        control = self.write("allowed/ok.txt", f"{TOKEN} ok\n")
        registry = self.registry(deny=("allowed/denied-child",))
        self.sentinel.arm(child, control)

        result, recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["allowed/ok.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(child), "ripgrep read a file that scope authority denies")
        self.assertNotIn(identity_of(child), spy.opened)
        self.assertNotIn(identity_of(child), recorder.handed_identities)

    def test_an_allowed_scope_inside_a_denied_parent_is_found_and_the_parent_is_not_read(self) -> None:
        blocked = self.write("denied/blocked.txt", f"{TOKEN} blocked\n")
        pocket = self.write("denied/pocket/open.txt", f"{TOKEN} pocket\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",), allow=("denied/pocket",))
        self.sentinel.arm(blocked, pocket, control)

        result, recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["denied/pocket/open.txt", "public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(blocked), "a denied parent's own file was read")
        self.assertTrue(self.sentinel.was_read(pocket), "the allowed pocket inside it was not searched")
        self.assertNotIn(identity_of(blocked), spy.opened)
        self.assertNotIn(identity_of(self.root / "denied"), spy.listed, "a denied directory was listed")

    def test_a_case_alias_of_a_denied_scope_is_never_read(self) -> None:
        secret = self.write("Evidence/secret.txt", f"{TOKEN} secret\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("evidence",))  # spelled differently from the directory on disk
        self.sentinel.arm(secret, control)

        result, _recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(secret), "an alias spelled in another case was read")
        self.assertNotIn(identity_of(secret), spy.opened)

    def test_a_normalization_alias_of_a_denied_scope_is_never_read(self) -> None:
        decomposed = unicodedata.normalize("NFD", "caf\u00e9")
        composed = unicodedata.normalize("NFC", "caf\u00e9")
        self.assertNotEqual(decomposed, composed)
        secret = self.write(f"{decomposed}/secret.txt", f"{TOKEN} secret\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=(composed,))
        self.sentinel.arm(secret, control)

        result, _recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(secret), "an alias in another Unicode form was read")
        self.assertNotIn(identity_of(secret), spy.opened)

    def test_a_scope_root_reached_through_a_symlink_keeps_its_nested_denials(self) -> None:
        real = self.root / "real"
        secret = self.write("denied/secret.txt", f"{TOKEN} secret\n", root=real)
        control = self.write("public/control.txt", f"{TOKEN} control\n", root=real)
        link = self.root / "scope-link"
        link.symlink_to(real, target_is_directory=True)
        registry = self.registry(deny=("denied",), root=real, scope_root=link)
        self.sentinel.arm(secret, control)

        result, _recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(secret), "a nested denial was lost behind a symlinked root")
        self.assertNotIn(identity_of(secret), spy.opened)


class AliasesOfDeniedFilesTests(BoundaryCase):
    def test_a_hard_link_to_a_denied_file_is_not_read_through_its_allowed_name(self) -> None:
        denied = self.write("denied/secret.txt", f"{TOKEN} secret\n")
        os.link(denied, self.root / "public-alias.txt")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",))
        self.sentinel.arm(denied, control)

        result, recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/control.txt"], "the denied bytes were reported under another name")
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(denied), "the denied inode was read through a hard link")
        self.assertNotIn(identity_of(denied), recorder.handed_identities)

    def test_hard_links_are_searched_as_before_when_no_scope_denies_search(self) -> None:
        shared = self.write("public/one.txt", f"{TOKEN} shared\n")
        os.link(shared, self.root / "public" / "two.txt")
        registry = self.registry()

        result, _recorder, _spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/one.txt", "public/two.txt"])

    def test_symlinks_into_a_denied_scope_are_not_followed(self) -> None:
        denied = self.write("denied/secret.txt", f"{TOKEN} secret\n")
        (self.root / "public").mkdir()
        (self.root / "public" / "link-dir").symlink_to(self.root / "denied", target_is_directory=True)
        (self.root / "public" / "link-file").symlink_to(denied)
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",))
        self.sentinel.arm(denied, control)

        result, _recorder, spy = self.observe(registry)

        self.assertEqual(self.paths(result), ["public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(denied))
        self.assertNotIn(identity_of(denied), spy.opened)


class ReplacementAfterAuthorisationTests(BoundaryCase):
    def test_a_name_swapped_for_a_hard_link_after_authorisation_cannot_redirect_the_read(self) -> None:
        denied = self.write("denied/secret.txt", f"{TOKEN} secret\n")
        target = self.write("public/target.txt", f"{TOKEN} target\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",))
        self.sentinel.arm(denied, control)

        def swap(_record: Any) -> None:
            target.unlink()
            os.link(denied, target)

        self.observe(registry, before_run=swap)

        self.sentinel.require_alive(self, control)
        self.assertFalse(
            self.sentinel.was_read(denied),
            "a name replaced after authorisation was re-opened and the denied inode was read",
        )

    def test_a_name_swapped_for_a_symlink_after_authorisation_cannot_redirect_the_read(self) -> None:
        denied = self.write("denied/secret.txt", f"{TOKEN} secret\n")
        target = self.write("public/target.txt", f"{TOKEN} target\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",))
        self.sentinel.arm(denied, control)

        def swap(_record: Any) -> None:
            target.unlink()
            target.symlink_to(denied)

        self.observe(registry, before_run=swap)

        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(denied), "a symlink planted after authorisation was followed")


class RipgrepIsHandedOnlyAuthorisedDescriptorsTests(BoundaryCase):
    def test_ripgrep_is_given_descriptors_and_never_a_path(self) -> None:
        self.write("public/control.txt", f"{TOKEN} control\n")
        self.write("allowed/ok.txt", f"{TOKEN} ok\n")
        self.write("allowed/denied-child/x.txt", f"{TOKEN} child\n")
        registry = self.registry(deny=("allowed/denied-child",))

        _result, recorder, _spy = self.observe(registry)

        self.assertTrue(recorder.ripgrep_calls, "ripgrep was never run")
        offenders = [operand for operand in recorder.operands if not DESCRIPTOR_OPERAND.fullmatch(operand)]
        self.assertEqual(offenders, [], "ripgrep was handed a path and will reopen it itself")

    def test_ripgrep_only_receives_authorised_regular_files(self) -> None:
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        allowed = self.write("allowed/ok.txt", f"{TOKEN} ok\n")
        child = self.write("allowed/denied-child/x.txt", f"{TOKEN} child\n")
        blocked = self.write("denied/blocked.txt", f"{TOKEN} blocked\n")
        pocket = self.write("denied/pocket/open.txt", f"{TOKEN} pocket\n")
        os.link(blocked, self.root / "public" / "alias.txt")
        registry = self.registry(deny=("allowed/denied-child", "denied"), allow=("denied/pocket",))

        _result, recorder, _spy = self.observe(registry)

        handed = recorder.handed_identities
        self.assertTrue(handed, "ripgrep was handed no descriptor")
        self.assertEqual(handed, {identity_of(control), identity_of(allowed), identity_of(pocket)})
        self.assertFalse(handed & {identity_of(child), identity_of(blocked)})
        for call in recorder.ripgrep_calls:
            for _descriptor, _identity, mode in call.descriptor_identities:
                self.assertTrue(stat.S_ISREG(mode))


class NoOracleTests(BoundaryCase):
    def respond(self, *, denied_contains: bool, secret_contains: bool) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="uam-scope-oracle-") as tmp:
            root = Path(os.path.realpath(tmp))
            needle = "UAM-ONLY-IN-WITHHELD-PLACES"
            self.write("public/control.txt", "unrelated control text\n", root=root)
            self.write("denied/blocked.txt", f"{needle}\n" if denied_contains else "nothing here\n", root=root)
            self.write(".env", f"{needle}\n" if secret_contains else "nothing here\n", root=root)
            self.write("credentials/token.txt", f"{needle}\n" if secret_contains else "nothing here\n", root=root)
            engine = DiscoveryEngine(self.registry(deny=("denied",), root=root))
            return engine.search_scope(SCOPE, needle)

    def test_the_response_does_not_depend_on_what_a_denied_scope_contains(self) -> None:
        with_content = self.respond(denied_contains=True, secret_contains=False)
        without_content = self.respond(denied_contains=False, secret_contains=False)
        self.assertEqual(with_content, without_content)
        self.assertIs(with_content["absent_within_search_domain"], True)
        self.assertIs(with_content["search_domain"]["scope_authority_exclusions"], True)
        self.assertIn("scope_authority", with_content["search_domain"]["not_covered"])

    def test_the_response_does_not_depend_on_what_a_secret_path_contains(self) -> None:
        with_content = self.respond(denied_contains=False, secret_contains=True)
        without_content = self.respond(denied_contains=False, secret_contains=False)
        self.assertEqual(with_content, without_content)
        self.assertEqual(with_content["results"], [])

    def test_secret_paths_are_never_read(self) -> None:
        env = self.write(".env", f"{TOKEN} secret\n")
        token = self.write("credentials/token.txt", f"{TOKEN} secret\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        self.sentinel.arm(env, token, control)

        result, _recorder, spy = self.observe(self.registry())

        self.assertEqual(self.paths(result), ["public/control.txt"])
        self.sentinel.require_alive(self, control)
        self.assertFalse(self.sentinel.was_read(env))
        self.assertFalse(self.sentinel.was_read(token))
        self.assertNotIn(identity_of(env), spy.opened)


class HitsAndMissesTests(BoundaryCase):
    def test_a_query_that_matches_nothing_reads_no_denied_file_either(self) -> None:
        denied = self.write("denied/blocked.txt", f"{TOKEN} blocked\n")
        control = self.write("public/control.txt", f"{TOKEN} control\n")
        registry = self.registry(deny=("denied",))
        self.sentinel.arm(denied, control)

        result, _recorder, _spy = self.observe(registry, query="UAM-MATCHES-NOTHING-ANYWHERE")

        self.assertEqual(result["results"], [])
        self.assertFalse(self.sentinel.was_read(denied))
        self.assertIs(result["absent_within_search_domain"], True)


class RevokedLocatorTests(WorldTestCase):
    def test_a_locator_from_before_a_revocation_stops_working_and_the_hit_disappears(self) -> None:
        gateway = self.world.gateway()
        found = gateway.search_scope(SCOPE_ID, "needle-nested")
        hits = [hit for hit in found["results"] if hit["path"].endswith("notes/nested.md")]
        self.assertEqual(len(hits), 1, found["results"])
        locator = hits[0]["locator"]
        self.assertIn("needle-nested", gateway.read_file(locator["workspace_id"], locator["path"])["content"])

        gateway.scopes.add_scope(RootScope(
            scope_id="revoked", root=str(self.world.plain / "notes"),
            authority=authority(content_read=False, text_search=False),
        ))

        with self.assertRaises(WorkspaceError):
            gateway.read_file(locator["workspace_id"], locator["path"])
        again = gateway.search_scope(SCOPE_ID, "needle-nested")
        self.assertEqual([hit for hit in again["results"] if hit["path"].endswith("notes/nested.md")], [])


if __name__ == "__main__":
    unittest.main()
