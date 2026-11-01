"""S1-B / S1-E: what a tool DERIVES from files, remotes and old index rows obeys the rules of what it reads.

Three derived surfaces, each with the counterexample that made it a defect:

* a remote URL that embeds a token was returned as the repository identity (discovery, exploration evidence, the
  persisted reality index) -> ``strip_url_credentials``;
* exploration read ``.env.example`` (and four other project-root files) by path, with no scope check, and returned a
  sample taken from the content -> descriptor reads under the Reader's rules, no dotenv-family file;
* a reality index written by an older release (or an older sensitive-name policy) was served again by a new
  process -> rows are bound to ``SENSITIVE_POLICY_VERSION`` and never read under another one.

Every guarantee has a control that shows the scenario really produces the leak without the fix, so a pass cannot
be a test that never exercised the path.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from universal_agent_middleware import descriptor_io
from universal_agent_middleware import reality_index as reality_index_module
from universal_agent_middleware.discovery import DiscoveryEngine, strip_url_credentials
from universal_agent_middleware.exploration import ExplorationEngine
from universal_agent_middleware.reality_index import POLICY_BINDING, RealityIndex, bind_policy
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from s1_instruments import OpenOracle, alarm
from synthetic_fixtures import init_git_repo

needs_symlinks = unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
needs_fifo = unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")

TOKEN = "ghp_S1FictionalRemoteToken0042"
BODY = "S1_FICTIONAL_DENIED_BODY_0042"
RUNTIME_TEXT = "run it with docker compose up\n"


def authority(**overrides: bool) -> RootScopeAuthority:
    base = dict(
        discover=True, metadata_read=True, content_read=True, text_search=True, git_observe=True,
        classify=True, index=True, relate=True, auto_admit=True,
    )
    return RootScopeAuthority(**{**base, **overrides})


def registry_for(root: Path, **overrides: bool) -> RootScopeRegistry:
    registry = RootScopeRegistry()
    registry.add_scope(RootScope(scope_id="s", root=str(root), authority=authority(**overrides)))
    return registry


class StripUrlCredentialsTests(unittest.TestCase):
    UNCHANGED = (
        "ssh://git@host/acme/widget.git",
        "git@github.com:acme/widget.git",
        "/srv/git/widget.git",
        "../relative/widget",
        "file:///srv/git/widget.git",
        "https://github.com/acme/widget",
        "https://github.com/acme/widget@v1",  # an @ after the first slash is path, not a user part
        "http://[::1]:8080/acme/widget",
        "",
    )
    STRIPPED = (
        ("https://user:TOKEN@github.com/acme/widget.git", "https://github.com/acme/widget.git"),
        ("https://TOKEN@github.com/acme/widget", "https://github.com/acme/widget"),
        (
            "https://oauth2:TOKEN@gitlab.example.com/acme/widget.git?private_token=TOKEN#frag",
            "https://gitlab.example.com/acme/widget.git",
        ),
        ("http://user:p%2Fss@host:8080/acme/widget", "http://host:8080/acme/widget"),
        ("https://user:p@ss@github.com/acme/widget", "https://github.com/acme/widget"),  # last @ ends the user part
        ("https://TOKEN@[::1]:8443/acme/widget", "https://[::1]:8443/acme/widget"),
        ("git+https://TOKEN@host/acme/widget", "git+https://host/acme/widget"),
        ("ftp://user:TOKEN@host/acme/widget", "ftp://host/acme/widget"),
        ("ssh://git:TOKEN@host/acme/widget.git", "ssh://git@host/acme/widget.git"),  # the account stays, the password goes
        ("HTTPS://user:TOKEN@github.com/acme/widget", "HTTPS://github.com/acme/widget"),
    )

    def test_a_url_with_nothing_to_strip_comes_back_unchanged(self) -> None:
        for url in self.UNCHANGED:
            with self.subTest(url=url):
                self.assertEqual(strip_url_credentials(url), url)

    def test_credentials_and_query_strings_are_removed(self) -> None:
        for url, expected in self.STRIPPED:
            with self.subTest(url=url):
                result = strip_url_credentials(url)
                self.assertEqual(result, expected)
                self.assertNotIn("TOKEN", result)

    def test_normalized_identity_never_carries_a_credential(self) -> None:
        engine = DiscoveryEngine(RootScopeRegistry())
        cases = {
            "https://user:TOKEN@github.com/acme/widget.git": "acme/widget",
            "https://TOKEN@gitlab.com/acme/widget.git?x=1": "acme/widget",
            "git@github.com:acme/widget.git": "acme/widget",
            "https://oauth2:TOKEN@gitlab.example.com/acme/widget.git": "https://gitlab.example.com/acme/widget",
        }
        for url, identity in cases.items():
            with self.subTest(url=url):
                self.assertEqual(engine._normalize_remote(url), identity)


class RemoteIdentityEndToEndTests(unittest.TestCase):
    """A real repository whose ``origin`` embeds a token, observed through the real discovery/exploration/index."""

    def setUp(self) -> None:
        scope_tmp = tempfile.TemporaryDirectory(prefix="uam-s1-remote-")
        state_tmp = tempfile.TemporaryDirectory(prefix="uam-s1-remote-state-")
        self.addCleanup(scope_tmp.cleanup)
        self.addCleanup(state_tmp.cleanup)
        self.root = Path(scope_tmp.name).resolve()
        self.state = Path(state_tmp.name).resolve()
        self.repo = self.root / "widget"
        init_git_repo(self.repo, files={"README.md": "# widget\n"})
        url = f"https://octo:{TOKEN}@github.com/acme/widget.git?private_token={TOKEN}"
        subprocess.run(
            ["git", "remote", "add", "origin", url], cwd=str(self.repo), check=True, capture_output=True, timeout=10,
        )
        self.registry = registry_for(self.root)
        self.index = RealityIndex(self.state)
        self.discovery = DiscoveryEngine(self.registry, reality_index=self.index)

    def inventory(self) -> dict:
        return self.discovery.scope_inventory("s", enrich_git=True, git_budget=10)

    def index_dump(self) -> str:
        """Every text value stored in the index database, whatever table or column holds it."""
        connection = sqlite3.connect(str(self.index._db_path))
        try:
            parts: list[str] = []
            for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
                for row in connection.execute(f"SELECT * FROM {table}").fetchall():  # noqa: S608 (names from sqlite_master)
                    parts.extend(str(value) for value in row)
            return "\n".join(parts)
        finally:
            connection.close()

    def test_the_inventory_names_the_repository_without_the_token(self) -> None:
        inventory = self.inventory()
        identities = [project["remote_identity"] for project in inventory["projects"]]
        self.assertEqual(identities, ["acme/widget"])
        self.assertNotIn(TOKEN, json.dumps(inventory))

    def test_the_persisted_index_never_holds_the_token(self) -> None:
        self.inventory()
        dump = self.index_dump()
        self.assertIn("acme/widget", dump)  # the index really was written
        self.assertNotIn(TOKEN, dump)
        self.assertEqual([entry.remote_identity for entry in self.index.lookup_by_alias("widget")], ["acme/widget"])

    def test_exploration_evidence_does_not_echo_the_remote(self) -> None:
        inventory = self.inventory()
        project_id = inventory["projects"][0]["project_id"]
        exploration = ExplorationEngine(self.discovery, self.registry)
        for result in (
            exploration.explain_coverage("s", project_id),
            exploration.what_am_i_missing("s"),
            exploration.explore("s", intent="widget ci", max_projects=5, max_files=10),
        ):
            self.assertNotIn(TOKEN, json.dumps(result))

    def test_control_without_the_fix_the_same_scenario_leaks(self) -> None:
        with mock.patch("universal_agent_middleware.discovery.strip_url_credentials", lambda url: url):
            inventory = self.inventory()
        self.assertIn(TOKEN, json.dumps(inventory))


@needs_symlinks
class ExplorationRuntimeRefTests(unittest.TestCase):
    """``_detect_code_runtime_refs`` reads fixed project-root files; it does so under the Reader's rules."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-s1-explore-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "scope"
        self.project = self.root / "proj"
        self.outside = self.base / "outside"
        self.project.mkdir(parents=True)
        self.outside.mkdir()

    def refs(self, registry: RootScopeRegistry | None = None) -> list[str]:
        registry = registry or registry_for(self.root)
        return ExplorationEngine(DiscoveryEngine(registry), registry)._detect_code_runtime_refs(self.project)

    def write(self, name: str, text: str) -> Path:
        path = self.project / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_fixed_files_still_yield_hints(self) -> None:
        self.write("README.md", RUNTIME_TEXT)
        self.write("pyproject.toml", "[tool]\nurl = 'localhost:8080'\n")
        refs = self.refs()
        self.assertEqual([ref.split(":", 1)[0] for ref in refs], ["pyproject.toml", "README.md"])

    def test_a_dotenv_template_is_never_opened_and_its_body_changes_nothing(self) -> None:
        template = self.write(".env.example", f"OPENAI_API_KEY={BODY}\n")
        oracle = OpenOracle([template])
        with oracle.watching():
            first = self.refs()
        template.write_text("OPENAI_API_KEY=a-completely-different-fictional-value\n", encoding="utf-8")
        with oracle.watching():
            second = self.refs()
        self.assertEqual(first, [])
        self.assertEqual(second, first)
        self.assertEqual(oracle.violations, [])

    def test_a_scope_without_content_read_reads_nothing(self) -> None:
        readme = self.write("README.md", RUNTIME_TEXT)
        reads: list[int] = []
        real_read = os.read
        identity = (os.stat(readme).st_dev, os.stat(readme).st_ino)

        def recording(descriptor, count):
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == identity:
                reads.append(count)
            return real_read(descriptor, count)

        with mock.patch("os.read", recording):
            denied = self.refs(registry_for(self.root, content_read=False))
            self.assertEqual(reads, [])  # not one byte was requested from the file
            allowed = self.refs()
            self.assertTrue(reads)  # control: the instrument does see a read where reading is granted
        self.assertEqual(denied, [])
        self.assertEqual(len(allowed), 1)  # ...and the same file does yield a hint there

    def test_a_link_to_a_denied_name_is_not_followed(self) -> None:
        secret = self.write(".secrets.env", f"docker compose up {BODY}\n")
        (self.project / "README.md").symlink_to(".secrets.env")
        oracle = OpenOracle([secret])
        with oracle.watching():
            first = self.refs()
        secret.write_text("docker compose up another-fictional-body\n", encoding="utf-8")
        with oracle.watching():
            second = self.refs()
        self.assertEqual(first, [])
        self.assertEqual(second, first)
        self.assertEqual(oracle.violations, [])

    def test_a_link_out_of_the_project_is_not_followed(self) -> None:
        target = self.outside / "notes.md"
        target.write_text(RUNTIME_TEXT, encoding="utf-8")
        (self.project / "README.md").symlink_to(target)
        oracle = OpenOracle([target])
        with oracle.watching():
            self.assertEqual(self.refs(), [])
        self.assertEqual(oracle.violations, [])

    def test_a_hard_link_into_a_narrower_scope_is_refused(self) -> None:
        private = self.project / "private"
        private.mkdir()
        (private / "notes.md").write_text(RUNTIME_TEXT, encoding="utf-8")
        os.link(private / "notes.md", self.project / "README.md")
        registry = registry_for(self.root)
        registry.add_scope(RootScope(scope_id="inner", root=str(private), authority=authority(content_read=False)))
        self.assertEqual(self.refs(registry), [])
        # Control: a plain file with the same text, in the same scopes, does yield a hint.
        (self.project / "README.md").unlink()
        self.write("README.md", RUNTIME_TEXT)
        self.assertEqual(len(self.refs(registry)), 1)

    def test_a_name_swapped_after_validation_is_never_followed(self) -> None:
        protected = self.outside / "protected.txt"
        protected.write_text(f"docker compose up {BODY}\n", encoding="utf-8")
        readme = self.write("README.md", "# harmless\n")
        real_open_child = descriptor_io.open_child
        fired: list[bool] = []

        def swap_then_open(name, dir_fd, *, directory):
            if name == "README.md" and not fired:
                fired.append(True)
                readme.unlink()
                readme.symlink_to(protected)
            return real_open_child(name, dir_fd, directory=directory)

        oracle = OpenOracle([protected])
        with oracle.watching(), mock.patch.object(descriptor_io, "open_child", swap_then_open):
            refs = self.refs()
        self.assertTrue(fired)  # the race really was injected
        self.assertEqual(refs, [])
        self.assertEqual(oracle.violations, [])

    @needs_fifo
    def test_a_fifo_with_a_runtime_file_name_is_not_opened(self) -> None:
        os.mkfifo(self.project / "README.md")
        with alarm():
            self.assertEqual(self.refs(), [])

    def test_a_file_over_the_budget_contributes_nothing(self) -> None:
        self.write("README.md", RUNTIME_TEXT + "x" * 300_000)
        self.assertEqual(self.refs(), [])

    def test_a_platform_without_descriptor_walks_refuses_instead_of_reading_by_path(self) -> None:
        self.write("README.md", RUNTIME_TEXT)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("fell back to reading by path")

        with mock.patch.object(descriptor_io, "descriptor_walk_supported", return_value=False), \
                mock.patch.object(Path, "read_text", forbidden), mock.patch.object(Path, "read_bytes", forbidden):
            self.assertEqual(self.refs(), [])


class RealityIndexPolicyBindingTests(unittest.TestCase):
    """Rows written under another sensitive-name policy are never served, and never deleted or re-dated."""

    LEGACY_TOKEN = "ghp_S1FictionalLegacyIndexToken0042"
    INVENTORY = {
        "scope_root": "/srv/uam-s1/scope",
        "projects": [{
            "project_id": "widget",
            "remote_identity": f"https://octo:{LEGACY_TOKEN}@github.com/acme/widget",
            "instances": [{"path": "/srv/uam-s1/scope/widget", "workspace_id": "", "is_worktree": False}],
        }],
    }
    CLEAN_INVENTORY = {
        "scope_root": "/srv/uam-s1/scope",
        "projects": [{
            "project_id": "widget",
            "remote_identity": "acme/widget",
            "instances": [{"path": "/srv/uam-s1/scope/widget", "workspace_id": "", "is_worktree": False}],
        }],
    }

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-s1-index-")
        self.addCleanup(tmp.cleanup)
        self.index = RealityIndex(Path(tmp.name) / "state")

    @contextmanager
    def written_under(self, version: str):
        """Run as the release that enforced sensitive-name policy ``version`` would have."""
        with mock.patch.object(reality_index_module, "POLICY_BINDING", f"|{version}"):
            yield

    def every_read(self, generation: str = "gen1") -> dict[str, object]:
        index = self.index
        return {
            "snapshot": index.get_active_snapshot("s", generation, allow_stale=True),
            "alias": index.lookup_by_alias("widget"),
            "alias_scoped": index.lookup_by_alias("widget", scope_id="s", policy_generation=generation),
            "projects": index.list_projects(),
            "projects_scope": index.list_projects(scope_id="s"),
            "projects_scope_generation": index.list_projects(scope_id="s", policy_generation=generation),
            "instances": index.get_project_instances("widget"),
            "instances_generation": index.get_project_instances("widget", policy_generation=generation),
        }

    def stored_policy_values(self) -> list[tuple[str, str]]:
        connection = sqlite3.connect(str(self.index._db_path))
        try:
            return connection.execute(
                "SELECT 'active', policy_generation FROM active_generation "
                "UNION ALL SELECT 'snapshot', policy_generation FROM scope_snapshots ORDER BY 1, 2"
            ).fetchall()
        finally:
            connection.close()

    def test_rows_from_another_policy_version_are_not_served(self) -> None:
        with self.written_under("uam-sensitive-names/older"):
            self.index.write_snapshot("s", self.INVENTORY, "gen1", git_enriched=True)
            served = self.every_read()
            # Control: under the policy that wrote them, every read does return the data.
            self.assertIsNotNone(served["snapshot"])
            for key in ("alias", "alias_scoped", "projects", "projects_scope", "projects_scope_generation",
                        "instances", "instances_generation"):
                self.assertTrue(served[key], key)
        for key, value in self.every_read().items():
            self.assertFalse(value, f"{key} served a row written under another sensitive-name policy")

    def test_rows_written_before_the_binding_existed_are_not_served(self) -> None:
        self.index.write_snapshot("s", self.INVENTORY, "gen1", git_enriched=True)
        connection = sqlite3.connect(str(self.index._db_path))
        try:
            for table in ("active_generation", "scope_snapshots"):
                connection.execute(
                    f"UPDATE {table} SET policy_generation = substr(policy_generation, 1, "  # noqa: S608
                    "length(policy_generation) - length(?))",
                    (POLICY_BINDING,),
                )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual({value for _, value in self.stored_policy_values()}, {"gen1"})  # what an older release stored
        for key, value in self.every_read().items():
            self.assertFalse(value, f"{key} served a row that carries no policy binding")

    def test_the_stored_generation_carries_the_binding_and_the_registry_value_is_untouched(self) -> None:
        self.index.write_snapshot("s", self.CLEAN_INVENTORY, "gen1", git_enriched=True)
        self.assertEqual(
            self.stored_policy_values(), [("active", bind_policy("gen1")), ("snapshot", bind_policy("gen1"))],
        )
        snapshot = self.index.get_active_snapshot("s", "gen1", allow_stale=True)
        self.assertEqual(snapshot["freshness"]["policy_generation"], "gen1")

    def test_a_refresh_under_the_current_policy_replaces_without_deleting_or_redating(self) -> None:
        with self.written_under("uam-sensitive-names/older"):
            self.index.write_snapshot("s", self.INVENTORY, "gen1", git_enriched=True)
        before = self.observation_times()
        self.index.write_snapshot("s", self.CLEAN_INVENTORY, "gen1", git_enriched=True)
        after = self.observation_times()
        self.assertEqual(len(after), 2)  # the older generation is still there, as history
        self.assertTrue(set(before) < set(after))
        for generation, observed_at in before.items():
            self.assertEqual(after[generation], observed_at)  # its observation time was not rewritten
        served = json.dumps(self.every_read(), default=lambda entry: entry.to_dict())
        self.assertIn("acme/widget", served)
        self.assertNotIn(self.LEGACY_TOKEN, served)

    def observation_times(self) -> dict[str, float]:
        connection = sqlite3.connect(str(self.index._db_path))
        try:
            return dict(connection.execute("SELECT generation_id, observed_at FROM scope_snapshots").fetchall())
        finally:
            connection.close()

    def test_health_asks_for_a_reindex_until_the_scope_is_refreshed(self) -> None:
        registry = registry_for(Path("/srv/uam-s1/scope"))
        generation = registry.policy_generation
        with self.written_under("uam-sensitive-names/older"):
            self.index.write_snapshot("s", self.INVENTORY, generation, git_enriched=True)
        stale = self.index.health_report(registry)
        self.assertEqual(stale["failure_class"], "reality_index_policy_mismatch")
        entry = stale["scopes"][0]
        self.assertFalse(entry["policy_match"])
        self.assertFalse(entry["sensitive_policy_bound"])
        self.index.write_snapshot("s", self.CLEAN_INVENTORY, generation, git_enriched=True)
        fresh = self.index.health_report(registry)
        entry = fresh["scopes"][0]
        self.assertTrue(entry["policy_match"])
        self.assertTrue(entry["sensitive_policy_bound"])
        self.assertEqual(entry["policy_generation"], generation)  # reported as the registry states it


if __name__ == "__main__":
    unittest.main()
