"""S1-A: one source of sensitive path-component names, and the incident file families it must cover.

The 2026-10-16 incident file was ``.secrets.env``. It matched neither original rule (``^\\.env(\\..*)?$`` needs the
name to START with ``.env``; the extension list has no ``.env``), so a text search returned its lines. These tests pin the
family, pin the names that must stay readable (documentation about secrets is not a secret), and pin that every consumer
decides through ``policy`` instead of a list of its own.
"""
import json
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware import policy
from universal_agent_middleware.errors import PathPolicyError
from universal_agent_middleware.policy import (
    SENSITIVE_POLICY_VERSION, ensure_relative_path, is_denied_component, is_denied_path, resolve_safe_path,
    should_hide_path,
)
from universal_agent_middleware.scope_search import is_sensitive_name, is_sensitive_path
from universal_agent_middleware.workspace import WorkspaceReader, WorkspaceRegistry

FICTIONAL_BODY = "FICTIONAL_S1_MARKER=not-a-real-credential-0001\n"

# The incident family, and the neighbours the original two rules missed or only the scope search denied.
DENIED_NAMES = (
    ".secrets.env", "secrets.env", "tokens.env", "keys.env", "prod.env", "deploy.env.bak", "x.env~", "SECRETS.ENV",
    ".env", ".env.local", ".ENV.PRODUCTION", ".env-prod", ".env_backup", ".env~", ".envrc", ".envrc.local", ".envs",
    ".git-credentials", ".pgpass", ".my.cnf", ".s3cfg", ".boto", ".dockercfg", ".vault-token", ".htpasswd", ".azure",
    ".secrets", "secrets.yml", "secrets.yaml", ".secrets.toml", "Secrets.JSON", "client_secret_123.json",
    "token.json", "tokens.json", "kubeconfig", "_netrc",
    "server.pem", "cert.p12", "cert.pfx", "private.key", "store.keystore", "release.jks", "AuthKey_ABC.p8", "putty.ppk",
    "login.keychain-db", "old.keychain", "terraform.tfstate", "terraform.tfstate.backup", "prod.tfvars", "prod.tfvars.json",
    "id_rsa", "id_rsa_work", "id_ecdsa", "id_dsa", "id_ed25519", "id_ed25519_sk",
    ".zsh_history", ".bash_history", ".python_history", ".psql_history",
    # the original exact names
    ".git", ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json",
    "secrets.json",
)
# Names that must stay readable: prose about secrets, ordinary code, public keys, virtualenvs.
ALLOWED_NAMES = (
    "README.md", "docs", "credential-model.md", "environment.md", "keys.md", "sshd_notes.txt", "secrets.md", "secret_santa.py",
    "env.py", "envelope.txt", "venv", ".venv", ".pyenv", "id_rsa.pub", "id_ed25519.pub", "tokenizer.py", "token_bucket.py",
    "client.json", "history.md", "my_history_notes.md", "keychain.md", "terraform.md", "tfvars_explained.md", "package.json",
    "environments.md", "dev.environment", "idea.txt", "sshkey.md",
    # DOCUMENTED RESIDUAL, not an endorsement: ".txt" is too ambiguous to refuse by name (notes, fixtures, prose), so a
    # file called secrets.txt is covered by the workspace's registered scope, not by this list.
    "secret.txt", "secrets.txt",
)


class NameFamilyTests(unittest.TestCase):
    def test_the_incident_family_is_denied_by_every_entry_point(self):
        for name in DENIED_NAMES:
            with self.subTest(name=name):
                self.assertTrue(is_denied_component(name))
                with self.assertRaises(PathPolicyError):
                    ensure_relative_path(f"config/{name}")
                self.assertTrue(is_denied_path(f"deep/er/{name}/x.txt"))
                self.assertTrue(is_sensitive_name(name))
                self.assertTrue(is_sensitive_path(f"/tmp/project/{name}"))

    def test_ordinary_and_explanatory_names_stay_readable(self):
        for name in ALLOWED_NAMES:
            with self.subTest(name=name):
                self.assertFalse(is_denied_component(name))
                self.assertFalse(is_sensitive_name(name))
                self.assertEqual(ensure_relative_path(f"docs/{name}"), Path("docs", name))

    def test_matching_does_not_depend_on_letter_case_or_unicode_form(self):
        for name in (".Secrets.Env", "TOKENS.ENV", ".GIT-CREDENTIALS", "Terraform.TFSTATE", "ID_RSA_work", ".ZSH_HISTORY"):
            with self.subTest(name=name):
                self.assertTrue(is_denied_component(name))
        decomposed = "cre\u0301dentials"  # not the denied name: a different word, must not be denied by accident
        self.assertFalse(is_denied_component(decomposed))

    def test_a_denied_component_anywhere_in_a_path_denies_the_path(self):
        self.assertTrue(is_denied_path("a/.secrets.env/b"))
        self.assertTrue(is_denied_path("/abs/dir/.envs/x"))
        self.assertFalse(is_denied_path("a/b/c.txt"))


class SingleSourceTests(unittest.TestCase):
    def test_the_scope_search_decides_exactly_like_policy(self):
        corpus = set(DENIED_NAMES) | set(ALLOWED_NAMES) | {
            name.upper() for name in DENIED_NAMES} | {name.title() for name in ALLOWED_NAMES} | {
            ".envision", ".environment", "a.env", "a.environment", ".env.", ".secrets.env.example", "secrets.envx"}
        for name in sorted(corpus):
            with self.subTest(name=name):
                self.assertEqual(is_sensitive_name(name), is_denied_component(name))
                self.assertEqual(is_sensitive_path(f"x/{name}"), is_denied_path(f"x/{name}"))

    def test_the_names_the_scope_search_alone_used_to_deny_are_denied_everywhere(self):
        # Before S1 the scope search denied any ".env*" name; policy did not. One list now.
        for name in (".envrc", ".env-prod", ".env_backup", ".envs", ".envision"):
            with self.subTest(name=name):
                self.assertTrue(is_denied_component(name))

    def test_no_consumer_module_keeps_a_private_list_of_sensitive_names(self):
        source_root = Path(policy.__file__).parent
        for module in ("scope_search.py", "resolver.py", "discovery.py", "exploration.py", "workspace.py", "git_readonly.py"):
            text = (source_root / module).read_text(encoding="utf-8")
            for forbidden in ("_SENSITIVE_NAMES", "_SENSITIVE_EXTENSIONS", "_DENIED_EXACT", "_DENIED_PATTERNS"):
                with self.subTest(module=module, forbidden=forbidden):
                    self.assertNotIn(forbidden, text)

    def test_the_policy_version_is_a_nonempty_stamp(self):
        self.assertRegex(SENSITIVE_POLICY_VERSION, r"^uam-sensitive-names/\d{4}-\d{2}-\d{2}\.\d+$")


class ReaderSurfaceTests(unittest.TestCase):
    """The incident channel end to end: a text search over a tree that holds the incident file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name, "repo")
        (root / "config").mkdir(parents=True)
        (root / "config" / "notes.md").write_text("discord and slack are mentioned in this note\n", encoding="utf-8")
        for name in (".secrets.env", "secrets.env", "tokens.env", "keys.env"):
            (root / "config" / name).write_text(f"DISCORD_TOKEN_FICTIONAL={FICTIONAL_BODY}", encoding="utf-8")
        registry = Path(self.tmp.name, "workspaces.json")
        registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{
            "workspace_id": "x", "root": str(root), "kind": "git-repository", "capabilities": ["filesystem.read"]}]}))
        self.reader = WorkspaceReader(WorkspaceRegistry(registry).get("x"))

    def test_search_text_never_returns_a_line_of_the_incident_family(self):
        for query in ("DISCORD", "discord", "FICTIONAL_S1_MARKER", "not-a-real-credential"):
            with self.subTest(query=query):
                result = self.reader.search_text(query)
                self.assertTrue(all("secrets.env" not in hit["path"] and ".env" not in hit["path"] for hit in result["results"]))
                self.assertNotIn("FICTIONAL_S1_MARKER", json.dumps(result["results"]))  # the echoed query is not a hit
                if query in ("FICTIONAL_S1_MARKER", "not-a-real-credential"):
                    self.assertEqual(result["results"], [])
        self.assertEqual([hit["path"] for hit in self.reader.search_text("discord")["results"]], ["config/notes.md"])

    def test_tree_hides_and_read_refuses_the_incident_family(self):
        paths = {entry["path"] for entry in self.reader.tree(depth=3)["entries"]}
        self.assertEqual({p for p in paths if p.startswith("config/")}, {"config/notes.md"})
        for name in (".secrets.env", "secrets.env", "tokens.env", "keys.env"):
            with self.subTest(name=name):
                with self.assertRaises(PathPolicyError):
                    self.reader.read_file(f"config/{name}")
                with self.assertRaises(PathPolicyError):
                    self.reader.file_digest(f"config/{name}")
                self.assertTrue(should_hide_path(self.reader.root, Path(self.reader.root, "config", name)))
                with self.assertRaises(PathPolicyError):
                    resolve_safe_path(self.reader.root, f"config/{name}")

    def test_the_content_of_a_denied_object_cannot_change_any_result(self):
        """Metamorphic: change ONLY the fictional body of the denied files; no tool result may change."""
        def observe():
            return json.dumps({
                "tree": self.reader.tree(depth=3),
                "search": self.reader.search_text("discord"),
                "search_body": self.reader.search_text("FICTIONAL"),
                "digest": self.reader.file_digest("config/notes.md")["sha256"],
            }, sort_keys=True)

        before = observe()
        for name in (".secrets.env", "secrets.env", "tokens.env", "keys.env"):
            Path(self.reader.root, "config", name).write_text("DIFFERENT_FICTIONAL_BODY=zzz-9999\nmore\nlines\n" * 40, encoding="utf-8")
        self.assertEqual(observe(), before)


if __name__ == "__main__":
    unittest.main()
