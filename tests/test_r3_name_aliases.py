"""R3-05: a name that is a denied name under another spelling is denied; no name that was readable becomes denied.

``policy.is_denied_component`` already compares case- and normalization-insensitively. Two more families of spellings
reach the same object, or the same intent, and were not covered:

* default-ignorable code points (zero-width space/joiners, bidi controls, soft hyphen, variation selectors, BOM) that a
  legacy or network filesystem, a client or a normalizer drops, and trailing spaces/dots that a Windows-semantics
  filesystem (an SMB or exFAT mount) drops: ``credentials.json `` or ``cred\\u200bentials.json`` names the denied file there;
* a newline inside a name defeated ``.*`` in the patterns (``.`` does not match it): ``.env\\nbackup`` starts with ``.env``
  and ``key\\n.pem`` ends with ``.pem`` exactly as much as the names the patterns were written for.

The rule added is an EQUIVALENCE CLOSURE, not a wider list: a spelling is denied exactly when the name it reduces to is.
The second half of this module pins that nothing which was readable becomes denied (the property is compared against the
verdict of the plain name, so it also holds for names this file does not list).
"""
from __future__ import annotations

import itertools
import unittest

from universal_agent_middleware.errors import PathPolicyError
from universal_agent_middleware.policy import ensure_relative_path, is_denied_component, is_denied_path

# Representative of every rule family in policy.py (exact names, dotenv family, key/cert extensions, secrets files,
# shell histories, ssh keys, credential directories).
DENIED_BASES = (
    ".env", ".envrc", ".env.local", ".secrets.env", "tokens.env", "prod.env", "secrets.json", "secrets.yml",
    "credentials.json", "credentials", "token.json", "tokens.json", "kubeconfig", ".npmrc", ".pypirc", ".netrc",
    "id_rsa", "id_ed25519", "id_rsa_work", ".ssh", ".aws", ".gnupg", ".git", ".git-credentials", ".pgpass",
    "server.pem", "cert.p12", "private.key", "release.jks", "prod.tfvars", "terraform.tfstate", "login.keychain-db",
    ".zsh_history", ".bash_history", "client_secret_123.json",
)
ALLOWED_BASES = (
    "README.md", "docs", "credential-model.md", "environment.md", "keys.md", "secrets.md", "secrets.txt", "secret.txt",
    "env.py", "venv", ".venv", "id_rsa.pub", "tokenizer.py", "client.json", "history.md", "package.json", "notes.txt",
    "my notes.txt", "a b", ".hidden", "na\u00efve.txt", "idea.txt", "Makefile", "x", "src",
)
IGNORABLES = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202e", "\u200e", "\u00ad", "\ufe0f", "\u180e")
TRAILERS = (" ", "  ", ".", "..", ". .", " .", "\t", "\n", " \n")


def with_ignorable_inside(name: str, mark: str) -> list[str]:
    """The name with ``mark`` after the first character, before the last one, and (twice) in the middle."""
    middle = len(name) // 2
    return [
        name[:1] + mark + name[1:], name[:-1] + mark + name[-1:], name[:middle] + mark + mark + name[middle:],
        mark + name, name + mark,
    ]


def spellings(name: str) -> list[str]:
    found: list[str] = []
    for mark in IGNORABLES:
        found += with_ignorable_inside(name, mark)
    found += [name + trailer for trailer in TRAILERS]
    found += [name + "\u200b" + trailer for trailer in TRAILERS]
    return sorted(set(found) - {name})


class AliasClosureTests(unittest.TestCase):
    def test_a_denied_name_stays_denied_under_every_ignorable_or_trailing_spelling(self) -> None:
        for base in DENIED_BASES:
            self.assertTrue(is_denied_component(base), f"fixture error: {base!r} is not a denied name")
            for spelling in spellings(base):
                with self.subTest(base=base, spelling=spelling):
                    self.assertTrue(is_denied_component(spelling))

    def test_every_entry_point_refuses_the_alias_spellings(self) -> None:
        samples = ("credentials.json ", "cred\u200bentials.json", ".np\u200cmrc", "id_rsa.", "secrets.json\u200b", ".s\u2060sh")
        for spelling in samples:
            with self.subTest(spelling=spelling):
                self.assertTrue(is_denied_component(spelling))
                self.assertTrue(is_denied_path(f"deep/{spelling}/x.txt"))
                with self.assertRaises(PathPolicyError):
                    ensure_relative_path(f"config/{spelling}")

    def test_a_newline_inside_a_name_does_not_defeat_the_patterns(self) -> None:
        for name in (".env\nbackup", ".env\n", "tokens.env\n", "key\n.pem", "x\n.tfstate", "a\nb.tfvars", ".secrets\n.env"):
            with self.subTest(name=name):
                self.assertTrue(is_denied_component(name))

    def test_a_newline_is_alias_closure_only_at_the_end_of_an_exact_name(self) -> None:
        # A line-oriented tool drops a TRAILING newline, so ``credentials.json\n`` names the denied file. No normalizer
        # deletes a newline from the MIDDLE of a name: ``cred\nentials.json`` is another file name, as readable as any other.
        # (A pattern name is different: ``.env\nbackup`` is denied because ``.*`` crosses the newline, see above.)
        for denied in ("credentials.json\n", "credentials.json \n", "id_rsa\n", ".ssh\n"):
            with self.subTest(denied=denied):
                self.assertTrue(is_denied_component(denied))
        for another_name in ("cred\nentials.json", "id\n_rsa", ".s\nsh"):
            with self.subTest(another_name=another_name):
                self.assertFalse(is_denied_component(another_name))

    def test_control_the_plain_names_were_and_are_decided_by_the_unchanged_rules(self) -> None:
        for base in DENIED_BASES:
            self.assertTrue(is_denied_component(base), base)
        for base in ALLOWED_BASES:
            self.assertFalse(is_denied_component(base), base)


class NoWideningTests(unittest.TestCase):
    """An alias of a readable name is readable; the closure adds spellings of denied names and nothing else."""

    def test_an_alias_spelling_of_a_readable_name_stays_readable(self) -> None:
        for base in ALLOWED_BASES:
            for spelling in spellings(base):
                with self.subTest(base=base, spelling=spelling):
                    self.assertFalse(is_denied_component(spelling))

    def test_the_verdict_of_a_spelling_is_the_verdict_of_the_name_it_reduces_to(self) -> None:
        corpus = DENIED_BASES + ALLOWED_BASES
        for base, spelling in itertools.chain.from_iterable(((base, s) for s in spellings(base)) for base in corpus):
            with self.subTest(base=base, spelling=spelling):
                self.assertEqual(is_denied_component(spelling), is_denied_component(base))

    def test_ordinary_names_with_a_newline_or_odd_characters_are_not_newly_denied(self) -> None:
        for name in ("line\none.txt", "multi\nline", "tab\tname.md", "emoji\U0001f600.txt", "environment", "keystone", "tfvars_explained.md"):
            with self.subTest(name=name):
                self.assertFalse(is_denied_component(name))

    def test_components_that_are_only_ignorable_or_trailing_characters_are_not_denied(self) -> None:
        for name in ("\u200b", "\ufeff\u200b", " ", "  ", "...", ". ."):
            with self.subTest(name=name):
                self.assertFalse(is_denied_component(name))


if __name__ == "__main__":
    unittest.main()
