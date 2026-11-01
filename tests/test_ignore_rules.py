"""Ignore-file semantics of the in-process scope search, one rule at a time.

``ignore_rules`` interprets ``.gitignore``, ``.ignore`` and ``.rgignore`` the way ripgrep's ``ignore``
crate does. ``test_scope_search_walk`` compares whole trees with ``rg --files``; these tests pin the
individual rules, and the one deliberate departure: a rule that cannot be translated faithfully is
*not applied* and is counted, never guessed.
"""
from __future__ import annotations

import unittest

from universal_agent_middleware.ignore_rules import (
    EMPTY_RULES,
    MAX_RULES_PER_FILE,
    IgnoreVerdict,
    parse_ignore_file,
)

FILE = False
DIR = True
Case = tuple[str, bool, IgnoreVerdict | None]


class RuleTableTests(unittest.TestCase):
    def check(self, rules: str | bytes, cases: list[Case]) -> None:
        data = rules.encode("utf-8") if isinstance(rules, str) else rules
        parsed = parse_ignore_file(data)
        for relative, is_dir, expected in cases:
            with self.subTest(rules=rules, path=relative, is_dir=is_dir):
                self.assertEqual(parsed.verdict(relative, is_dir=is_dir), expected)

    def test_a_wildcard_without_a_slash_matches_at_every_depth(self) -> None:
        self.check("*.log\n", [
            ("a.log", FILE, "ignore"), ("x/y/a.log", FILE, "ignore"), ("a.txt", FILE, None), ("log", FILE, None),
        ])

    def test_negation_re_includes_and_the_last_matching_rule_wins(self) -> None:
        self.check("*.log\n!keep.log\n", [
            ("a.log", FILE, "ignore"), ("keep.log", FILE, "whitelist"), ("x/keep.log", FILE, "whitelist"),
        ])
        self.check("*.txt\n!*.txt\n*.txt\n", [("a.txt", FILE, "ignore")])
        self.check("*.txt\n!a.txt\n", [("a.txt", FILE, "whitelist"), ("b.txt", FILE, "ignore")])

    def test_a_trailing_slash_applies_to_directories_only(self) -> None:
        self.check("build/\n", [
            ("build", DIR, "ignore"), ("x/build", DIR, "ignore"), ("build", FILE, None),
        ])

    def test_a_leading_slash_anchors_to_the_ignore_files_directory(self) -> None:
        self.check("/root.txt\n", [("root.txt", FILE, "ignore"), ("x/root.txt", FILE, None)])

    def test_any_other_slash_anchors_too(self) -> None:
        self.check("docs/*.md\n", [
            ("docs/a.md", FILE, "ignore"), ("docs/x/a.md", FILE, None), ("x/docs/a.md", FILE, None),
        ])

    def test_double_star_forms(self) -> None:
        self.check("**/cache\n", [("cache", DIR, "ignore"), ("a/b/cache", FILE, "ignore"), ("cachex", FILE, None)])
        self.check("src/**/gen\n", [
            ("src/gen", DIR, "ignore"), ("src/a/b/gen", DIR, "ignore"), ("gen", DIR, None), ("other/src/gen", DIR, None),
        ])
        self.check("foo/**\n", [
            ("foo/a", FILE, "ignore"), ("foo/a/b", FILE, "ignore"), ("foo", DIR, None), ("x/foo/a", FILE, None),
        ])
        self.check("a/**/b.txt\n", [
            ("a/b.txt", FILE, "ignore"), ("a/x/b.txt", FILE, "ignore"), ("a/x/y/b.txt", FILE, "ignore"), ("b.txt", FILE, None),
        ])

    def test_character_classes_single_character_and_alternation(self) -> None:
        self.check("[ab].dat\n", [("a.dat", FILE, "ignore"), ("b.dat", FILE, "ignore"), ("c.dat", FILE, None)])
        self.check("[!ab].dat\n", [("c.dat", FILE, "ignore"), ("a.dat", FILE, None)])
        self.check("[a-c]x\n", [("bx", FILE, "ignore"), ("dx", FILE, None)])
        self.check("q?.cfg\n", [("qa.cfg", FILE, "ignore"), ("qab.cfg", FILE, None), ("q/.cfg", FILE, None)])
        self.check("*.{js,css}\n", [("a.js", FILE, "ignore"), ("a.css", FILE, "ignore"), ("a.ts", FILE, None)])

    def test_a_wildcard_never_crosses_a_separator(self) -> None:
        self.check("a*b\n", [("axb", FILE, "ignore"), ("a/b", FILE, None)])
        self.check("x/*\n", [("x/y", FILE, "ignore"), ("x/y/z", FILE, None)])

    def test_escapes_and_trailing_spaces(self) -> None:
        self.check("\\#hash.txt\n\\!bang.txt\n", [("#hash.txt", FILE, "ignore"), ("!bang.txt", FILE, "ignore")])
        self.check("trail.txt   \n", [("trail.txt", FILE, "ignore")])
        self.check("esc.txt\\ \n", [("esc.txt ", FILE, "ignore"), ("esc.txt", FILE, None)])

    def test_comments_and_blank_lines_are_not_rules(self) -> None:
        parsed = parse_ignore_file(b"# a comment\n\n   \n")
        self.assertFalse(parsed)
        self.assertEqual(parsed.verdict("a", is_dir=False), None)

    def test_a_bom_and_crlf_line_endings_are_tolerated(self) -> None:
        self.check("\ufeff*.log\r\n!keep.log\r\n", [("a.log", FILE, "ignore"), ("keep.log", FILE, "whitelist")])

    def test_reading_stops_at_the_first_line_that_is_not_utf8(self) -> None:
        self.check(b"a.log\n\xff\xfe\nb.log\n", [("a.log", FILE, "ignore"), ("b.log", FILE, None)])

    def test_a_directory_rule_without_trailing_slash_matches_directories_and_files_alike(self) -> None:
        self.check("cache\n", [("cache", DIR, "ignore"), ("cache", FILE, "ignore")])


class RulesThatAreNotAppliedTests(unittest.TestCase):
    """Anything not translated faithfully is skipped and counted, and the other rules still apply."""

    UNSUPPORTED = ("a**b", "**a", "a**", "[z-a]", "[", "[]", "{a,}", "{,a}", "foo}", "{a", "trail\\", "{a/**,b}")

    def test_each_unsupported_pattern_is_counted_and_applies_nothing(self) -> None:
        for pattern in self.UNSUPPORTED:
            with self.subTest(pattern=pattern):
                parsed = parse_ignore_file(f"{pattern}\n*.keep-applied\n".encode())
                self.assertEqual(parsed.skipped_rules, 1)
                self.assertEqual(parsed.verdict("x.keep-applied", is_dir=False), "ignore")
                self.assertIsNone(parsed.verdict(pattern.replace("*", "q"), is_dir=False))

    def test_an_oversized_pattern_is_skipped(self) -> None:
        parsed = parse_ignore_file(("x" * 600 + "\n*.ok\n").encode())
        self.assertEqual(parsed.skipped_rules, 1)
        self.assertEqual(parsed.verdict("a.ok", is_dir=False), "ignore")

    def test_too_many_wildcards_is_skipped(self) -> None:
        parsed = parse_ignore_file(b"*a*b*c*d*e*f*g\n*.ok\n")
        self.assertEqual(parsed.skipped_rules, 1)
        self.assertEqual(parsed.verdict("a.ok", is_dir=False), "ignore")

    def test_rules_past_the_per_file_cap_are_skipped_and_counted(self) -> None:
        body = "".join(f"rule{index}.txt\n" for index in range(MAX_RULES_PER_FILE + 5)).encode()
        parsed = parse_ignore_file(body)
        self.assertEqual(parsed.skipped_rules, 5)
        self.assertEqual(parsed.verdict("rule0.txt", is_dir=False), "ignore")
        self.assertIsNone(parsed.verdict(f"rule{MAX_RULES_PER_FILE + 1}.txt", is_dir=False))

    def test_a_file_with_only_comments_is_the_shared_empty_value(self) -> None:
        self.assertIs(parse_ignore_file(b"# nothing\n"), EMPTY_RULES)
        self.assertEqual(EMPTY_RULES.skipped_rules, 0)


if __name__ == "__main__":
    unittest.main()
