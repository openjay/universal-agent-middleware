"""Gitignore-style ignore rules, evaluated in-process for the scope search.

The scope search used to let ripgrep walk a wide directory and apply the repository ignore files
itself. Authorisation has to be decided before a file is opened, so the walk is ours now and the
ignore files are interpreted here, with the semantics of ripgrep's ``ignore`` crate (ripgrep 14):

* a ``.gitignore`` counts only inside a Git checkout (an ancestor directory within the walk holds
  ``.git``), the nearest checkout wins for ``.gitignore``; ``.ignore`` and ``.rgignore`` always
  count; for each of the three kinds the nearest directory with a matching rule decides, and the
  kinds rank ``.rgignore`` over ``.ignore`` over ``.gitignore``;
* inside one file the last matching rule wins, ``!`` re-includes, a trailing ``/`` makes a rule
  apply to directories only, a leading ``/`` or any other ``/`` anchors it to the file's directory;
* the glob dialect is the one ``globset`` implements (``*``, ``?``, ``**``, ``[...]``, ``{a,b}``,
  backslash escapes) with ``/`` never matched by a wildcard.

Anything this module cannot translate faithfully (a malformed glob, an oversized pattern, a file
past the size cap) is *not applied*, counted in ``IgnoreRules.skipped_rules`` and declared by the
search (``ignore_rules_not_applied``). Skipping a plain rule searches more files than ripgrep would;
skipping a ``!`` rule searches fewer. Either way no claim reaches past what was searched, and the
walk never opens anything authority has not allowed.
Differential tests compare the walker's file set with ``rg --files`` on the same trees.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

IgnoreVerdict = Literal["ignore", "whitelist"]

MAX_IGNORE_FILE_BYTES: Final = 1 << 20
MAX_RULES_PER_FILE: Final = 10_000
_MAX_PATTERN_CHARS: Final = 512
_MAX_WILDCARDS: Final = 6


@dataclass(frozen=True)
class _Rule:
    regex: str
    negated: bool
    dir_only: bool


class IgnoreRules:
    """The compiled rules of one ignore file, answering for one relative path at a time."""

    __slots__ = ("_for_files", "_for_dirs", "_negated_for_files", "_negated_for_dirs", "skipped_rules")

    def __init__(self, rules: list[_Rule], skipped_rules: int = 0):
        self.skipped_rules = skipped_rules
        file_rules = [rule for rule in rules if not rule.dir_only]
        self._for_files, self._negated_for_files = _combine(file_rules)
        self._for_dirs, self._negated_for_dirs = _combine(rules)

    def __bool__(self) -> bool:
        return self._for_dirs is not None

    def verdict(self, relative: str, *, is_dir: bool) -> IgnoreVerdict | None:
        """The verdict of the last rule that matches ``relative`` (POSIX, no leading slash)."""
        pattern, negated = (
            (self._for_dirs, self._negated_for_dirs) if is_dir else (self._for_files, self._negated_for_files)
        )
        if pattern is None:
            return None
        matched = pattern.fullmatch(relative)
        if matched is None or matched.lastindex is None:
            return None
        return "whitelist" if negated[matched.lastindex - 1] else "ignore"


def _combine(rules: list[_Rule]) -> tuple[re.Pattern[str] | None, tuple[bool, ...]]:
    """One alternation whose first alternative is the *last* rule, so the first match is the winner."""
    if not rules:
        return None, ()
    ordered = list(reversed(rules))
    pattern = re.compile("|".join(f"({rule.regex})" for rule in ordered), re.DOTALL)
    return pattern, tuple(rule.negated for rule in ordered)


EMPTY_RULES: Final = IgnoreRules([])


def parse_ignore_file(data: bytes) -> IgnoreRules:
    """Compile the rules of an ignore file given as bytes.

    Like ripgrep, reading stops at the first line that is not valid UTF-8; the rules before it
    still count.
    """
    rules: list[_Rule] = []
    skipped = 0
    for number, raw_line in enumerate(data.split(b"\n")):
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            break
        if line.endswith("\r"):
            line = line[:-1]
        if number == 0 and line.startswith("\ufeff"):
            line = line[1:]
        try:
            rule = _rule_from_line(line)
        except _Unsupported:
            skipped += 1
            continue
        if rule is None:
            continue
        if len(rules) >= MAX_RULES_PER_FILE:
            skipped += 1
            continue
        rules.append(rule)
    return IgnoreRules(rules, skipped) if rules or skipped else EMPTY_RULES


class _Unsupported(Exception):
    """A pattern this module does not translate (never raised for a plain, valid gitignore line)."""


def _rule_from_line(line: str) -> _Rule | None:
    if line.startswith("#"):
        return None
    if not line.endswith("\\ "):
        line = line.rstrip()
    if not line:
        return None
    negated = False
    dir_only = False
    anchored = False
    if line.startswith("\\!") or line.startswith("\\#"):
        line = line[1:]
    else:
        if line.startswith("!"):
            negated = True
            line = line[1:]
        if line.startswith("/"):
            line = line[1:]
            anchored = True
    if line.endswith("/"):
        dir_only = True
        line = line[:-1]
        if line.endswith("\\"):
            line = line[:-1]
    glob = line
    if not anchored and "/" not in line and not (glob.startswith("**/") or glob == "**"):
        glob = "**/" + glob
    if glob.endswith("/**"):
        glob += "/*"
    if len(glob) > _MAX_PATTERN_CHARS:
        raise _Unsupported
    counter = _Counter()
    regex = _glob_to_regex(glob, counter, allow_recursive=True)
    if regex is None or counter.wildcards > _MAX_WILDCARDS:
        raise _Unsupported
    return _Rule(regex=regex, negated=negated, dir_only=dir_only)


@dataclass
class _Counter:
    wildcards: int = 0


def _glob_to_regex(glob: str, counter: _Counter, *, allow_recursive: bool) -> str | None:
    """Translate a ``globset`` glob (``/`` is a literal separator) to a regular expression source."""
    parts: list[str] = []
    index = 0
    length = len(glob)
    while index < length:
        char = glob[index]
        if char == "\\":
            if index + 1 >= length:
                return None
            parts.append(re.escape(glob[index + 1]))
            index += 2
        elif char == "?":
            counter.wildcards += 1
            parts.append("[^/]")
            index += 1
        elif char == "*":
            end = index
            while end < length and glob[end] == "*":
                end += 1
            stars = end - index
            if stars == 1:
                counter.wildcards += 1
                parts.append("[^/]*")
                index = end
            elif stars == 2 and allow_recursive:
                counter.wildcards += 1
                after = glob[end] if end < length else ""
                at_component_start = index == 0 or glob[index - 1] == "/"
                if at_component_start and after == "/":
                    parts.append("(?:.*/)?")
                    index = end + 1
                elif at_component_start and end == length:
                    parts.append(".*")
                    index = end
                else:
                    return None
            else:
                return None
        elif char == "[":
            translated = _class_to_regex(glob, index)
            if translated is None:
                return None
            source, index = translated
            counter.wildcards += 1
            parts.append(source)
        elif char == "{":
            translated_group = _alternation_to_regex(glob, index, counter)
            if translated_group is None:
                return None
            source, index = translated_group
            parts.append(source)
        elif char == "}":
            return None  # an unopened alternate group is an error in globset: the rule is not applied
        else:
            parts.append(re.escape(char))
            index += 1
    return "".join(parts)


def _class_to_regex(glob: str, start: int) -> tuple[str, int] | None:
    """``[abc]``, ``[a-z]``, ``[!abc]`` and ``[^abc]``; never matches ``/``."""
    length = len(glob)
    index = start + 1
    negate = False
    if index < length and glob[index] in "!^":
        negate = True
        index += 1
    items: list[str] = []
    first = True
    while index < length:
        char = glob[index]
        if char == "]" and not first:
            if not items:
                return None
            body = "".join(items)
            return f"(?!/)[{'^' if negate else ''}{body}]", index + 1
        first = False
        if char == "\\":
            if index + 1 >= length:
                return None
            index += 1
            char = glob[index]
        if index + 2 < length and glob[index + 1] == "-" and glob[index + 2] != "]":
            high = glob[index + 2]
            consumed = 3
            if high == "\\":
                if index + 3 >= length:
                    return None
                high = glob[index + 3]
                consumed = 4
            if ord(high) < ord(char):
                return None
            items.append(f"{re.escape(char)}-{re.escape(high)}")
            index += consumed
        else:
            items.append(re.escape(char))
            index += 1
    return None


def _alternation_to_regex(glob: str, start: int, counter: _Counter) -> tuple[str, int] | None:
    """``{a,b}``: one level, no recursive wildcard inside an alternative."""
    length = len(glob)
    index = start + 1
    alternatives: list[str] = []
    current: list[str] = []
    while index < length:
        char = glob[index]
        if char == "\\":
            if index + 1 >= length:
                return None
            current.append(glob[index : index + 2])
            index += 2
        elif char == "[":
            end = index + 1
            if end < length and glob[end] in "!^":
                end += 1
            if end < length and glob[end] == "]":
                end += 1
            while end < length and glob[end] != "]":
                end += 2 if glob[end] == "\\" else 1
            if end >= length:
                return None
            current.append(glob[index : end + 1])
            index = end + 1
        elif char == "{":
            return None
        elif char == ",":
            alternatives.append("".join(current))
            current = []
            index += 1
        elif char == "}":
            alternatives.append("".join(current))
            translated: list[str] = []
            for alternative in alternatives:
                if not alternative:
                    return None  # empty alternates are an error in globset by default
                source = _glob_to_regex(alternative, counter, allow_recursive=False)
                if source is None:
                    return None
                translated.append(source)
            return "(?:" + "|".join(translated) + ")", index + 1
        else:
            current.append(char)
            index += 1
    return None
