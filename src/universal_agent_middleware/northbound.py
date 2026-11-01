"""The northbound output boundary: no host path leaves in a tool answer (v0.6.1, PR-1).

Every answer and every error of the session-read MCP server passes through ``NorthboundBoundary`` once,
at the point where it becomes the text a client reads. The boundary does three things, in this order:

1. **Typed rewrite.** A worktree that project discovery found carries a host path in the process
   (``discovered_worktrees[].path``). It leaves as a stable identifier that contains no host
   information (``worktree_id``, a digest of the real path) and, when the worktree lies inside an
   authorized RootScope, the scope and the path relative to it (``scope_id``, ``relative_path``).
2. **Field rule.** A field that is defined to hold a path (``path``, ``rel_path``, ``root`` ...) keeps a
   relative value exactly as it is and is dropped when the value is absolute (``/``, ``file:`` URI,
   drive letter, UNC). Relative paths are the contract of the tools and are never rewritten.
3. **Text rule.** Every other string, an error message included, has each absolute host path replaced
   by a label: ``<workspace:ID>``, ``<scope:ID>``, ``<state>``, ``<registry-dir>``, ``<home>``,
   ``<tmp>`` for a root UAM knows (every spelling UAM can derive for it: as declared, resolved,
   ``/private`` and ``/var`` forms, Unicode NFC and NFD, any letter case) and ``<host-path>`` for any
   other absolute path. The remainder of a path below a known root is dropped with it: an error that
   names a file the caller did not send must not name it after the rewrite either.

Not promised, on purpose:

* Content is not rewritten. File text, diffs and commit text are the repository's data, and an answer
  that altered them would no longer be evidence. A tool lists the keys that carry content for it
  (``exempt``); anything not listed is checked, so a new metadata field is covered by default.
* A path glued to a letter or digit (``x/Users/y``) is not a path start, because ``学习/资料/笔记`` and
  ``café/menu`` are relative paths. A known root is recognised anywhere, glued or not.
* A path with a space in it is redacted up to its first space, unless it is quoted (``'/a b/c'``, as Python's
  ``OSError`` writes it), in which case the quote bounds it. Free text cannot say where an unquoted path ends.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import fold_name

HOST_PATH = "<host-path>"

# Fields that are defined to hold a path. A relative value stays; an absolute value is dropped.
PATH_FIELDS = frozenset({
    "path", "rel_path", "relative_path", "root", "canonical_path", "common_dir", "repo_root", "git_dir",
    "toplevel", "cwd", "directory", "state_dir", "registry_path", "config_dir",
})

# One component is a host path only when it names one of these; two components always are.
_TOP_LEVEL = frozenset({
    "Users", "home", "root", "Volumes", "private", "var", "tmp", "opt", "usr", "etc", "Library", "System",
    "Applications", "Network", "cores", "mnt", "media", "srv", "nix", "bin", "sbin", "dev", "proc",
})
_QUOTES = frozenset("\"'`")
_DELIMITERS = frozenset("\"'`<>|;,(){}[]，。；：！？（）【】「」『』《》、")
_TRAILING = ".:!?\\"
_NO_START_AFTER = frozenset("._~:/\\-@")  # a slash after one of these (or after a letter, digit or mark) continues a name
_FILE_SCHEME = re.compile(r"file://(?:localhost)?(?=/)", re.IGNORECASE)
_WINDOWS_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
# A drive path or a UNC path inside running text (a letter before the drive letter means it is part of a word).
_WINDOWS_TEXT = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\[\w.-]+\\)[^\s\"'`<>|;,(){}\[\]]*")
_ALIAS_PREFIXES = ("var", "tmp", "etc")


@dataclass(frozen=True)
class HostRoot:
    """A directory UAM knows by path: what kind it is and which identifier names it."""

    kind: str
    name: str
    path: str

    @property
    def label(self) -> str:
        return f"<{self.kind}:{self.name}>" if self.name else f"<{self.kind}>"


def _spellings(path: str) -> set[str]:
    """Every way UAM can spell ``path``: as given, resolved, normalised, the macOS ``/private`` forms, NFC and NFD."""
    candidates = {path}
    try:
        candidates.add(os.path.normpath(path))
        candidates.add(os.path.realpath(path))
    except (OSError, ValueError):
        pass
    for candidate in list(candidates):
        for prefix in _ALIAS_PREFIXES:
            if candidate == f"/private/{prefix}" or candidate.startswith(f"/private/{prefix}/"):
                candidates.add(candidate[len("/private"):])
            if candidate == f"/{prefix}" or candidate.startswith(f"/{prefix}/"):
                candidates.add("/private" + candidate)
    forms: set[str] = set()
    for candidate in candidates:
        stripped = candidate.rstrip("/")
        if len(stripped) < 2 or not stripped.startswith("/"):
            continue
        forms.add(unicodedata.normalize("NFC", stripped))
        forms.add(unicodedata.normalize("NFD", stripped))
    return forms


def _real_parts(path: str) -> tuple[str, ...]:
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        real = path
    return Path(real).parts


def worktree_identifier(path: str) -> str:
    """A stable identifier of the worktree at ``path`` that says nothing about where the host keeps it.

    The digest is taken over the folded components of the real path, so the same directory gets the
    same identifier whatever its letter case, normalisation or symlink spelling.
    """
    folded = "/".join(fold_name(part) for part in _real_parts(path))
    return "wt-" + hashlib.sha256(folded.encode("utf-8")).hexdigest()[:16]


def scope_relative(path: str, scope_roots: Iterable[tuple[str, str]]) -> tuple[str, str] | None:
    """``(scope_id, path relative to that scope)`` for the most specific scope that contains ``path``, or None."""
    parts = _real_parts(path)
    folded = [fold_name(part) for part in parts]
    best: tuple[int, str] | None = None
    for scope_id, root in scope_roots:
        root_parts = _real_parts(root)
        root_folded = [fold_name(part) for part in root_parts]
        if len(root_parts) <= len(parts) and folded[: len(root_folded)] == root_folded:
            if best is None or len(root_parts) > best[0]:
                best = (len(root_parts), scope_id)
    if best is None:
        return None
    remainder = parts[best[0]:]
    return best[1], "/".join(remainder) if remainder else "."


def is_absolute_path_text(value: str) -> bool:
    """Whether ``value`` is an absolute host path: ``/``, a ``file:`` URI, a drive or a UNC path (a quoted one included)."""
    unquoted = value.lstrip("\"'`")
    return unquoted.startswith("/") or unquoted.lower().startswith("file:") or bool(_WINDOWS_ABSOLUTE.match(unquoted))


def _absolute_form(value: str) -> str | None:
    """The absolute path that ``value`` names (unquoted, without a ``file:`` scheme), or None when it is relative."""
    stripped = _FILE_SCHEME.sub("", value.strip("\"'`"))
    return stripped if is_absolute_path_text(stripped) else None


class NorthboundBoundary:
    """Rewrites an answer so that no host path leaves in it. ``roots`` is asked on every call (roots change with the registry)."""

    def __init__(self, roots: Callable[[], Iterable[HostRoot]] | None = None) -> None:
        self._roots = roots or (lambda: ())

    # -- known roots --------------------------------------------------------------------------------------------

    def _known(self) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
        """``([(folded spelling, original spelling, label)] longest first, [(scope_id, root)])``."""
        aliases: dict[str, tuple[str, str]] = {}
        scopes: list[tuple[str, str]] = []
        try:
            roots = list(self._roots())
        except Exception:  # the boundary must still run when a root cannot be listed: the generic rule covers it
            roots = []
        for root in roots:
            if root.kind == "scope":
                scopes.append((root.name, root.path))
            for spelling in _spellings(root.path):
                aliases.setdefault(spelling.casefold(), (spelling, root.label))
        ordered = sorted(
            ((folded, original, label) for folded, (original, label) in aliases.items()),
            key=lambda item: len(item[1]), reverse=True,
        )
        return ordered, scopes

    # -- text ---------------------------------------------------------------------------------------------------

    def clean_text(self, text: str) -> str:
        aliases, _ = self._known()
        return self._redact(text, aliases)

    @staticmethod
    def _stops_token(char: str) -> bool:
        return char in _DELIMITERS or char.isspace()

    def _redact(self, text: str, aliases: list[tuple[str, str, str]]) -> str:
        if "/" not in text and "\\" not in text:
            return text
        text = _WINDOWS_TEXT.sub(HOST_PATH, _FILE_SCHEME.sub("", text))
        pieces: list[str] = []
        copied = 0  # text before this offset is already in ``pieces``
        index = 0
        length = len(text)
        while True:
            index = text.find("/", index)
            if index < 0:
                break
            end, label = self._path_at(text, index, length, aliases)
            if end == index:
                index += 1
                continue
            pieces.append(text[copied:index])
            pieces.append(label)
            copied = index = end
        pieces.append(text[copied:])
        return "".join(pieces)

    def _path_at(self, text: str, start: int, length: int, aliases: list[tuple[str, str, str]]) -> tuple[int, str]:
        """``(end, label)`` of the host path that starts at ``start``, or ``(start, "")`` when none does."""
        previous = text[start - 1] if start else ""
        quote = previous if previous in _QUOTES else ""
        for folded, original, label in aliases:
            size = len(original)
            if text[start:start + size].casefold() != folded:
                continue
            after = start + size
            if after < length and not (text[after] == "/" or self._stops_token(text[after]) or text[after] in _TRAILING):
                continue  # a longer name that merely begins like the root
            return self._extend(text, after, length, quote), label
        if previous and (previous in _NO_START_AFTER or unicodedata.category(previous)[0] in "LNM"):
            return start, ""
        end = self._extend(text, start + 1, length, quote)
        components = [part for part in text[start:end].split("/") if part]
        if len(components) >= 2 or (len(components) == 1 and components[0] in _TOP_LEVEL):
            return end, HOST_PATH
        return start, ""

    def _extend(self, text: str, position: int, length: int, quote: str = "") -> int:
        """Where the path that reaches ``position`` ends: at the quote that opened it, else at a delimiter or space."""
        if quote:
            closing = text.find(quote, position)
            if closing >= 0:
                return closing  # ``'/Users/x/My Files/y'``: a quoted path may contain spaces
        end = position
        while end < length and not self._stops_token(text[end]):
            end += 1
        while end > position and text[end - 1] in _TRAILING:
            end -= 1
        return end

    # -- structure ----------------------------------------------------------------------------------------------

    def clean(self, value: Any, *, exempt: frozenset[str] = frozenset()) -> Any:
        """``value`` with every host path removed. ``exempt`` names the keys whose values are content and stay as they are."""
        aliases, scopes = self._known()
        return self._walk(value, exempt, aliases, scopes)

    def _walk(
        self, value: Any, exempt: frozenset[str], aliases: list[tuple[str, str, str]], scopes: list[tuple[str, str]],
    ) -> Any:
        if isinstance(value, str):
            return self._redact(value, aliases)
        if isinstance(value, Mapping):
            return self._walk_mapping(value, exempt, aliases, scopes)
        if isinstance(value, (list, tuple)):
            return [self._walk(item, exempt, aliases, scopes) for item in value]
        return value

    def _walk_mapping(
        self, value: Mapping[Any, Any], exempt: frozenset[str], aliases: list[tuple[str, str, str]],
        scopes: list[tuple[str, str]],
    ) -> dict[Any, Any]:
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key in exempt:
                cleaned[key] = item
                continue
            if key == "discovered_worktrees" and isinstance(item, list):
                cleaned[key] = [self._worktree(entry, exempt, aliases, scopes) for entry in item]
                continue
            if isinstance(key, str) and key in PATH_FIELDS and isinstance(item, str):
                if not is_absolute_path_text(item):
                    cleaned[key] = item
                continue
            cleaned[self._key(key, cleaned, aliases)] = self._walk(item, exempt, aliases, scopes)
        return cleaned

    def _key(self, key: Any, taken: Mapping[Any, Any], aliases: list[tuple[str, str, str]]) -> Any:
        if not isinstance(key, str) or "/" not in key:
            return key
        redacted = self._redact(key, aliases)
        candidate, number = redacted, 1
        while candidate in taken:
            number += 1
            candidate = f"{redacted}#{number}"
        return candidate

    def _worktree(
        self, entry: Any, exempt: frozenset[str], aliases: list[tuple[str, str, str]], scopes: list[tuple[str, str]],
    ) -> Any:
        """A discovered worktree without its host path: a stable identifier and, where one applies, its scope and relative path."""
        if not isinstance(entry, Mapping):
            return self._walk(entry, exempt, aliases, scopes)
        path = entry.get("path")
        rest = {key: item for key, item in entry.items() if key != "path"}
        cleaned = self._walk_mapping(rest, exempt, aliases, scopes)
        if not isinstance(path, str):
            return cleaned
        host = _absolute_form(path)
        if host is None:
            return {"path": path, **cleaned}
        located: dict[str, Any] = {"worktree_id": worktree_identifier(host)}
        relation = scope_relative(host, scopes)
        if relation is not None:
            located["scope_id"], located["relative_path"] = relation
        return {**located, **cleaned}


def default_roots(extra: Iterable[HostRoot] = ()) -> list[HostRoot]:
    """The roots every process knows: its home directory, temporary directory and working directory."""
    roots = list(extra)
    for kind, getter in (
        ("home", lambda: str(Path.home())), ("tmp", tempfile.gettempdir), ("cwd", os.getcwd),
    ):
        try:
            roots.append(HostRoot(kind, "", getter()))
        except (OSError, RuntimeError, KeyError):
            continue
    return roots
