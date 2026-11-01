"""Path-level authority beneath a workspace root.

Admission verifies the RootScope authority of a workspace's ROOT only. A RootScope nested inside
that root (an evidence or preservation directory, say) is a narrower trust zone, and the
documented rule is that the most specific scope wins. This module lets the workspace Reader, the
Git observer and the scope search (``scope_search``) enforce that rule per path, before any file is
opened.

Design constraints:

* fail closed: a path is checked both as written (lexical) and as it really resolves, so neither
  an alias of a denied file nor a link planted inside a denied directory gets through;
* the spelling of a path is chosen by the caller, so it is also checked the way a case- and
  normalization-insensitive filesystem (the macOS default) sees it, and must be allowed under both
  readings: ``Evidence/x`` is the file ``evidence/x`` there;
* one snapshot of the live policy per operation: the policy is re-read for every operation, so a
  revocation applies to the next call and one walk never straddles two different policies;
* no oracle: a denial is decided from the path alone, before any existence check;
* a hard link is the same bytes under another name, and authority here is decided from a name: a
  regular file with other names is refused while a nested scope denies the operation, because its
  other name may lie inside that scope;
* explicit contract: only workspaces resolved through the derived family are guarded. A static
  registration is its own, separately authorized contract and is not touched here.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, assert_never

from .errors import ScopeAuthorityError
from .root_scope import RootScopeAuthority, RootScopeRegistry, fold_path

PathOperation = Literal["read", "search", "enumerate", "scope_search"]


def _has_other_names(info: os.stat_result) -> bool:
    """A regular file with more than one name."""
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


def _is_hard_linked(path: Path) -> bool:
    """``_has_other_names`` for a path. An uninspectable path is not one: the caller's own
    handling of that error applies."""
    try:
        info = os.stat(path)
    except OSError:
        return False
    return _has_other_names(info)


@dataclass(frozen=True)
class _Zone:
    """A RootScope nested under the workspace root, with its resolved root."""

    root: Path
    folded_root: tuple[str, ...]
    scope_id: str
    authority: RootScopeAuthority

    def covers(self, path: Path) -> bool:
        return path == self.root or self.root in path.parents

    def covers_folded(self, folded_path: tuple[str, ...]) -> bool:
        return folded_path[: len(self.folded_root)] == self.folded_root

    def allows(self, operation: PathOperation) -> bool:
        authority = self.authority
        if operation == "read":
            return authority.content_read
        if operation == "search":
            # Search returns matching lines, so it is content access with the search permission.
            return authority.content_read and authority.text_search
        if operation == "enumerate":
            # Names and sizes: granted by metadata access, and implied by content access.
            return authority.content_read or authority.metadata_read
        if operation == "scope_search":
            # The cross-project scope search reports which files contain a query, never the lines,
            # and has always been authorised by the search permission alone. The workspace
            # ``search`` above returns lines and so also needs content access; the two are
            # deliberately not the same operation.
            return authority.text_search
        assert_never(operation)


class PathPolicy:
    """Immutable view of the nested-scope authority beneath one workspace root.

    Paths must be absolute. A path outside every nested zone is governed by the scope that
    admitted the workspace, which the caller already verified, so it is always allowed here.
    """

    __slots__ = ("_zones",)

    def __init__(self, zones: tuple[_Zone, ...] = ()):
        self._zones = zones  # most specific first

    @classmethod
    def unrestricted(cls) -> PathPolicy:
        return cls(())

    @classmethod
    def beneath(cls, scopes: RootScopeRegistry, workspace_root: str | Path) -> PathPolicy:
        """Snapshot the live policy: the scopes nested under ``workspace_root``."""
        return cls(tuple(
            _Zone(root=root, folded_root=fold_path(root), scope_id=scope.scope_id, authority=scope.authority)
            for root, scope in scopes.nested_scopes(workspace_root)
        ))

    @property
    def restricted(self) -> bool:
        return bool(self._zones)

    def _governing(self, path: Path) -> tuple[_Zone, ...]:
        """The zones that must all allow an operation on ``path``.

        The most specific zone as the path is spelled, and the most specific one as a
        case-insensitive filesystem would see it. When both name the same zone (the usual case) it is
        that zone alone; when they differ, both must allow, so the stricter reading wins and neither
        reading can grant what the other denies.
        """
        if not self._zones:
            return ()
        exact = next((zone for zone in self._zones if zone.covers(path)), None)
        folded_path = fold_path(path)
        folded = next((zone for zone in self._zones if zone.covers_folded(folded_path)), None)
        if exact is folded:
            return () if exact is None else (exact,)
        return tuple(zone for zone in (exact, folded) if zone is not None)

    def allows(self, operation: PathOperation, path: Path) -> bool:
        return all(zone.allows(operation) for zone in self._governing(path))

    def require(self, operation: PathOperation, *paths: Path) -> None:
        """Raise ``ScopeAuthorityError`` unless every given path is allowed."""
        for path in paths:
            for zone in self._governing(path):
                if not zone.allows(operation):
                    raise ScopeAuthorityError(operation, zone.scope_id)

    def _denying_zone(self, operation: PathOperation) -> _Zone | None:
        return next((zone for zone in self._zones if not zone.allows(operation)), None)

    def denies(self, operation: PathOperation) -> bool:
        """Whether any nested scope denies ``operation``."""
        return self._denying_zone(operation) is not None

    def has_other_names(self, operation: PathOperation, path: Path) -> bool:
        """Whether ``path`` is a regular file that has other names while a nested scope denies ``operation``.

        Only a workspace that contains a denying nested scope pays for the ``stat``; a path that
        cannot be inspected is left to the caller's own handling of that error.
        """
        return self._denying_zone(operation) is not None and _is_hard_linked(path)

    def refuses_other_names(self, operation: PathOperation, info: os.stat_result) -> bool:
        """``has_other_names`` for an object that has already been inspected.

        A walk that opens files judges the object it holds (``fstat`` of the open descriptor, or
        the ``lstat`` it listed), not the name it listed, so a name swapped after the listing
        cannot change which object was judged.
        """
        return self._denying_zone(operation) is not None and _has_other_names(info)

    def require_single_name(self, operation: PathOperation, path: Path) -> None:
        """Raise ``ScopeAuthorityError`` for a hard-linked file (see ``has_other_names``)."""
        denying = self._denying_zone(operation)
        if denying is not None and _is_hard_linked(path):
            raise ScopeAuthorityError(operation, denying.scope_id, reason="hard_linked_file")

    def require_single_object_name(self, operation: PathOperation, info: os.stat_result) -> None:
        """``require_single_name`` for an object that is already open: judged by the held object's link count.

        Used by the descriptor-based Reader, which decides from ``fstat`` of the descriptor it will read, not from a
        path that could name another file by the time it is read.
        """
        denying = self._denying_zone(operation)
        if denying is not None and _has_other_names(info):
            raise ScopeAuthorityError(operation, denying.scope_id, reason="hard_linked_file")

    def descends(self, operation: PathOperation, directory: Path) -> bool:
        """Whether a walk should enter ``directory``.

        A denied directory is still entered when a zone that allows the operation lies beneath
        it (an allowed scope nested inside a denied one), so that scope stays reachable; the
        entries of the denied directory itself are filtered one by one with ``allows``.
        """
        if self.allows(operation, directory):
            return True
        return any(
            zone.allows(operation) and directory in zone.root.parents for zone in self._zones
        )

    def pockets(self, operation: PathOperation, workspace_root: Path) -> list[tuple[str, ...]]:
        """Roots, as components below ``workspace_root``, of allowed scopes nested inside a denying one.

        A walk that never lists a denying directory cannot find an allowed scope inside it by
        walking, so such a scope has to be reached directly. A scope is listed here only when
        ``operation`` is allowed at its root and denied at its parent directory; one whose parent
        is allowed is reached by the ordinary walk. Components are taken below the workspace root
        by position, as in ``excluded_subtrees``, because a zone may be reached through a root
        spelled differently.
        """
        base = workspace_root.resolve()
        folded_base = fold_path(base)
        roots: set[tuple[str, ...]] = set()
        for zone in self._zones:
            if not self.allows(operation, zone.root) or self.allows(operation, zone.root.parent):
                continue
            if zone.folded_root[: len(folded_base)] != folded_base or len(zone.root.parts) <= len(base.parts):
                raise ValueError("a nested zone does not lie beneath the workspace root")
            roots.add(tuple(zone.root.parts[len(base.parts):]))
        return sorted(roots)

    def excluded_subtrees(self, operation: PathOperation, workspace_root: Path) -> list[str]:
        """Workspace-relative POSIX paths of the subtrees that deny ``operation``.

        Used where a pathspec is the only available filter (Git). A pathspec cannot re-include a
        zone nested inside an excluded one, so such a zone is excluded too: fail closed. The path is
        taken below the workspace root by components, because a zone may be reached through a root
        spelled differently (see ``RootScopeRegistry.nested_scopes``).
        """
        denied = [zone for zone in self._zones if not zone.allows(operation)]
        outermost = [
            zone for zone in denied
            if not any(other.root != zone.root and other.root in zone.root.parents for other in denied)
        ]
        base = workspace_root.resolve()  # the root the zones were derived from (see ``beneath``)
        folded_base = fold_path(base)
        subtrees: set[str] = set()
        for zone in outermost:
            if zone.folded_root[: len(folded_base)] != folded_base or len(zone.root.parts) <= len(base.parts):
                raise ValueError("a nested zone does not lie beneath the workspace root")
            subtrees.add(Path(*zone.root.parts[len(base.parts):]).as_posix())
        return sorted(subtrees)
