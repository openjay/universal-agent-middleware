"""RootScope authority model for UAM Autonomous Reality Discovery.

A RootScope defines a standing trust zone: a directory tree where UAM is
authorized to perform specific operations (discover, read, search, etc.)
without per-workspace registration.

Authority inheritance: all paths under a scope's root inherit that scope's
permissions. More specific scopes (longer root paths) take precedence.

Override enforcement: reserved for v0.5; currently loaded but not enforced.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .policy import fold_name


def fold_path(path: Path) -> tuple[str, ...]:
    """The components of ``path`` as a case- and normalization-insensitive filesystem compares them."""
    return tuple(fold_name(part) for part in path.parts)


@dataclass(frozen=True)
class RootScopeAuthority:
    discover: bool = False
    metadata_read: bool = False
    content_read: bool = False
    text_search: bool = False
    git_observe: bool = False
    classify: bool = False
    index: bool = False
    relate: bool = False
    auto_admit: bool = False
    # On-demand, read-only admission of ordinary (non-Git) directories as
    # `filesystem-directory` workspaces. Never implies discovery, indexing or Git access.
    directory_admit: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "discover": self.discover,
            "metadata_read": self.metadata_read,
            "content_read": self.content_read,
            "text_search": self.text_search,
            "git_observe": self.git_observe,
            "classify": self.classify,
            "index": self.index,
            "relate": self.relate,
            "auto_admit": self.auto_admit,
            "directory_admit": self.directory_admit,
        }

    def meet(self, other: RootScopeAuthority) -> RootScopeAuthority:
        """What both authorities grant: a flag is set only when both set it."""
        return RootScopeAuthority(**{
            field.name: getattr(self, field.name) and getattr(other, field.name)
            for field in fields(self)
        })


@dataclass(frozen=True)
class RootScope:
    scope_id: str
    root: str
    authority: RootScopeAuthority
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "root": self.root,
            "authority": self.authority.to_dict(),
            "description": self.description,
        }

    def policy_digest_basis(self) -> dict[str, Any]:
        """What ``policy_generation`` hashes: ``to_dict`` minus a ``directory_admit`` left at False.

        A scope that does not use the bit keeps the digest it had before the bit existed;
        otherwise installing this release would invalidate every reality-index snapshot for
        a policy that did not change. Enabling the bit changes the digest, as any authority
        change must.
        """
        basis = self.to_dict()
        if not self.authority.directory_admit:
            del basis["authority"]["directory_admit"]
        return basis

    def covers(self, path: str | Path) -> bool:
        """Check if a path falls within this scope's root."""
        try:
            resolved = Path(path).resolve()
            scope_root = Path(self.root).resolve()
            resolved.relative_to(scope_root)
            return True
        except (ValueError, OSError):
            return False

    def covers_folded(self, path: str | Path) -> bool:
        """Like ``covers``, comparing case- and normalization-insensitively.

        This is what a case-insensitive filesystem sees: ``Evidence`` and ``evidence`` are one
        directory there, and the spelling is chosen by whoever supplies the path.
        """
        try:
            resolved = Path(path).resolve()
            scope_root = Path(self.root).resolve()
        except (OSError, RuntimeError):
            return False
        root_parts = fold_path(scope_root)
        return fold_path(resolved)[: len(root_parts)] == root_parts


class RootScopeRegistry:
    """Manages standing trust zones.

    Scopes are loaded from a JSON config file. More specific scopes
    (longer root paths) take precedence over broader ones for a given path.
    """

    def __init__(self, config_path: str | Path | None = None):
        self._scopes: list[RootScope] = []
        self._overrides: dict[str, str] = {}
        self._config_path: Path | None = Path(config_path) if config_path else None
        self._policy_generation: str = ""
        self._source_mtime_ns: int | None = None
        self._source_size: int | None = None
        self._source_hash: str = ""
        if config_path:
            self._load(Path(config_path))
        else:
            self._recompute_policy_generation()

    def _clear_policy(self) -> None:
        self._scopes = []
        self._overrides = {}
        self._source_mtime_ns = None
        self._source_size = None
        self._source_hash = ""
        self._recompute_policy_generation()

    def _load(self, path: Path) -> None:
        self._scopes = []
        self._overrides = {}
        if not path.exists():
            self._clear_policy()
            return
        try:
            stat = path.stat()
            raw_text = path.read_text(encoding="utf-8")
            raw = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            self._clear_policy()
            return

        for scope_raw in raw.get("scopes", []):
            authority = RootScopeAuthority(**scope_raw.get("authority", {}))
            self._scopes.append(RootScope(
                scope_id=scope_raw["scope_id"],
                root=scope_raw["root"],
                authority=authority,
                description=scope_raw.get("description", ""),
            ))

        self._overrides = raw.get("overrides", {})
        self._scopes.sort(key=lambda s: len(str(Path(s.root).resolve())), reverse=True)
        self._source_mtime_ns = stat.st_mtime_ns
        self._source_size = stat.st_size
        self._source_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        self._recompute_policy_generation()

    def _maybe_reload(self) -> None:
        """Reload policy from disk when the config file has changed or revoked."""
        if self._config_path is None:
            return
        if not self._config_path.exists():
            if self._scopes or self._overrides or self._source_hash:
                self._clear_policy()
            return
        try:
            stat = self._config_path.stat()
            raw_text = self._config_path.read_text(encoding="utf-8")
            content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        except OSError:
            if self._scopes or self._overrides or self._source_hash:
                self._clear_policy()
            return
        if (
            self._source_mtime_ns is not None
            and stat.st_mtime_ns == self._source_mtime_ns
            and self._source_size == stat.st_size
            and self._source_hash == content_hash
        ):
            return
        self._load(self._config_path)

    def _recompute_policy_generation(self) -> None:
        payload = {
            "scopes": [s.policy_digest_basis() for s in self._scopes],
            "overrides": self._overrides,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        self._policy_generation = digest

    @property
    def policy_generation(self) -> str:
        self._maybe_reload()
        return self._policy_generation

    def list_scopes(self) -> list[dict[str, Any]]:
        self._maybe_reload()
        return [s.to_dict() for s in self._scopes]

    def resolve_scope(self, path: str | Path) -> RootScope | None:
        """Find the most specific scope covering a path."""
        self._maybe_reload()
        resolved = Path(path).resolve()
        for scope in self._scopes:
            if scope.covers(resolved):
                return scope
        return None

    def nested_scopes(self, root: str | Path) -> list[tuple[Path, RootScope]]:
        """Scopes whose resolved root lies strictly inside ``root``, most specific first.

        Admission verifies the authority at a workspace root only. These are the narrower trust
        zones inside it whose authority takes precedence for the paths they cover.
        """
        self._maybe_reload()
        base = Path(root).resolve()
        folded_base = fold_path(base)
        nested: list[tuple[Path, RootScope]] = []
        for scope in self._scopes:
            try:
                scope_root = Path(scope.root).resolve()
            except (OSError, RuntimeError):
                continue  # an unresolvable root covers nothing (see covers()), so it nests nothing
            folded_root = fold_path(scope_root)
            # Compared as a case-insensitive filesystem sees it: a scope spelled ``Evidence`` still
            # lies inside a workspace root that spells its parent differently, and it is the same
            # directory, not a nested one, when only the spelling differs.
            if len(folded_root) > len(folded_base) and folded_root[: len(folded_base)] == folded_base:
                nested.append((scope_root, scope))
        return nested

    def can_read(self, path: str | Path) -> bool:
        authority = self.effective_authority(path)
        return authority is not None and authority.content_read

    def can_search(self, path: str | Path) -> bool:
        authority = self.effective_authority(path)
        return authority is not None and authority.text_search

    def effective_authority(self, path: str | Path) -> RootScopeAuthority | None:
        """Return the most-specific authority for a path, or None if uncovered.

        The path is judged twice, as spelled and as a case-insensitive filesystem would see it, and
        must be allowed by both: ``Evidence/x`` is the file ``evidence/x`` there, so a scope that
        denies ``evidence`` cannot be sidestepped by changing the case of the name. Where the two
        views disagree about which scope governs, only what both scopes grant is granted; a path
        that no scope covers as spelled is uncovered, whatever a case-folded comparison would say.
        """
        self._maybe_reload()
        resolved = Path(path).resolve()
        exact = next((scope for scope in self._scopes if scope.covers(resolved)), None)
        # The deepest folded match, counted in components: string length is not comparable across
        # spellings that normalize differently.
        folded = max(
            (scope for scope in self._scopes if scope.covers_folded(resolved)),
            key=lambda scope: len(Path(scope.root).resolve().parts),
            default=None,
        )
        if exact is None or folded is None:
            return None
        if exact is folded:
            return exact.authority
        return exact.authority.meet(folded.authority)

    def get_override(self, path: str) -> str | None:
        """Check if a path has a human override (ignore/restrict/archive)."""
        self._maybe_reload()
        return self._overrides.get(path)

    def add_scope(self, scope: RootScope) -> None:
        self._scopes.append(scope)
        self._scopes.sort(key=lambda s: len(str(Path(s.root).resolve())), reverse=True)
        self._recompute_policy_generation()

    def replace_scopes(self, scopes: list[RootScope], overrides: dict[str, str] | None = None) -> None:
        """Replace all scopes (used for revocation tests and hot reload)."""
        self._scopes = list(scopes)
        self._scopes.sort(key=lambda s: len(str(Path(s.root).resolve())), reverse=True)
        if overrides is not None:
            self._overrides = overrides
        self._recompute_policy_generation()
