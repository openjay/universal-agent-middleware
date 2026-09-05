"""RootScope authority model for UAM Autonomous Reality Discovery.

A RootScope defines a standing trust zone: a directory tree where UAM is
authorized to perform specific operations (discover, read, search, etc.)
without per-workspace registration.

Authority inheritance: all paths under a scope's root inherit that scope's
permissions. More specific scopes (longer root paths) take precedence.

Override enforcement: reserved for v0.5; currently loaded but not enforced.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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
        }


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

    def covers(self, path: str | Path) -> bool:
        """Check if a path falls within this scope's root."""
        try:
            resolved = Path(path).resolve()
            scope_root = Path(self.root).resolve()
            resolved.relative_to(scope_root)
            return True
        except (ValueError, OSError):
            return False

    def can_read_content(self, path: str | Path) -> bool:
        return self.covers(path) and self.authority.content_read

    def can_discover(self, path: str | Path) -> bool:
        return self.covers(path) and self.authority.discover


class RootScopeRegistry:
    """Manages standing trust zones.

    Scopes are loaded from a JSON config file. More specific scopes
    (longer root paths) take precedence over broader ones for a given path.
    """

    def __init__(self, config_path: str | Path | None = None):
        self._scopes: list[RootScope] = []
        self._overrides: dict[str, str] = {}
        if config_path:
            self._load(Path(config_path))

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
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

    def list_scopes(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._scopes]

    def resolve_scope(self, path: str | Path) -> RootScope | None:
        """Find the most specific scope covering a path."""
        resolved = Path(path).resolve()
        for scope in self._scopes:
            if scope.covers(resolved):
                return scope
        return None

    def can_read(self, path: str | Path) -> bool:
        scope = self.resolve_scope(path)
        return scope is not None and scope.authority.content_read

    def can_discover(self, path: str | Path) -> bool:
        scope = self.resolve_scope(path)
        return scope is not None and scope.authority.discover

    def can_search(self, path: str | Path) -> bool:
        scope = self.resolve_scope(path)
        return scope is not None and scope.authority.text_search

    def can_git_observe(self, path: str | Path) -> bool:
        scope = self.resolve_scope(path)
        return scope is not None and scope.authority.git_observe

    def get_override(self, path: str) -> str | None:
        """Check if a path has a human override (ignore/restrict/archive)."""
        return self._overrides.get(path)

    def add_scope(self, scope: RootScope) -> None:
        self._scopes.append(scope)
        self._scopes.sort(key=lambda s: len(str(Path(s.root).resolve())), reverse=True)
