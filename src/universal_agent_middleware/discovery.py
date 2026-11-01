"""Autonomous Reality Discovery engine for UAM.

Discovers Git repositories, identifies projects, groups worktrees,
and builds a derived inventory — all within authorized RootScopes.

Layer 1: Deterministic filesystem discovery (no LLM, no git subprocess)
Layer 2: Identity resolution (remote-based project grouping)
Layer 3: Derived inventory with freshness/provenance
Layer 4: Optional lazy Git enrichment (on-demand or budgeted)
"""
from __future__ import annotations

import copy
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .root_scope import RootScopeRegistry
from .git_readonly import ReadOnlyGit
from .models import KIND_FILESYSTEM_DIRECTORY, KIND_GIT_REPOSITORY, is_git_checkout
from .errors import WorkspaceError
from .path_authority import PathPolicy
from .workspace import bind_root_identity
from .reality_index import (
    DEFAULT_MAX_AGE_SEC,
    IncompatibleSchemaError,
    IndexLockedError,
    RealityIndex,
)
from .scope_search import (
    DEFAULT_LIMITS,
    ScopeSearchLimits,
    find_ripgrep,
    is_sensitive_path,
    search_domain,
    search_tree,
)

# The most hits one scope search returns, whatever the caller asked for.
_MAX_SEARCH_RESULTS = 500


def _search_locator(
    scope_id: str, scope_root: Path, hit: Path, may_probe: Callable[[Path], bool],
) -> dict[str, str]:
    """Where a search hit can be read through the ordinary workspace tools.

    The locator names the derived workspace that contains the hit and the path inside it. The
    workspace is the nearest Git repository at or below the scope root; failing that, the hit's
    top-level directory; for a file directly in the scope root, the scope root itself. It is a
    pointer, not a permission: reading through it resolves the handle against live authority
    like any other request, so a scope without ``directory_admit``, a revoked scope or a nested
    scope that denies reading still refuses. It carries no host path.

    A directory is looked at for a ``.git`` entry only where ``may_probe`` says the scope that
    governs it lets its metadata be observed; elsewhere it is reported as a plain directory, so
    the locator does not tell what a denying scope keeps hidden.

    ``hit`` must lie below ``scope_root``.
    """
    ancestors = [parent for parent in hit.parents if parent == scope_root or scope_root in parent.parents]
    checkout = next((parent for parent in ancestors if may_probe(parent) and is_git_checkout(parent)), None)
    if checkout is not None:
        workspace_root, kind = checkout, KIND_GIT_REPOSITORY
    else:
        parts = hit.relative_to(scope_root).parts
        workspace_root = scope_root / parts[0] if len(parts) > 1 else scope_root
        kind = KIND_FILESYSTEM_DIRECTORY
    root_rel = "" if workspace_root == scope_root else workspace_root.relative_to(scope_root).as_posix()
    return {
        "workspace_id": f"derived:{scope_id}:{root_rel}",
        "path": hit.relative_to(workspace_root).as_posix(),
        "kind": kind,
    }


_URL_WITH_AUTHORITY = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)(?P<tail>.*)$", re.DOTALL)
# Only for these schemes is the user part of a remote URL an account name (``ssh://git@host/...``). For every
# other scheme (``https://<token>@host/...``, ``https://user:<token>@host/...``, ``git+https://...``) it is
# treated as a credential and dropped.
_USERINFO_IS_ACCOUNT = frozenset({"ssh", "git", "git+ssh", "ssh+git"})


def strip_url_credentials(url: str) -> str:
    """A remote URL without what it may carry besides identity: a password, a token, a query string.

    ``origin`` is whatever its owner typed, and a URL that embeds a token is common enough that the
    remote identity (returned by discovery, stored in the reality index and echoed into exploration
    evidence) must not be the raw string. ``scp``-style remotes (``git@host:org/repo``) and local
    paths have no authority section and come back unchanged.
    """
    match = _URL_WITH_AUTHORITY.match(url)
    if match is None:
        return url
    scheme = match.group("scheme")
    account_scheme = scheme.lower() in _USERINFO_IS_ACCOUNT
    userinfo, at, host = match.group("authority").rpartition("@")
    tail = match.group("tail")
    if at:
        account = userinfo.partition(":")[0] if account_scheme else ""
        authority = f"{account}@{host}" if account else host
    else:
        authority = host
    if not account_scheme:
        # A query string or fragment on a web URL is never part of the repository identity.
        tail = re.split(r"[?#]", tail, maxsplit=1)[0]
    return f"{scheme}://{authority}{tail}"


_PROJECT_MARKERS = frozenset({
    ".git",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "AGENTS.md",
    "CLAUDE.md",
})

_NOISE_DIRS = frozenset({
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    "vendor",
    "target",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    "coverage",
    ".turbo",
    ".parcel-cache",
    ".git",
})

# macOS TCC-protected and system-data directories — never descend (any depth).
# Proactive skip avoids iterdir()/stat() that trigger Sequoia "access data from other apps".
_MACOS_TCC_DIRS = frozenset({
    "Containers",
    "Group Containers",
    "Application Support",
    "Saved Application State",
    "Metadata",
    "Caches",
    "Mail",
    "Messages",
    "Safari",
    "Cookies",
    "Preferences",
    "HTTPStorages",
    "WebKit",
    "IdentityServices",
    "Biome",
    "IntelligencePlatform",
    "Suggestions",
    "Shortcuts",
    "Calendars",
    "Reminders",
    "HomeKit",
    "Accounts",
    "Sharing",
    "SyncServices",
    "Assistant",
    "CallServices",
    "CoreFollowUp",
    "Daemon Containers",
    "FamilyCircle",
    "Finance",
    "FinanceBackup",
    "Passes",
    "PersonalizationPortrait",
    "StatusKit",
    "Trial",
    "Weather",
})

# Top-level home directories that are not developer workspaces (depth 0 only).
_MACOS_HOME_SKIP_DIRS = frozenset({
    "Library",
    "Applications",
    "Pictures",
    "Music",
    "Movies",
    ".Trash",
    "Public",
    "System",
    "Volumes",
})

# Session-scoped circuit breaker: paths that returned EPERM/EACCES are never re-probed.
_denied_paths_circuit_breaker: set[str] = set()


def _normalize_path_key(path: Path) -> str:
    return str(path.expanduser().resolve(strict=False))


def clear_denied_paths_circuit_breaker() -> None:
    """Reset denied-path circuit breaker (tests only)."""
    _denied_paths_circuit_breaker.clear()


def _record_denied_path(path: Path) -> None:
    _denied_paths_circuit_breaker.add(_normalize_path_key(path))


def _relative_parts(path: Path, scan_root: Path) -> tuple[str, ...]:
    try:
        return path.resolve().relative_to(scan_root.resolve()).parts
    except ValueError:
        return path.parts


def _should_proactively_skip_path(path: Path, *, scan_root: Path) -> bool:
    """Return True when path string matches a skip rule — before iterdir/stat/is_dir."""
    if _normalize_path_key(path) in _denied_paths_circuit_breaker:
        return True
    rel_parts = _relative_parts(path, scan_root)
    for depth, part in enumerate(rel_parts):
        if part.startswith(".") and part != ".git":
            return True
        if part in _NOISE_DIRS or part in _MACOS_TCC_DIRS:
            return True
        if depth == 0 and part in _MACOS_HOME_SKIP_DIRS:
            return True
    return False


def _should_skip_directory(entry: Path, *, scan_root: Path, parent_depth: int) -> bool:
    """Return True if directory entry must not be descended during discovery."""
    name = entry.name
    if name.startswith(".") and name != ".git":
        return True
    if name in _NOISE_DIRS or name in _MACOS_TCC_DIRS:
        return True
    if parent_depth == 0 and name in _MACOS_HOME_SKIP_DIRS:
        return True
    return False

_MAX_DEPTH = 4
_MAX_REPOS = 500
_DEFAULT_CACHE_TTL = 300.0


def scan_coverage() -> dict[str, Any]:
    """The bounds every discovery scan runs under: what it did not find is not proven absent.

    Discovery finds Git repositories only. An ordinary directory inside an authorized scope is
    never listed here, even when it can be read through an explicit ``filesystem-directory``
    workspace: absence from a scan says nothing about readability.
    """
    return {
        "mode": "bounded",
        "max_depth": _MAX_DEPTH,
        "not_exhaustive": True,
        "max_repos": _MAX_REPOS,
        "discovers": "git-repositories",
        "non_git_directories": "not_discovered",
    }


def _enrichment_summary(inventory: dict[str, Any], budget: int) -> dict[str, Any]:
    """The ``git_enrichment`` block a fresh scan reports, recomputed from the instances as they stand."""
    instances = [inst for project in inventory.get("projects", []) for inst in project.get("instances", [])]
    enriched = sum(1 for inst in instances if inst.get("git_enriched"))
    return {
        "requested": True,
        "budget": budget,
        "enriched_instances": enriched,
        "total_instances": len(instances),
        "partial": enriched < len(instances),
        "complete": enriched == len(instances),
    }


@dataclass
class DiscoveredRepository:
    path: str
    remote_identity: str = ""
    default_branch: str = ""
    head: str = ""
    branch: str = ""
    is_worktree: bool = False
    common_dir: str = ""
    last_commit_ts: float = 0.0
    markers: list[str] = field(default_factory=list)
    clean: bool | None = None
    changed_count: int = 0
    git_enriched: bool = False

    @property
    def project_key(self) -> str:
        if self.remote_identity:
            return self.remote_identity
        if self.common_dir:
            return self.common_dir
        return self.path

    def to_dict(self, *, scope_id: str = "", scope_root: Path | None = None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "remote_identity": self.remote_identity,
            "default_branch": self.default_branch,
            "head": self.head,
            "branch": self.branch,
            "is_worktree": self.is_worktree,
            "last_commit_ts": self.last_commit_ts,
            "markers": self.markers,
            "git_enriched": self.git_enriched,
        }
        if self.clean is not None:
            d["clean"] = self.clean
            d["changed_count"] = self.changed_count
        if scope_id and scope_root is not None:
            try:
                rel = str(Path(self.path).resolve().relative_to(scope_root.resolve()))
                d["workspace_id"] = f"derived:{scope_id}:{rel}"
            except ValueError:
                d["workspace_id"] = f"derived:{scope_id}:{Path(self.path).name}"
        return d


@dataclass
class DiscoveredProject:
    project_id: str
    remote_identity: str = ""
    instances: list[DiscoveredRepository] = field(default_factory=list)
    canonical_path: str = ""
    languages: list[str] = field(default_factory=list)
    last_activity: str = ""
    status: str = "unknown"

    def to_dict(self, *, scope_id: str = "", scope_root: Path | None = None) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "remote_identity": self.remote_identity,
            "instance_count": len(self.instances),
            "canonical_path": self.canonical_path,
            "languages": self.languages,
            "last_activity": self.last_activity,
            "status": self.status,
            "instances": [
                i.to_dict(scope_id=scope_id, scope_root=scope_root)
                for i in self.instances
            ],
        }


@dataclass
class _ScopeCacheEntry:
    result: dict[str, Any]
    observed_at: float
    policy_generation: str
    git_enriched: bool = False


class DiscoveryEngine:
    """Discovers projects within authorized RootScopes."""

    def __init__(
        self,
        scope_registry: RootScopeRegistry,
        *,
        cache_ttl: float = _DEFAULT_CACHE_TTL,
        reality_index: RealityIndex | None = None,
        search_limits: ScopeSearchLimits = DEFAULT_LIMITS,
    ):
        self._scopes = scope_registry
        self._cache: dict[str, _ScopeCacheEntry] = {}
        self._cache_ttl = cache_ttl
        self._index = reality_index
        self._search_limits = search_limits

    def _cache_key(self, scope_id: str) -> str:
        return f"{scope_id}:{self._scopes.policy_generation}"

    def invalidate_cache(self, scope_id: str | None = None) -> None:
        """Invalidate cached inventory (e.g. after policy revocation)."""
        if scope_id is None:
            self._cache.clear()
        else:
            keys_to_remove = [k for k in self._cache if k.startswith(f"{scope_id}:")]
            for k in keys_to_remove:
                del self._cache[k]

    def discover_scope(
        self, scope_id: str, *, enrich_git: bool = False, git_budget: int = 50,
    ) -> dict[str, Any]:
        """Discover all projects within a scope.

        Fast mode (enrich_git=False): directory scan only, no git subprocesses.
        Enriched mode: optionally run git metadata reads up to git_budget repos.
        """
        scopes = self._scopes.list_scopes()
        target = None
        for s in scopes:
            if s["scope_id"] == scope_id:
                target = s
                break
        if not target:
            return {"error": f"unknown scope: {scope_id}"}

        if not target["authority"]["discover"]:
            return {"error": f"scope {scope_id} does not have discover authority"}

        root = Path(target["root"])
        if not root.is_dir():
            return {"error": f"scope root does not exist: {target['root']}"}

        repos = self._scan_for_repositories(root, target["authority"], enrich_git=enrich_git, git_budget=git_budget)
        projects = self._resolve_projects(repos)
        self._enrich_projects(projects, target["authority"])

        enriched_count = sum(
            1 for p in projects
            for inst in p.instances
            if inst.git_enriched
        )
        total_instances = sum(len(p.instances) for p in projects)

        observed_at = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": "scope-discovery-v1",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "scope_root": str(root),
            "total_repositories": len(repos),
            "total_projects": len(projects),
            "git_enriched": enrich_git,
            "git_enrichment": {
                "requested": enrich_git,
                "budget": git_budget if enrich_git else 0,
                "enriched_instances": enriched_count,
                "total_instances": total_instances,
                "partial": enrich_git and enriched_count < total_instances,
                "complete": enrich_git and enriched_count == total_instances,
            },
            "projects": [p.to_dict(scope_id=scope_id, scope_root=root) for p in projects],
        }

    def scope_inventory(
        self, scope_id: str, *, enrich_git: bool = False, git_budget: int = 50,
        allow_stale: bool = False,
    ) -> dict[str, Any]:
        """Return cached or fresh inventory for a scope."""
        now = time.time()
        policy_gen = self._scopes.policy_generation

        # Fast path: cross-process SQLite index (<50ms when warm)
        if self._index is not None:
            indexed = self._index.get_active_snapshot(
                scope_id,
                policy_gen,
                max_age_sec=min(self._cache_ttl, DEFAULT_MAX_AGE_SEC),
                allow_stale=allow_stale,
            )
            if indexed is not None:
                needs_git = enrich_git and not indexed.get("freshness", {}).get("git_enriched")
                if not needs_git:
                    result = copy.deepcopy(indexed)
                    stale = result.get("freshness", {}).get("stale", False)
                    result["freshness"]["served_at"] = datetime.now(timezone.utc).isoformat()
                    result["freshness"]["cache_hit"] = True
                    result["coverage"] = scan_coverage()
                    if stale and self._index is not None:
                        self._index.schedule_background_refresh(
                            scope_id,
                            lambda sid=scope_id: self._refresh_index(sid),
                        )
                    return result

        key = self._cache_key(scope_id)
        entry = self._cache.get(key)
        cache_hit = False
        persisted = False

        if entry and (now - entry.observed_at) < self._cache_ttl:
            if not enrich_git or entry.git_enriched:
                cache_hit = True
                result = copy.deepcopy(entry.result)
            else:
                result = self._enrich_cached_inventory(entry.result, git_budget=git_budget)
                entry.result = copy.deepcopy(result)
                entry.git_enriched = True
                entry.observed_at = time.time()
                cache_hit = True
        else:
            effective_enrich = enrich_git
            if not effective_enrich and self._index is not None:
                existing_gen = self._index._is_active_enriched(
                    scope_id, policy_gen
                )
                if existing_gen is not None:
                    effective_enrich = True
            result = self.discover_scope(scope_id, enrich_git=effective_enrich, git_budget=git_budget)
            if "error" not in result:
                self._cache[key] = _ScopeCacheEntry(
                    result=copy.deepcopy(result),
                    observed_at=time.time(),
                    policy_generation=policy_gen,
                    git_enriched=effective_enrich,
                )
                persisted = self._persist_for_next_read(scope_id, result, effective_enrich)

        if "error" not in result:
            cached_entry = self._cache.get(key)
            observed_at = cached_entry.observed_at if cached_entry else now
            cache_age_ms = int((now - observed_at) * 1000) if cache_hit else 0
            # "indexed" is a claim about what happened to this scan, so it follows the persistence
            # call's own answer: a scope without index authority or a missing index persists nothing.
            if cache_hit:
                source = "scope_inventory_cache"
            else:
                source = "live_scan_indexed" if persisted else "live_scan"
            result["freshness"] = {
                "served_at": datetime.now(timezone.utc).isoformat(),
                "cache_hit": cache_hit,
                "cache_age_ms": cache_age_ms,
                "expires_in_ms": max(0, int((self._cache_ttl - (now - observed_at)) * 1000)),
                "source": source,
                "policy_generation": policy_gen,
                "git_enriched": cached_entry.git_enriched if cached_entry else enrich_git,
            }
            result["coverage"] = scan_coverage()

        return result

    def index_scope(
        self,
        scope_id: str,
        *,
        enrich_git: bool = False,
        git_budget: int = 50,
    ) -> dict[str, Any]:
        """Force a live scan and persist to the cross-process reality index."""
        scopes = self._scopes.list_scopes()
        target = next((s for s in scopes if s["scope_id"] == scope_id), None)
        if target and not target["authority"].get("index"):
            return {"error": f"scope {scope_id} does not have index authority"}
        self.invalidate_cache(scope_id)
        result = self.discover_scope(scope_id, enrich_git=enrich_git, git_budget=git_budget)
        if "error" not in result:
            gen_id = self._persist_to_index(scope_id, result, enrich_git)
            result["index_generation"] = gen_id
            key = self._cache_key(scope_id)
            self._cache[key] = _ScopeCacheEntry(
                result=copy.deepcopy(result),
                observed_at=time.time(),
                policy_generation=self._scopes.policy_generation,
                git_enriched=enrich_git,
            )
        return result

    def _persist_to_index(
        self,
        scope_id: str,
        result: dict[str, Any],
        git_enriched: bool,
    ) -> str | None:
        if self._index is None:
            return None
        target = next((s for s in self._scopes.list_scopes()
                       if s["scope_id"] == scope_id), None)
        if target is None or not target["authority"].get("index"):
            return None
        if self._index.is_corrupt:
            self._index.rebuild()
        return self._index.write_snapshot(
            scope_id,
            result,
            self._scopes.policy_generation,
            git_enriched=git_enriched,
        )

    def _persist_for_next_read(
        self,
        scope_id: str,
        result: dict[str, Any],
        git_enriched: bool,
    ) -> bool:
        """Cache a read's own scan if the index allows it; a read never fails over its cache.

        An index this release may not write (newer schema) or cannot write right now (lock held past
        the retries) only costs the next reader a scan. ``index_scope`` is the explicit write and
        still raises: whoever asked for an index must learn that it was not written.
        """
        try:
            return self._persist_to_index(scope_id, result, git_enriched) is not None
        except (IncompatibleSchemaError, IndexLockedError):
            return False

    def _refresh_index(self, scope_id: str) -> None:
        """Background refresh callback (runs in daemon thread).

        Inherits git enrichment from the existing active snapshot to prevent
        quality-downgrade: if the current index is enriched, the refresh
        must also be enriched.
        """
        try:
            enrich = False
            if self._index is not None:
                gen = self._index._is_active_enriched(
                    scope_id, self._scopes.policy_generation
                )
                if gen is not None:
                    enrich = True
            self.index_scope(scope_id, enrich_git=enrich)
        except Exception:
            pass

    def _may_observe_git(self, repo_path: Path) -> bool:
        """Whether the scope that governs ``repo_path`` grants ``git_observe`` right now.

        The same question a fresh scan asks of each directory it walks (the most specific scope
        decides), so a repository is never asked for Git by one path and withheld by the other.
        """
        authority = self._scopes.effective_authority(repo_path)
        return authority is not None and authority.git_observe

    def _enrich_cached_inventory(self, result: dict[str, Any], *, git_budget: int) -> dict[str, Any]:
        """Lazy git enrichment for a cached fast-scan inventory.

        A cached inventory remembers where repositories are, not what may be asked of them, so
        authority is judged now, per repository, exactly as a fresh scan would judge it. A
        repository whose governing scope does not grant ``git_observe`` is left un-enriched and the
        result says the enrichment is partial.
        """
        enriched = copy.deepcopy(result)
        count = 0
        for project in enriched.get("projects", []):
            for inst in project.get("instances", []):
                if count >= git_budget:
                    enriched["git_enrichment_partial"] = True
                    enriched["git_enrichment"] = _enrichment_summary(enriched, git_budget)
                    return enriched
                if inst.get("git_enriched"):
                    continue
                repo_path = Path(inst.get("path", ""))
                if not repo_path.is_dir():
                    continue
                if not self._may_observe_git(repo_path):
                    continue
                repo = self._read_repo_metadata(repo_path)
                if not repo.git_enriched:
                    continue
                inst["head"] = repo.head
                inst["branch"] = repo.branch
                inst["remote_identity"] = repo.remote_identity
                inst["is_worktree"] = repo.is_worktree
                inst["last_commit_ts"] = repo.last_commit_ts
                inst["git_enriched"] = True
                if repo.clean is not None:
                    inst["clean"] = repo.clean
                    inst["changed_count"] = repo.changed_count
                count += 1
        enriched["git_enriched"] = True
        enriched["git_enrichment"] = _enrichment_summary(enriched, git_budget)
        if enriched["git_enrichment"]["partial"]:
            enriched["git_enrichment_partial"] = True
        return enriched

    def search_scope(self, scope_id: str, query: str, max_results: int = 50) -> dict[str, Any]:
        """Search text across all repositories in a scope, with project attribution."""
        scopes = self._scopes.list_scopes()
        target = None
        for s in scopes:
            if s["scope_id"] == scope_id:
                target = s
                break
        if not target:
            return {"error": f"unknown scope: {scope_id}"}
        if not target["authority"]["text_search"]:
            return {
                "error": f"scope {scope_id} does not have search authority",
                "search_completeness": "DENIED",
                "safe_to_conclude_absent": False,
                "absent_within_search_domain": False,
                "incomplete": True,
            }

        root = Path(target["root"])
        executable = find_ripgrep()
        if executable is None:
            return {
                "error": "search unavailable: ripgrep executable missing",
                "scope_id": scope_id,
                "search_completeness": "FAILED",
                "safe_to_conclude_absent": False,
                "absent_within_search_domain": False,
                "incomplete": True,
                "failure_reason": "execution_error",
                "failure_stage": "launch",
            }
        max_results = max(1, min(max_results, _MAX_SEARCH_RESULTS))
        # Authority is decided before anything is read. The nested scopes beneath the root are taken
        # as one snapshot that the whole search obeys, and the root is judged by the live registry
        # as well: another scope may govern the root path itself, which no nested snapshot shows.
        policy = PathPolicy.beneath(self._scopes, root)
        if not self._scopes.can_search(root):
            return {
                "error": f"scope {scope_id} does not have search authority",
                "scope_id": scope_id,
                "search_completeness": "DENIED",
                "safe_to_conclude_absent": False,
                "absent_within_search_domain": False,
                "incomplete": True,
            }
        tree = search_tree(
            root, query, executable=executable, policy=policy, max_results=max_results,
            limits=self._search_limits,
        )

        # Second layer, not the boundary: nothing here has been read on its authority. A hit that the
        # live registry no longer allows (the policy moved after the snapshot) is withheld, and the
        # absence conclusion below is withheld with it.
        authority_withheld = False
        results: list[dict[str, Any]] = []
        for parts in tree.hits:
            abs_path = root.joinpath(*parts)
            rel = "/".join(parts)
            if is_sensitive_path(rel):
                continue
            if not self._scopes.can_search(abs_path):
                authority_withheld = True
                continue
            entry: dict[str, Any] = {
                "path": rel,
                "scope_relative": True,
                "locator": _search_locator(scope_id, root, abs_path, self._may_probe_metadata),
            }
            project_id = self._attribute_path_to_project(root, str(abs_path), scope_id=scope_id)
            if project_id:
                entry["project_id"] = project_id
            results.append(entry)

        failure_stage: str | None
        if tree.timed_out:
            completeness = "FAILED"
            failure_reason: str | None = "timeout"
            failure_stage = "timeout"
        elif tree.rg_failed or tree.enumeration_failed:
            completeness = "FAILED"
            failure_reason = "execution_error"
            if tree.launch_failed:
                failure_stage = "launch"
            elif tree.enumeration_failed:
                failure_stage = "enumerate"
            else:
                failure_stage = "execute"
        elif tree.truncated:
            completeness = "PARTIAL"
            failure_reason = "result_limit"
            failure_stage = "limit"
        elif tree.scan_limit:
            completeness = "PARTIAL"
            failure_reason = "scan_limit"
            failure_stage = "limit"
        elif tree.changed or tree.other_errors:
            completeness = "PARTIAL"
            failure_reason = "enumeration_incomplete"
            failure_stage = "enumerate"
        elif tree.undecodable or tree.unterminated or tree.unexpected_output:
            completeness = "PARTIAL"
            failure_reason = "unreadable_output"
            failure_stage = "decode"
        else:
            completeness = "COMPLETE"
            failure_reason = None
            failure_stage = None

        result: dict[str, Any] = {
            "scope_id": scope_id,
            "query": query,
            "total_matches": len(results),
            "results": results,
            "search_completeness": completeness,
            # The search is bounded (see search_domain), so it never proves absence from the scope.
            # What a complete search without a match does establish is absence within its domain.
            "safe_to_conclude_absent": False,
            "absent_within_search_domain": (
                completeness == "COMPLETE" and len(results) == 0 and not authority_withheld
            ),
            "search_domain": search_domain(
                scope_authority_exclusions=policy.denies("scope_search") or authority_withheld,
                ignore_rules_not_applied=tree.ignore_rules_skipped > 0,
                limits=self._search_limits,
            ),
            "incomplete": completeness != "COMPLETE",
        }
        if failure_reason:
            result["failure_reason"] = failure_reason
        if failure_stage:
            result["failure_stage"] = failure_stage
        if tree.error_type:
            result["error_type"] = tree.error_type
        if tree.scan_limit:
            result["limit_reached"] = tree.scan_limit
        skipped: dict[str, int] = {}
        if tree.undecodable:
            skipped["undecodable_paths"] = tree.undecodable
        if tree.unterminated:
            skipped["unterminated_records"] = tree.unterminated
        if tree.unexpected_output:
            skipped["unexpected_records"] = tree.unexpected_output
        if tree.changed:
            skipped["changed_during_search"] = tree.changed
        if tree.other_errors:
            skipped["enumeration_errors"] = tree.other_errors
        if skipped:
            result["paths_skipped"] = skipped
        if tree.timed_out:
            result["note"] = (
                f"Search timed out after {self._search_limits.deadline_seconds:g}s; results shown were "
                "collected before the deadline and the remainder was not examined. "
                "Try narrowing the search with a more "
                "specific query or use uam_search_text on individual workspaces."
            )

        return result

    def _may_probe_metadata(self, path: Path) -> bool:
        """Whether the scope governing ``path`` lets its metadata be observed (the enumeration rule)."""
        authority = self._scopes.effective_authority(path)
        return authority is not None and (authority.metadata_read or authority.content_read)

    def _get_cached_inventory(self, scope_id: str) -> dict[str, Any] | None:
        key = self._cache_key(scope_id)
        entry = self._cache.get(key)
        if entry and (time.time() - entry.observed_at) < self._cache_ttl:
            return entry.result
        return None

    def _attribute_path_to_project(self, scope_root: Path, abs_path: str, scope_id: str = "") -> str | None:
        """Resolve which discovered project a file path belongs to."""
        cached = self._get_cached_inventory(scope_id) if scope_id else None
        if not cached and scope_id:
            self.scope_inventory(scope_id)
            cached = self._get_cached_inventory(scope_id)
        if not cached:
            return None
        file_path = Path(abs_path)
        best_match: str | None = None
        best_depth = -1
        for proj in cached.get("projects", []):
            for inst in proj.get("instances", []):
                inst_path = Path(inst.get("path", ""))
                try:
                    file_path.relative_to(inst_path)
                    depth = len(inst_path.parts)
                    if depth > best_depth:
                        best_depth = depth
                        best_match = proj.get("project_id", "")
                except ValueError:
                    continue
        return best_match

    def _scan_for_repositories(
        self, root: Path, authority: dict[str, bool], *,
        enrich_git: bool = False, git_budget: int = 50,
    ) -> list[DiscoveredRepository]:
        """Layer 1: Deterministic filesystem scan for Git repos."""
        repos: list[DiscoveredRepository] = []
        git_count = [0]
        self._walk_for_repos(
            root, repos, depth=0, scan_root=root,
            git_observe=authority.get("git_observe", False) and enrich_git,
            enrich_git=enrich_git,
            git_budget=git_budget,
            git_count=git_count,
        )
        return repos[:_MAX_REPOS]

    def _walk_for_repos(
        self, path: Path, repos: list[DiscoveredRepository], depth: int,
        scan_root: Path,
        git_observe: bool = False,
        enrich_git: bool = False,
        git_budget: int = 50,
        git_count: list[int] | None = None,
    ) -> None:
        if depth > _MAX_DEPTH or len(repos) >= _MAX_REPOS:
            return

        if _should_proactively_skip_path(path, scan_root=scan_root):
            return

        effective_scope = self._scopes.resolve_scope(str(path))
        if effective_scope:
            if not effective_scope.authority.discover:
                return
            if enrich_git:
                git_observe = effective_scope.authority.git_observe

        try:
            entries = sorted(path.iterdir())
        except (PermissionError, OSError):
            _record_denied_path(path)
            return

        has_git = False
        markers: list[str] = []

        for entry in entries:
            name = entry.name
            if name == ".git":
                has_git = True
                markers.append(".git")
            elif name in _PROJECT_MARKERS:
                markers.append(name)

        if has_git:
            counter = git_count if git_count is not None else [0]
            if git_observe and counter[0] < git_budget:
                repo = self._read_repo_metadata(path)
                if repo.git_enriched:
                    counter[0] += 1
            else:
                repo = DiscoveredRepository(path=str(path))
            repo.markers = markers
            repos.append(repo)
            return

        for entry in entries:
            if _should_skip_directory(entry, scan_root=scan_root, parent_depth=depth):
                continue
            if _should_proactively_skip_path(entry, scan_root=scan_root):
                continue
            try:
                is_dir = entry.is_dir()
            except (PermissionError, OSError):
                _record_denied_path(entry)
                continue
            if not is_dir:
                continue
            if entry.is_symlink():
                continue
            self._walk_for_repos(
                entry, repos, depth + 1, scan_root=scan_root,
                git_observe=git_observe,
                enrich_git=enrich_git,
                git_budget=git_budget,
                git_count=git_count,
            )

    def _read_repo_metadata(self, repo_path: Path) -> DiscoveredRepository:
        """Read basic git metadata using hermetic ReadOnlyGit with bound RootIdentity and live scope check."""
        repo = DiscoveredRepository(path=str(repo_path), git_enriched=False)

        try:
            lstat_info = os.stat(repo_path, follow_symlinks=False)
            if stat.S_ISLNK(lstat_info.st_mode) or not stat.S_ISDIR(lstat_info.st_mode):
                return repo
            if not self._may_observe_git(repo_path):
                return repo
            bound_identity = bind_root_identity(
                repo_path, policy_generation=self._scopes.policy_generation,
            )
            bound_root = Path(bound_identity.root)
            if not self._may_observe_git(bound_root):
                return repo

            def _reverify_discovery_git() -> None:
                if self._scopes.policy_generation != bound_identity.policy_generation:
                    raise WorkspaceError("scope policy generation changed during git enrichment")
                if not self._may_observe_git(bound_root) or not self._may_observe_git(repo_path):
                    raise WorkspaceError("live scope authority denies git.observe")
                now_lstat = os.stat(repo_path, follow_symlinks=False)
                if stat.S_ISLNK(now_lstat.st_mode) or (
                    (now_lstat.st_dev, now_lstat.st_ino) != (bound_identity.dev, bound_identity.ino)
                ):
                    raise WorkspaceError("workspace root identity changed")

            git = ReadOnlyGit(
                bound_identity.root,
                path_policy=PathPolicy.beneath(self._scopes, bound_identity.root),
                root_identity=bound_identity,
                authority_check=_reverify_discovery_git,
                require_bound_identity=True,
            )
            status = git.status()

            head = status.get("head") or ""  # an unborn branch has no head: "" like an unobserved one
            branch = status.get("branch", "")

            changed = [line for line in status.get("status", "").splitlines() if line.strip()]
            clean = len(changed) == 0
            changed_count = len(changed)
            remote_identity = ""
            is_worktree = False
            common_dir = ""
            last_commit_ts = 0.0

            try:
                remote_url = git._run(["remote", "get-url", "origin"], timeout=5).strip()
                remote_identity = self._normalize_remote(remote_url)
            except WorkspaceError:
                pass

            try:
                common = git._run(["rev-parse", "--git-common-dir"], timeout=5).strip()
                if common != ".git":
                    is_worktree = True
                    common_dir = str((bound_root / common).resolve())
            except WorkspaceError:
                pass

            try:
                ts_str = git._run(["log", "-1", "--format=%ct"], timeout=5).strip()
                last_commit_ts = float(ts_str)
            except (WorkspaceError, ValueError):
                pass

            git._verify_root()
            repo.head = head
            repo.branch = branch
            repo.clean = clean
            repo.changed_count = changed_count
            repo.remote_identity = remote_identity
            repo.is_worktree = is_worktree
            repo.common_dir = common_dir
            repo.last_commit_ts = last_commit_ts
            repo.git_enriched = True
        except (WorkspaceError, OSError):
            return DiscoveredRepository(path=str(repo_path), git_enriched=False)

        return repo

    def _normalize_remote(self, url: str) -> str:
        """Normalize a git remote URL to org/repo identity, never carrying a credential."""
        url = strip_url_credentials(url.strip())
        if url.endswith(".git"):
            url = url[:-4]
        if url.startswith("git@"):
            parts = url.split(":", 1)
            if len(parts) == 2:
                return parts[1]
        if "github.com/" in url or "gitlab.com/" in url:
            for prefix in ("https://github.com/", "https://gitlab.com/",
                           "http://github.com/", "http://gitlab.com/"):
                if url.startswith(prefix):
                    return url[len(prefix):]
        return url

    def _resolve_projects(
        self, repos: list[DiscoveredRepository]
    ) -> list[DiscoveredProject]:
        """Layer 2: Group repositories into logical projects by identity."""
        groups: dict[str, list[DiscoveredRepository]] = {}
        for repo in repos:
            key = repo.project_key
            groups.setdefault(key, []).append(repo)

        projects: list[DiscoveredProject] = []
        for key, instances in groups.items():
            canonical = self._pick_canonical(instances)
            project_id = self._derive_project_id(key, canonical)

            proj = DiscoveredProject(
                project_id=project_id,
                remote_identity=canonical.remote_identity,
                instances=instances,
                canonical_path=canonical.path,
            )
            projects.append(proj)

        return projects

    def _pick_canonical(self, instances: list[DiscoveredRepository]) -> DiscoveredRepository:
        """Pick the most likely canonical instance (non-worktree, most recent)."""
        non_worktrees = [r for r in instances if not r.is_worktree]
        candidates = non_worktrees or instances
        return max(candidates, key=lambda r: r.last_commit_ts)

    def _derive_project_id(self, key: str, canonical: DiscoveredRepository) -> str:
        """Derive a human-readable project ID from the grouping key."""
        if canonical.remote_identity:
            parts = canonical.remote_identity.split("/")
            if len(parts) >= 2:
                return parts[-1].lower()
            return parts[0].lower()
        return Path(canonical.path).name.lower()

    def _enrich_projects(
        self, projects: list[DiscoveredProject], authority: dict[str, bool]
    ) -> None:
        """Layer 3: Add classification and freshness metadata."""
        now = time.time()
        seven_days = 7 * 86400
        thirty_days = 30 * 86400
        one_eighty_days = 180 * 86400

        for proj in projects:
            latest_ts = max(
                (i.last_commit_ts for i in proj.instances if i.last_commit_ts > 0),
                default=0,
            )

            if latest_ts > 0:
                proj.last_activity = datetime.fromtimestamp(
                    latest_ts, tz=timezone.utc
                ).isoformat()
                age = now - latest_ts
                if age < seven_days:
                    proj.status = "active"
                elif age < thirty_days:
                    proj.status = "recent"
                elif age < one_eighty_days:
                    proj.status = "dormant"
                else:
                    proj.status = "archived"

            proj.languages = self._detect_languages(proj)

    def _detect_languages(self, proj: DiscoveredProject) -> list[str]:
        """Simple language detection from project markers."""
        langs: set[str] = set()
        for inst in proj.instances:
            for m in inst.markers:
                match m:
                    case "pyproject.toml":
                        langs.add("python")
                    case "package.json":
                        langs.add("javascript")
                    case "Cargo.toml":
                        langs.add("rust")
                    case "go.mod":
                        langs.add("go")
                    case "pom.xml" | "build.gradle":
                        langs.add("java")
                    case _:
                        pass
        return sorted(langs)
