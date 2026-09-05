"""Autonomous Reality Discovery engine for UAM.

Discovers Git repositories, identifies projects, groups worktrees,
and builds a derived inventory — all within authorized RootScopes.

Layer 1: Deterministic filesystem discovery (no LLM)
Layer 2: Identity resolution (remote-based project grouping)
Layer 3: Derived inventory with freshness/provenance
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .root_scope import RootScope, RootScopeRegistry
from .git_readonly import ReadOnlyGit
from .policy import _is_denied_component
from .errors import WorkspaceError

_SENSITIVE_NAMES = frozenset({
    ".env", ".ssh", ".aws", ".gnupg", ".kube", ".docker",
    ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json",
    "secrets.json", "id_rsa", "id_ed25519",
})

_SENSITIVE_EXTENSIONS = frozenset({
    ".pem", ".p12", ".pfx", ".key", ".keystore",
})

_RG_SECRET_GLOBS = [
    "!.git", "!.ssh", "!.aws", "!.gnupg", "!.kube", "!.docker",
    "!.npmrc", "!.pypirc", "!.netrc", "!**/credentials",
    "!**/credentials.json", "!**/secrets.json",
    "!**/.env", "!**/.env.*",
    "!**/*.pem", "!**/*.p12", "!**/*.pfx", "!**/*.key", "!**/*.keystore",
    "!**/id_rsa", "!**/id_ed25519",
]


def _scope_relative_path(search_root: Path, path: Path) -> str | None:
    """Return POSIX relative path from search_root, or None if outside."""
    try:
        rel = path.resolve().relative_to(search_root.resolve())
    except ValueError:
        return None
    text = str(rel).replace("\\", "/")
    return "" if text == "." else text


def _build_search_exclusion_globs(
    search_root: Path,
    registry: RootScopeRegistry,
) -> list[str]:
    """Build ripgrep -g globs excluding paths where text_search is denied.

    Nested scopes with text_search=False are pre-excluded so ripgrep never
    opens denied files (OSS-SEC-001 pre-read boundary). Allowed nested scopes
    inside a denied parent are searched via disjoint sub-roots from
    ``_collect_search_paths``; deeper denied scopes inside allowed areas are
    excluded here so the most specific authority wins.
    """
    search_root = search_root.resolve()
    globs: list[str] = []

    denied: list[tuple[str, Path]] = []
    for entry in registry.list_scopes():
        scope_root = Path(entry["root"]).resolve()
        rel = _scope_relative_path(search_root, scope_root)
        if rel is None:
            continue
        effective = registry.resolve_scope(scope_root)
        if effective is None or effective.authority.text_search:
            continue
        denied.append((rel, scope_root))

    denied.sort(key=lambda item: (item[0].count("/"), len(item[0])))

    for rel_prefix, _denied_root in denied:
        if rel_prefix:
            globs.append(f"!{rel_prefix}/**")

    return globs


def _collect_search_paths(
    search_root: Path,
    registry: RootScopeRegistry,
) -> list[Path]:
    """Return supplementary directory sub-roots beyond ``search_root`` to scan.

    The primary search always runs from ``search_root`` with root-relative
    exclusion globs. Holes inside denied scopes and searchable siblings of
    denied directories (e.g. unreadable ``chmod 000`` enclaves) are scanned
    via these additional disjoint paths.
    """
    search_root = search_root.resolve()
    extra: list[Path] = []

    denied_roots: list[Path] = []
    for entry in registry.list_scopes():
        scope_root = Path(entry["root"]).resolve()
        if scope_root == search_root:
            continue
        try:
            scope_root.relative_to(search_root)
        except ValueError:
            continue
        effective = registry.resolve_scope(scope_root)
        if effective is None or effective.authority.text_search:
            continue
        denied_roots.append(scope_root)

    for entry in registry.list_scopes():
        if not entry["authority"]["text_search"]:
            continue
        hole_root = Path(entry["root"]).resolve()
        effective = registry.resolve_scope(hole_root)
        if effective is None or not effective.authority.text_search:
            continue
        for denied_root in denied_roots:
            try:
                hole_root.relative_to(denied_root)
            except ValueError:
                continue
            if hole_root != denied_root:
                extra.append(hole_root)
                break

    if not denied_roots:
        return extra

    try:
        children = sorted(search_root.iterdir())
    except (PermissionError, OSError):
        return extra

    denied_set = {dr.resolve() for dr in denied_roots}
    hole_set = {hr.resolve() for hr in extra}

    def under_denied(path: Path) -> bool:
        for denied_root in denied_set:
            if path == denied_root:
                return True
            try:
                path.relative_to(denied_root)
                return path.resolve() not in hole_set
            except ValueError:
                continue
        return False

    for child in children:
        if not child.is_dir() or child.is_symlink():
            continue
        if under_denied(child):
            continue
        effective = registry.resolve_scope(child)
        if effective is None or not effective.authority.text_search:
            continue
        extra.append(child.resolve())

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in extra:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            deduped.append(path.resolve())
    return deduped


def _is_sensitive_path(path: str) -> bool:
    """Check if any path component triggers the central secret firewall."""
    for component in Path(path).parts:
        if _is_denied_component(component):
            return True
    name = Path(path).name.lower()
    if name in _SENSITIVE_NAMES:
        return True
    if name.startswith(".env"):
        return True
    suffix = Path(path).suffix.lower()
    return suffix in _SENSITIVE_EXTENSIONS

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
})

_MAX_DEPTH = 4
_MAX_REPOS = 500


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

    @property
    def project_key(self) -> str:
        """Key for grouping into logical projects."""
        if self.remote_identity:
            return self.remote_identity
        if self.common_dir:
            return self.common_dir
        return self.path

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "remote_identity": self.remote_identity,
            "default_branch": self.default_branch,
            "head": self.head,
            "branch": self.branch,
            "is_worktree": self.is_worktree,
            "last_commit_ts": self.last_commit_ts,
            "markers": self.markers,
        }
        if self.clean is not None:
            d["clean"] = self.clean
            d["changed_count"] = self.changed_count
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "remote_identity": self.remote_identity,
            "instance_count": len(self.instances),
            "canonical_path": self.canonical_path,
            "languages": self.languages,
            "last_activity": self.last_activity,
            "status": self.status,
            "instances": [i.to_dict() for i in self.instances],
        }


class DiscoveryEngine:
    """Discovers projects within authorized RootScopes."""

    def __init__(self, scope_registry: RootScopeRegistry):
        self._scopes = scope_registry
        self._cache: dict[str, dict[str, Any]] | None = None
        self._cache_time: float = 0.0
        self._cache_ttl: float = 300.0  # 5 minutes

    def discover_scope(self, scope_id: str) -> dict[str, Any]:
        """Discover all projects within a scope."""
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

        repos = self._scan_for_repositories(root, target["authority"])
        projects = self._resolve_projects(repos)
        self._enrich_projects(projects, target["authority"])

        observed_at = datetime.now(timezone.utc).isoformat()
        return {
            "schema_version": "scope-discovery-v1",
            "observed_at": observed_at,
            "scope_id": scope_id,
            "scope_root": str(root),
            "total_repositories": len(repos),
            "total_projects": len(projects),
            "projects": [p.to_dict() for p in projects],
        }

    def scope_inventory(self, scope_id: str) -> dict[str, Any]:
        """Return cached or fresh inventory for a scope."""
        now = time.time()
        cache_hit = False
        if (self._cache and self._cache.get("scope_id") == scope_id
                and (now - self._cache_time) < self._cache_ttl):
            cache_hit = True
            result = dict(self._cache)
        else:
            result = self.discover_scope(scope_id)
            if "error" not in result:
                self._cache = result
                self._cache_time = now

        if "error" not in result:
            cache_age_ms = int((now - self._cache_time) * 1000) if cache_hit else 0
            result["freshness"] = {
                "served_at": datetime.now(timezone.utc).isoformat(),
                "cache_hit": cache_hit,
                "cache_age_ms": cache_age_ms,
                "expires_in_ms": int((self._cache_ttl - (now - self._cache_time)) * 1000),
                "source": "scope_inventory_cache" if cache_hit else "live_scan",
            }
            result["coverage"] = {
                "mode": "bounded",
                "max_depth": _MAX_DEPTH,
                "not_exhaustive": True,
                "max_repos": _MAX_REPOS,
            }

        return result

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
            return {"error": f"scope {scope_id} does not have search authority"}

        root = Path(target["root"])
        raw_paths: list[str] = []
        # Resolve from explicit installation locations before applying the hermetic
        # child environment. Missing rg must not masquerade as an empty search.
        candidates = [Path(p) for p in ("/usr/bin/rg", "/usr/local/bin/rg", "/opt/homebrew/bin/rg")]
        candidates.append(Path.home() / ".local/bin/rg")
        executable = next((p for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
        if executable is None:
            return {"error": "search unavailable: ripgrep executable missing", "scope_id": scope_id}
        try:
            cmd = [str(executable),
                   "--no-config",
                   "--fixed-strings",
                   "--ignore-case",
                   "-l",
                   "--no-messages",
                   "--max-count=1",
                   "--max-depth=5",
                   "-g", "!node_modules", "-g", "!.git",
                   "-g", "!.venv", "-g", "!__pycache__",
                   "-g", "!target", "-g", "!dist",
                   "-g", "!build", "-g", "!vendor"]
            for secret_glob in _RG_SECRET_GLOBS:
                cmd.extend(["-g", secret_glob])
            for deny_glob in _build_search_exclusion_globs(root, self._scopes):
                cmd.extend(["-g", deny_glob])
            extra_paths = _collect_search_paths(root, self._scopes)
            search_paths = [str(root)] + [str(path) for path in extra_paths]
            cmd.extend(["--", query, *search_paths])
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "LC_ALL": "C", "HOME": "/nonexistent"},
            )
            if proc.returncode not in (0, 1, 2):
                return {"error": "search failed: ripgrep execution error", "scope_id": scope_id}
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if _is_sensitive_path(line):
                    continue
                if not self._scopes.can_search(line):
                    continue
                raw_paths.append(line)
                if len(raw_paths) >= max_results:
                    break
        except (subprocess.TimeoutExpired, OSError):
            return {"error": "search unavailable: timeout or execution failure", "scope_id": scope_id}

        results: list[dict[str, Any]] = []
        for abs_path in raw_paths:
            try:
                rel = str(Path(abs_path).relative_to(root))
            except ValueError:
                continue
            entry: dict[str, Any] = {"path": rel, "scope_relative": True}
            project_id = self._attribute_path_to_project(root, abs_path, scope_id=scope_id)
            if project_id:
                entry["project_id"] = project_id
            results.append(entry)

        return {
            "scope_id": scope_id,
            "query": query,
            "total_matches": len(results),
            "results": results[:max_results],
        }

    def _attribute_path_to_project(self, scope_root: Path, abs_path: str, scope_id: str = "") -> str | None:
        """Resolve which discovered project a file path belongs to.

        Self-contained: if no cached inventory exists, performs a lightweight
        discovery to establish project attribution without requiring a prior
        scope_inventory() call.
        """
        if not self._cache and scope_id:
            self.scope_inventory(scope_id)
        if not self._cache:
            return None
        file_path = Path(abs_path)
        best_match: str | None = None
        best_depth = -1
        for proj in self._cache.get("projects", []):
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
        self, root: Path, authority: dict[str, bool]
    ) -> list[DiscoveredRepository]:
        """Layer 1: Deterministic filesystem scan for Git repos."""
        repos: list[DiscoveredRepository] = []
        self._walk_for_repos(root, repos, depth=0, git_observe=authority.get("git_observe", False))
        return repos[:_MAX_REPOS]

    def _walk_for_repos(
        self, path: Path, repos: list[DiscoveredRepository], depth: int,
        git_observe: bool = True,
    ) -> None:
        if depth > _MAX_DEPTH or len(repos) >= _MAX_REPOS:
            return

        effective_scope = self._scopes.resolve_scope(str(path))
        if effective_scope:
            git_observe = effective_scope.authority.git_observe
            if not effective_scope.authority.discover:
                return

        try:
            entries = sorted(path.iterdir())
        except (PermissionError, OSError):
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
            if git_observe:
                repo = self._read_repo_metadata(path)
            else:
                repo = DiscoveredRepository(path=str(path))
            repo.markers = markers
            repos.append(repo)
            return

        for entry in entries:
            if not entry.is_dir():
                continue
            name = entry.name
            if name.startswith(".") and name != ".git":
                continue
            if name in _NOISE_DIRS:
                continue
            if entry.is_symlink():
                continue
            self._walk_for_repos(entry, repos, depth + 1, git_observe=git_observe)

    def _read_repo_metadata(self, repo_path: Path) -> DiscoveredRepository:
        """Read basic git metadata using hermetic ReadOnlyGit."""
        repo = DiscoveredRepository(path=str(repo_path))

        try:
            git = ReadOnlyGit(str(repo_path))
            status = git.status()

            repo.head = status.get("head", "")
            repo.branch = status.get("branch", "")

            changed = [l for l in status.get("status", "").splitlines() if l.strip()]
            repo.clean = len(changed) == 0
            repo.changed_count = len(changed)

            try:
                remote_url = git._run(["remote", "get-url", "origin"], timeout=5).strip()
                repo.remote_identity = self._normalize_remote(remote_url)
            except WorkspaceError:
                pass

            try:
                common = git._run(["rev-parse", "--git-common-dir"], timeout=5).strip()
                if common != ".git":
                    repo.is_worktree = True
                    repo.common_dir = str((repo_path / common).resolve())
            except WorkspaceError:
                pass

            try:
                ts_str = git._run(["log", "-1", "--format=%ct"], timeout=5).strip()
                repo.last_commit_ts = float(ts_str)
            except (WorkspaceError, ValueError):
                pass

        except (WorkspaceError, OSError):
            pass

        return repo

    def _normalize_remote(self, url: str) -> str:
        """Normalize a git remote URL to org/repo identity."""
        url = url.strip()
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
