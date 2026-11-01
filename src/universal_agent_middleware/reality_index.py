"""Cross-process SQLite reality index for UAM v0.6.

Stores scope inventory snapshots, discovered instances, and inverted alias
lookup columns (project_id, directory basename, remote tail). Index entries
are invalidated when RootScope policy_generation changes.

Index provides candidate locations only — authorization remains live at read time.

Derived rows are also bound to the sensitive-name policy that produced them (``policy.SENSITIVE_POLICY_VERSION``):
what an older policy let into an inventory (a remote identity that still carried a credential, a project found
through a path the current policy refuses) must not be served again just because a new process opened the same
file. Rows written under another policy version, or before the binding existed, are never read; the next refresh
of the scope writes a fresh generation. Nothing is deleted or re-dated here: old rows age out through the normal
snapshot retention, and ``RootScope.policy_generation`` itself is untouched.
"""
from __future__ import annotations

import fcntl
import functools
import json
import random
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from .policy import SENSITIVE_POLICY_VERSION

SCHEMA_VERSION = 1
# The stamp appended to the stored policy_generation. A plain generation (written before this binding existed) or one
# with another version never ends with it, so it matches no read below. No schema change: an older release reading a
# stamped row sees a generation it does not recognise and refreshes, which is also what it does for any mismatch.
POLICY_BINDING = f"|{SENSITIVE_POLICY_VERSION}"
# Reads that take no policy_generation still only see rows carrying the current stamp.
_CURRENT_BINDING_ONLY = "substr(a.policy_generation, -length(?)) = ?"


def bind_policy(policy_generation: str) -> str:
    """The stored form of a RootScope ``policy_generation`` for the sensitive-name policy in force."""
    return f"{policy_generation}{POLICY_BINDING}"
BUSY_TIMEOUT_MS = 5000
DEFAULT_MAX_AGE_SEC = 300.0
# Only the active generation is ever read; older snapshot rows are a short rollback window, not a
# history. Without a bound the table grew by one full inventory per refresh (250 MB in four weeks).
SNAPSHOT_HISTORY_KEEP = 3
# Rows removed per write, so a table that is already far over the bound is trimmed over a few
# refreshes instead of in one long write transaction that blocks every reader.
SNAPSHOT_PRUNE_BATCH = 200
SQLITE_RETRY_ATTEMPTS = 8
SQLITE_RETRY_BASE_DELAY_SEC = 0.01

_T = TypeVar("_T")


def _index_enabled_scopes(scope_registry: Any | None) -> set[str]:
    """Return scope IDs where both discover and index authority are true."""
    if scope_registry is None:
        return set()
    result = set()
    for scope in scope_registry.list_scopes():
        authority = scope.get("authority", {})
        if authority.get("discover") and authority.get("index"):
            result.add(scope["scope_id"])
    return result

_SCHEMA_DROP_SCRIPT = """
DROP TABLE IF EXISTS instances;
DROP TABLE IF EXISTS scope_snapshots;
DROP TABLE IF EXISTS active_generation;
DROP TABLE IF EXISTS schema_meta;
"""


class IndexLockedError(Exception):
    """Raised when the index database is temporarily locked by another writer."""


class IncompatibleSchemaError(Exception):
    """Raised when the on-disk index schema is newer than this runtime supports."""

    def __init__(self, found_version: int, supported_version: int):
        self.found_version = found_version
        self.supported_version = supported_version
        super().__init__(
            f"index schema version {found_version} is newer than supported {supported_version}"
        )


def _is_lock_contention(exc: BaseException) -> bool:
    if isinstance(exc, sqlite3.OperationalError):
        message = str(exc).lower()
        return "locked" in message or "busy" in message
    return False


def _retry_delay(attempt: int) -> float:
    base = SQLITE_RETRY_BASE_DELAY_SEC * (2**attempt)
    return min(base + random.uniform(0, SQLITE_RETRY_BASE_DELAY_SEC), 1.0)


def _retry_sqlite(
    fn: Callable[[], _T],
    *,
    max_attempts: int = SQLITE_RETRY_ATTEMPTS,
) -> _T:
    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if not _is_lock_contention(exc):
                raise
            last_exc = exc
            if attempt >= max_attempts - 1:
                raise IndexLockedError(str(exc)) from exc
            time.sleep(_retry_delay(attempt))
    raise IndexLockedError(str(last_exc or "database is locked"))


@contextmanager
def _cross_process_lock(
    lock_path: Path,
    *,
    exclusive: bool = False,
    blocking: bool = True,
) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = lock_path.open("a+b")
    try:
        flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            flags |= fcntl.LOCK_NB
        fcntl.flock(fd, flags)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()


def _is_corruption(exc: BaseException) -> bool:
    if isinstance(exc, sqlite3.DatabaseError) and not isinstance(exc, sqlite3.OperationalError):
        return True
    if isinstance(exc, sqlite3.OperationalError):
        message = str(exc).lower()
        return any(token in message for token in ("malformed", "not a database", "corrupt"))
    return False


def _miss_when_unusable(
    miss: Callable[[], _T],
) -> Callable[[Callable[..., _T]], Callable[..., _T]]:
    """Make an index read answer "nothing indexed" when the index cannot be used.

    Every read is a shortcut over a live scan or a registry lookup. An index this release must not
    serve (its schema is newer than supported) or cannot read within the retry budget (a writer holds
    the lock) is therefore a miss: not an exception that fails the caller's whole operation, and not
    the rows of a file whose contents this release cannot vouch for. Corruption keeps its own handling
    inside each read. ``miss`` builds the empty answer so callers never share a mutable one.
    """

    def decorate(read: Callable[..., _T]) -> Callable[..., _T]:
        @functools.wraps(read)
        def guarded(self: RealityIndex, *args: Any, **kwargs: Any) -> _T:
            if self._schema_incompatible:
                return miss()
            try:
                return read(self, *args, **kwargs)
            except (IncompatibleSchemaError, IndexLockedError):
                return miss()

        return guarded

    return decorate


@dataclass(frozen=True)
class IndexedInstance:
    instance_id: str
    scope_id: str
    workspace_id: str
    rel_path: str
    project_id: str
    remote_identity: str
    remote_tail: str
    basename: str
    is_worktree: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "scope_id": self.scope_id,
            "workspace_id": self.workspace_id,
            "rel_path": self.rel_path,
            "project_id": self.project_id,
            "remote_identity": self.remote_identity,
            "remote_tail": self.remote_tail,
            "basename": self.basename,
            "is_worktree": self.is_worktree,
        }


class RealityIndex:
    """Persistent cross-process index for scope inventories and alias resolution."""

    def __init__(self, state_dir: str | Path):
        self._state_dir = Path(state_dir).expanduser().resolve(strict=False)
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._state_dir / "reality_index.db"
        self._process_lock_path = self._state_dir / "reality_index.lock"
        self._lock = threading.Lock()
        self._refresh_inflight: dict[str, threading.Thread] = {}
        self._refresh_lock_fds: dict[str, Any] = {}
        self._corrupt = False
        self._schema_incompatible = False
        self._incompatible_schema_version: int | None = None
        self._init_locked = False
        self._ensure_schema()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def is_corrupt(self) -> bool:
        return self._corrupt

    @property
    def schema_incompatible(self) -> bool:
        return self._schema_incompatible

    def _handle_db_error(self, exc: BaseException) -> None:
        if _is_lock_contention(exc):
            raise IndexLockedError(str(exc)) from exc
        if _is_corruption(exc):
            self._mark_corrupt()
            return
        raise exc

    def _connect(self, *, write: bool = False) -> sqlite3.Connection:
        def _open() -> sqlite3.Connection:
            conn = sqlite3.connect(
                self._db_path,
                timeout=BUSY_TIMEOUT_MS / 1000.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA synchronous=NORMAL")
            if write:
                conn.execute("PRAGMA journal_mode=WAL")
            return conn

        return _retry_sqlite(_open)

    def _read_schema_version(self, conn: sqlite3.Connection) -> int | None:
        try:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError:
            return None
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return None

    def _validate_schema_version(self, conn: sqlite3.Connection) -> None:
        version = self._read_schema_version(conn)
        if version is None:
            return
        if version > SCHEMA_VERSION:
            self._schema_incompatible = True
            self._incompatible_schema_version = version
            raise IncompatibleSchemaError(version, SCHEMA_VERSION)

    def _read_connection(self) -> sqlite3.Connection:
        """Open a read connection to an index this release may still serve.

        A newer release can migrate the file after this instance opened it, so the schema is checked
        on every read and not only at startup; ``_schema_incompatible`` then keeps the later reads
        away from the file without reopening it.
        """
        conn = self._connect()
        try:
            self._validate_schema_version(conn)
        except IncompatibleSchemaError:
            conn.close()
            raise
        return conn

    def _install_schema(self, conn: sqlite3.Connection) -> None:
        if self._db_path.exists() and self._db_path.stat().st_size > 0:
            self._validate_schema_version(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scope_snapshots (
                scope_id TEXT NOT NULL,
                generation_id TEXT NOT NULL,
                policy_generation TEXT NOT NULL,
                observed_at REAL NOT NULL,
                git_enriched INTEGER NOT NULL DEFAULT 0,
                snapshot_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'complete',
                PRIMARY KEY (scope_id, generation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_active
                ON scope_snapshots(scope_id, policy_generation, observed_at DESC);
            CREATE TABLE IF NOT EXISTS instances (
                instance_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                generation_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                project_id TEXT NOT NULL,
                remote_identity TEXT NOT NULL DEFAULT '',
                remote_tail TEXT NOT NULL DEFAULT '',
                basename TEXT NOT NULL DEFAULT '',
                is_worktree INTEGER NOT NULL DEFAULT 0,
                tombstone INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_instances_workspace
                ON instances(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_instances_project
                ON instances(scope_id, project_id);
            CREATE INDEX IF NOT EXISTS idx_instances_basename
                ON instances(scope_id, basename);
            CREATE INDEX IF NOT EXISTS idx_instances_remote_tail
                ON instances(scope_id, remote_tail);
            CREATE TABLE IF NOT EXISTS active_generation (
                scope_id TEXT PRIMARY KEY,
                generation_id TEXT NOT NULL,
                policy_generation TEXT NOT NULL,
                activated_at REAL NOT NULL
            );
            """
        )
        existing = self._read_schema_version(conn)
        if existing is None:
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )

    def _ensure_schema(self) -> None:
        if self._corrupt or self._schema_incompatible:
            return

        def _apply_schema() -> None:
            with _cross_process_lock(self._process_lock_path, exclusive=True):
                with self._connect(write=True) as conn:
                    self._install_schema(conn)
                    conn.commit()

        try:
            _retry_sqlite(_apply_schema)
        except IncompatibleSchemaError as exc:
            self._schema_incompatible = True
            self._incompatible_schema_version = getattr(exc, "found_version", None)
        except IndexLockedError:
            self._init_locked = True
        except sqlite3.DatabaseError as exc:
            self._handle_db_error(exc)

    def _mark_corrupt(self) -> None:
        self._corrupt = True

    def check_integrity(self) -> dict[str, Any]:
        """Run SQLite integrity_check; mark index corrupt on failure."""
        if self._schema_incompatible:
            return {
                "status": "INCOMPATIBLE",
                "valid": False,
                "reason": (
                    f"schema version {self._incompatible_schema_version} "
                    f"newer than supported {SCHEMA_VERSION}"
                ),
                "schema_version": self._incompatible_schema_version,
            }
        if self._init_locked:
            return {
                "status": "LOCKED",
                "valid": True,
                "reason": "schema initialization deferred — database locked by another process",
            }
        if not self._db_path.exists():
            return {"status": "MISSING", "valid": False, "reason": "index database not found"}
        if self._corrupt:
            return {"status": "CORRUPT", "valid": False, "reason": "index marked corrupt"}
        try:
            with self._connect() as conn:
                self._validate_schema_version(conn)
                row = conn.execute("PRAGMA integrity_check").fetchone()
                ok = row is not None and row[0] == "ok"
                if not ok:
                    self._mark_corrupt()
                    return {
                        "status": "CORRUPT",
                        "valid": False,
                        "reason": str(row[0]) if row else "integrity_check failed",
                    }
                version = self._read_schema_version(conn)
                return {
                    "status": "OK",
                    "valid": True,
                    "schema_version": version,
                    "db_path": str(self._db_path),
                }
        except IncompatibleSchemaError as exc:
            return {
                "status": "INCOMPATIBLE",
                "valid": False,
                "reason": str(exc),
                "schema_version": exc.found_version,
            }
        except IndexLockedError as exc:
            return {"status": "LOCKED", "valid": False, "reason": str(exc)}
        except sqlite3.DatabaseError as exc:
            if _is_lock_contention(exc):
                return {"status": "LOCKED", "valid": False, "reason": str(exc)}
            self._mark_corrupt()
            return {"status": "CORRUPT", "valid": False, "reason": str(exc)}

    def rebuild(self) -> None:
        """Reset corrupt database in-place without unlinking active files."""
        with self._lock:
            with _cross_process_lock(self._process_lock_path, exclusive=True):
                self._corrupt = False
                self._schema_incompatible = False
                if self._db_path.exists():
                    try:
                        with self._connect(write=True) as conn:
                            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                            conn.executescript(_SCHEMA_DROP_SCRIPT)
                            conn.commit()
                    except sqlite3.DatabaseError:
                        stamp = int(time.time())
                        for path in (
                            self._db_path,
                            self._db_path.with_suffix(".db-wal"),
                            self._db_path.with_suffix(".db-shm"),
                        ):
                            if path.exists():
                                path.rename(path.with_name(f"{path.name}.bak-{stamp}"))
                with self._connect(write=True) as conn:
                    self._install_schema(conn)
                    conn.commit()

    @_miss_when_unusable(lambda: None)
    def get_active_snapshot(
        self,
        scope_id: str,
        policy_generation: str,
        *,
        max_age_sec: float = DEFAULT_MAX_AGE_SEC,
        allow_stale: bool = False,
    ) -> dict[str, Any] | None:
        """Return cached inventory snapshot if fresh and policy matches."""
        if self._corrupt or not self._db_path.exists():
            return None
        try:
            with self._read_connection() as conn:
                active = conn.execute(
                    """
                    SELECT generation_id, policy_generation, activated_at
                    FROM active_generation WHERE scope_id = ?
                    """,
                    (scope_id,),
                ).fetchone()
                if not active or active["policy_generation"] != bind_policy(policy_generation):
                    return None

                snap = conn.execute(
                    """
                    SELECT snapshot_json, observed_at, git_enriched, status, generation_id
                    FROM scope_snapshots
                    WHERE scope_id = ? AND generation_id = ?
                    """,
                    (scope_id, active["generation_id"]),
                ).fetchone()
                if not snap:
                    return None

                age = time.time() - snap["observed_at"]
                if age > max_age_sec and not allow_stale:
                    return None

                result = json.loads(snap["snapshot_json"])
                result["index_generation"] = snap["generation_id"]
                result["freshness"] = {
                    "source": "reality_index",
                    "index_hit": True,
                    "cache_age_ms": int(age * 1000),
                    "policy_generation": policy_generation,
                    "git_enriched": bool(snap["git_enriched"]),
                    "stale": age > max_age_sec,
                    "status": snap["status"],
                }
                return result
        except (sqlite3.DatabaseError, json.JSONDecodeError) as exc:
            if isinstance(exc, sqlite3.DatabaseError) and _is_lock_contention(exc):
                return None
            if isinstance(exc, sqlite3.DatabaseError):
                self._handle_db_error(exc)
            else:
                self._mark_corrupt()
            return None

    def write_snapshot(
        self,
        scope_id: str,
        inventory: dict[str, Any],
        policy_generation: str,
        *,
        git_enriched: bool = False,
        status: str = "complete",
    ) -> str:
        """Atomically persist a scope inventory snapshot and alias index.

        Quality monotonicity: a non-enriched snapshot will not replace an
        enriched snapshot for the same scope/policy_generation. The write
        is silently skipped and the existing generation_id is returned.
        """
        if self._corrupt:
            self.rebuild()
        if self._schema_incompatible:
            raise IncompatibleSchemaError(
                self._incompatible_schema_version or -1,
                SCHEMA_VERSION,
            )

        if not git_enriched:
            existing_enriched = self._is_active_enriched(scope_id, policy_generation)
            if existing_enriched is not None:
                return existing_enriched

        generation_id = uuid.uuid4().hex
        observed_at = time.time()
        snapshot_json = json.dumps(inventory, separators=(",", ":"), ensure_ascii=False)
        stored_policy = bind_policy(policy_generation)

        def _write() -> None:
            with self._connect(write=True) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO scope_snapshots
                    (scope_id, generation_id, policy_generation, observed_at,
                     git_enriched, snapshot_json, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scope_id,
                        generation_id,
                        stored_policy,
                        observed_at,
                        int(git_enriched),
                        snapshot_json,
                        status,
                    ),
                )
                conn.execute(
                    "DELETE FROM instances WHERE scope_id = ? AND generation_id != ?",
                    (scope_id, generation_id),
                )
                for project in inventory.get("projects", []):
                    project_id = project.get("project_id", "")
                    remote = project.get("remote_identity", "")
                    remote_tail = remote.rsplit("/", 1)[-1].lower() if remote else ""
                    for inst in project.get("instances", []):
                        rel_path = inst.get("path", "")
                        if scope_id and inventory.get("scope_root"):
                            try:
                                rel_path = str(
                                    Path(inst.get("path", "")).resolve().relative_to(
                                        Path(inventory["scope_root"]).resolve()
                                    )
                                )
                            except ValueError:
                                pass
                        workspace_id = inst.get("workspace_id", "")
                        if not workspace_id and rel_path:
                            workspace_id = f"derived:{scope_id}:{rel_path}"
                        basename = Path(rel_path or inst.get("path", "")).name.lower()
                        instance_id = uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"{scope_id}:{workspace_id}",
                        ).hex
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO instances
                            (instance_id, scope_id, generation_id, workspace_id, rel_path,
                             project_id, remote_identity, remote_tail, basename, is_worktree)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                instance_id,
                                scope_id,
                                generation_id,
                                workspace_id,
                                rel_path,
                                project_id,
                                remote,
                                remote_tail,
                                basename,
                                int(inst.get("is_worktree", False)),
                            ),
                        )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO active_generation
                    (scope_id, generation_id, policy_generation, activated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (scope_id, generation_id, stored_policy, observed_at),
                )
                conn.execute(
                    "DELETE FROM instances WHERE scope_id = ? AND generation_id != ?",
                    (scope_id, generation_id),
                )
                conn.execute(
                    """
                    DELETE FROM scope_snapshots WHERE rowid IN (
                        SELECT rowid FROM scope_snapshots
                        WHERE scope_id = ? AND generation_id != ?
                          AND generation_id NOT IN (
                              SELECT generation_id FROM scope_snapshots
                              WHERE scope_id = ? AND generation_id != ?
                              ORDER BY observed_at DESC LIMIT ?)
                        ORDER BY observed_at ASC LIMIT ?)
                    """,
                    (scope_id, generation_id, scope_id, generation_id,
                     SNAPSHOT_HISTORY_KEEP - 1, SNAPSHOT_PRUNE_BATCH),
                )
                conn.commit()

        with self._lock:
            try:
                _retry_sqlite(_write)
            except IndexLockedError:
                raise
            except sqlite3.DatabaseError as exc:
                if _is_lock_contention(exc):
                    raise IndexLockedError(str(exc)) from exc
                self._handle_db_error(exc)
                raise
        return generation_id

    @_miss_when_unusable(list)
    def lookup_by_alias(
        self,
        alias: str,
        *,
        scope_id: str | None = None,
        policy_generation: str | None = None,
    ) -> list[IndexedInstance]:
        """Resolve bare names via inverted alias columns."""
        if self._corrupt or not self._db_path.exists():
            return []

        normalized = alias.lower().strip()
        try:
            with self._read_connection() as conn:
                sql = """
                    SELECT i.* FROM instances i
                    INNER JOIN active_generation a
                        ON i.scope_id = a.scope_id AND i.generation_id = a.generation_id
                    WHERE i.tombstone = 0
                      AND (
                        i.basename = ? OR lower(i.project_id) = ? OR i.remote_tail = ?
                      )
                """
                params: list[Any] = [normalized, normalized, normalized]
                sql += f" AND {_CURRENT_BINDING_ONLY}"
                params.extend([POLICY_BINDING, POLICY_BINDING])
                if scope_id:
                    sql += " AND i.scope_id = ?"
                    params.append(scope_id)
                if policy_generation:
                    sql += " AND a.policy_generation = ?"
                    params.append(bind_policy(policy_generation))
                rows = conn.execute(sql, params).fetchall()
                return [self._row_to_instance(r) for r in rows]
        except sqlite3.DatabaseError as exc:
            if _is_lock_contention(exc):
                return []
            self._handle_db_error(exc)
            return []

    @staticmethod
    def _row_to_instance(row: sqlite3.Row) -> IndexedInstance:
        return IndexedInstance(
            instance_id=row["instance_id"],
            scope_id=row["scope_id"],
            workspace_id=row["workspace_id"],
            rel_path=row["rel_path"],
            project_id=row["project_id"],
            remote_identity=row["remote_identity"],
            remote_tail=row["remote_tail"],
            basename=row["basename"],
            is_worktree=bool(row["is_worktree"]),
        )

    @_miss_when_unusable(list)
    def list_projects(
        self,
        *,
        scope_id: str | None = None,
        policy_generation: str | None = None,
    ) -> list[dict[str, Any]]:
        """List distinct projects from the active index generation."""
        if self._corrupt or not self._db_path.exists():
            return []
        try:
            with self._read_connection() as conn:
                if scope_id and policy_generation:
                    rows = conn.execute(
                        """
                        SELECT i.project_id, i.scope_id, COUNT(*) AS instance_count
                        FROM instances i
                        INNER JOIN active_generation a
                            ON i.scope_id = a.scope_id
                            AND i.generation_id = a.generation_id
                            AND a.policy_generation = ?
                        WHERE i.scope_id = ? AND i.tombstone = 0
                        GROUP BY i.project_id, i.scope_id
                        """,
                        (bind_policy(policy_generation), scope_id),
                    ).fetchall()
                elif scope_id:
                    rows = conn.execute(
                        f"""
                        SELECT i.project_id, i.scope_id, COUNT(*) AS instance_count
                        FROM instances i
                        INNER JOIN active_generation a
                            ON i.scope_id = a.scope_id AND i.generation_id = a.generation_id
                            AND {_CURRENT_BINDING_ONLY}
                        WHERE i.scope_id = ? AND i.tombstone = 0
                        GROUP BY i.project_id, i.scope_id
                        """,
                        (POLICY_BINDING, POLICY_BINDING, scope_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        f"""
                        SELECT i.project_id, i.scope_id, COUNT(*) AS instance_count
                        FROM instances i
                        INNER JOIN active_generation a
                            ON i.scope_id = a.scope_id AND i.generation_id = a.generation_id
                            AND {_CURRENT_BINDING_ONLY}
                        WHERE i.tombstone = 0
                        GROUP BY i.project_id, i.scope_id
                        """,
                        (POLICY_BINDING, POLICY_BINDING),
                    ).fetchall()
                return [
                    {
                        "project_id": r["project_id"],
                        "scope_id": r["scope_id"],
                        "instance_count": r["instance_count"],
                        "source": "reality_index",
                    }
                    for r in rows
                ]
        except sqlite3.DatabaseError as exc:
            if _is_lock_contention(exc):
                return []
            self._handle_db_error(exc)
            return []

    @_miss_when_unusable(list)
    def get_project_instances(
        self,
        project_id: str,
        *,
        policy_generation: str | None = None,
    ) -> list[IndexedInstance]:
        """Return indexed instances for a project_id across active generations."""
        if self._corrupt or not self._db_path.exists():
            return []
        normalized = project_id.lower()
        try:
            with self._read_connection() as conn:
                if policy_generation:
                    rows = conn.execute(
                        """
                        SELECT i.* FROM instances i
                        INNER JOIN active_generation a
                            ON i.scope_id = a.scope_id
                            AND i.generation_id = a.generation_id
                            AND a.policy_generation = ?
                        WHERE i.tombstone = 0
                          AND (lower(i.project_id) = ? OR i.basename = ?)
                        """,
                        (bind_policy(policy_generation), normalized, normalized),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        f"""
                        SELECT i.* FROM instances i
                        INNER JOIN active_generation a
                            ON i.scope_id = a.scope_id AND i.generation_id = a.generation_id
                            AND {_CURRENT_BINDING_ONLY}
                        WHERE i.tombstone = 0
                          AND (lower(i.project_id) = ? OR i.basename = ?)
                        """,
                        (POLICY_BINDING, POLICY_BINDING, normalized, normalized),
                    ).fetchall()
                return [self._row_to_instance(r) for r in rows]
        except sqlite3.DatabaseError as exc:
            if _is_lock_contention(exc):
                return []
            self._handle_db_error(exc)
            return []

    def health_report(self, scope_registry: Any | None = None) -> dict[str, Any]:
        """Health summary for doctor checks.

        Scopes are classified into three groups:
        - required: currently enabled (discover=True, index=True)
        - orphaned: present in DB but no longer in active scope config
        - informational: present in DB with stale policy (cleanup candidate)
        Only required scopes determine readiness; orphaned rows are informational.
        """
        integrity = self.check_integrity()
        report: dict[str, Any] = {
            "status": "PASS" if integrity.get("valid") else "FAIL",
            "integrity": integrity,
            "schema_version": SCHEMA_VERSION,
            "db_path": str(self._db_path),
            "scopes": [],
        }
        if integrity.get("status") == "INCOMPATIBLE":
            report["status"] = "FAIL"
            report["reason"] = integrity.get("reason", "incompatible schema")
            report["failure_class"] = "reality_index_schema_incompatible"
            return report
        if integrity.get("status") == "LOCKED":
            report["status"] = "DEGRADED"
            report["reason"] = integrity.get("reason", "index database locked")
            report["failure_class"] = "reality_index_locked"
            return report
        if not integrity.get("valid"):
            report["reason"] = integrity.get("reason", "index unhealthy")
            report["failure_class"] = "reality_index_integrity_failure"
            return report

        try:
            with self._connect() as conn:
                instance_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM instances i
                    INNER JOIN active_generation a
                        ON i.scope_id = a.scope_id AND i.generation_id = a.generation_id
                    WHERE i.tombstone = 0
                    """
                ).fetchone()[0]
                snapshot_count = conn.execute(
                    "SELECT COUNT(*) FROM active_generation"
                ).fetchone()[0]
                report["record_counts"] = {
                    "active_instances": instance_count,
                    "active_scopes": snapshot_count,
                }
                rows = conn.execute(
                    """
                    SELECT a.scope_id, a.policy_generation, a.activated_at,
                           s.git_enriched, s.status, s.observed_at,
                           (SELECT COUNT(*) FROM instances i
                            WHERE i.scope_id = a.scope_id
                              AND i.generation_id = a.generation_id
                              AND i.tombstone = 0) AS instance_count
                    FROM active_generation a
                    LEFT JOIN scope_snapshots s
                        ON a.scope_id = s.scope_id AND a.generation_id = s.generation_id
                    """
                ).fetchall()
                indexed_scope_ids = {r["scope_id"] for r in rows}
                enabled_scopes = _index_enabled_scopes(scope_registry)
                now = time.time()
                for row in rows:
                    sid = row["scope_id"]
                    is_required = sid in enabled_scopes
                    age_sec = now - row["observed_at"] if row["observed_at"] else None
                    stale = age_sec is not None and age_sec > DEFAULT_MAX_AGE_SEC
                    stored = row["policy_generation"]
                    # Rows written under another sensitive-name policy (or before the binding) are never read, so
                    # they count as a mismatch: the scope has to be re-indexed.
                    bound_to_current = stored.endswith(POLICY_BINDING)
                    policy_match = bound_to_current
                    if scope_registry is not None:
                        policy_match = stored == bind_policy(scope_registry.policy_generation)
                    entry: dict[str, Any] = {
                        "scope_id": sid,
                        "policy_generation": stored[: -len(POLICY_BINDING)] if bound_to_current else stored,
                        "sensitive_policy_bound": bound_to_current,
                        "policy_match": policy_match,
                        "age_sec": round(age_sec, 1) if age_sec is not None else None,
                        "stale": stale,
                        "git_enriched": bool(row["git_enriched"]),
                        "status": row["status"],
                        "instance_count": row["instance_count"],
                        "obligation": "required" if is_required else "orphaned",
                    }
                    report["scopes"].append(entry)
                missing_scopes = enabled_scopes - indexed_scope_ids
                for sid in sorted(missing_scopes):
                    report["scopes"].append({
                        "scope_id": sid,
                        "status": "missing",
                        "stale": True,
                        "obligation": "required",
                        "reason": "enabled scope has no index snapshot",
                    })
                required = [s for s in report["scopes"] if s.get("obligation") == "required"]
                if missing_scopes:
                    report["status"] = "DEGRADED"
                    report["reason"] = f"missing index for enabled scopes: {sorted(missing_scopes)}"
                    report["failure_class"] = "reality_index_missing"
                elif required and any(not s.get("policy_match", True) for s in required):
                    report["status"] = "DEGRADED"
                    report["reason"] = "policy_generation mismatch — reindex required"
                    report["failure_class"] = "reality_index_policy_mismatch"
                elif required and any(s.get("stale") for s in required):
                    report["status"] = "DEGRADED"
                    stale_ids = [s["scope_id"] for s in required if s.get("stale")]
                    report["reason"] = f"stale indexed scopes: {stale_ids}"
                    report["failure_class"] = "reality_index_stale"
                elif required and any(not s.get("git_enriched") for s in required):
                    non_enriched = [s["scope_id"] for s in required if not s.get("git_enriched")]
                    report["status"] = "DEGRADED"
                    report["reason"] = f"required scopes without git enrichment: {non_enriched}"
                    report["failure_class"] = "reality_index_not_enriched"
        except sqlite3.DatabaseError as exc:
            if _is_lock_contention(exc):
                report["status"] = "DEGRADED"
                report["failure_class"] = "reality_index_locked"
            else:
                report["status"] = "FAIL"
                report["failure_class"] = "reality_index_integrity_failure"
            report["reason"] = str(exc)
        return report

    def _release_refresh_lock(self, scope_id: str) -> None:
        fd = self._refresh_lock_fds.pop(scope_id, None)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                fd.close()

    def _is_active_enriched(
        self, scope_id: str, policy_generation: str
    ) -> str | None:
        """Return existing generation_id if active snapshot is enriched, else None."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT a.generation_id, s.git_enriched
                    FROM active_generation a
                    JOIN scope_snapshots s
                        ON a.scope_id = s.scope_id AND a.generation_id = s.generation_id
                    WHERE a.scope_id = ? AND a.policy_generation = ?
                    """,
                    (scope_id, bind_policy(policy_generation)),
                ).fetchone()
                if row and row["git_enriched"]:
                    return row["generation_id"]
        except (sqlite3.DatabaseError, Exception):
            pass
        return None

    def _release_refresh_lock(self, scope_id: str) -> None:
        fd = self._refresh_lock_fds.pop(scope_id, None)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                fd.close()

    def schedule_background_refresh(
        self,
        scope_id: str,
        refresh_fn: Callable[[], None],
    ) -> bool:
        """Single-flight background refresh with cross-process deduplication."""
        refresh_lock = self._state_dir / f"refresh-{scope_id}.lock"
        refresh_lock.parent.mkdir(parents=True, exist_ok=True)
        fd = refresh_lock.open("a+b")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fd.close()
            return False

        with self._lock:
            existing = self._refresh_inflight.get(scope_id)
            if existing is not None and existing.is_alive():
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
                return False
            self._refresh_lock_fds[scope_id] = fd

            def _run() -> None:
                try:
                    refresh_fn()
                finally:
                    with self._lock:
                        self._refresh_inflight.pop(scope_id, None)
                        self._release_refresh_lock(scope_id)

            thread = threading.Thread(
                target=_run,
                name=f"uam-index-refresh-{scope_id}",
                daemon=True,
            )
            self._refresh_inflight[scope_id] = thread
            thread.start()
            return True
