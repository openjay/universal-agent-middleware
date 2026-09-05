from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO
from .errors import UAMError


class AuditIntegrityError(UAMError):
    """Refuse writes when evidence is damaged or needs explicit migration."""


class HashChainedAuditLog:
    """Durable JSONL chain for cooperating writers on a local POSIX filesystem.

    Legacy chains remain readable but cannot be appended by v2. A process verifies
    existing history before its first append, then reads only the tail under flock.
    Full verify remains necessary for detecting later historical tampering. flock
    is advisory: old writers must be stopped before adopting v2; no NFS guarantee.
    """

    def __init__(self, path: str | Path, *, runtime_release: str | None = None,
                 freeze_file: str | Path | None = None):
        self.path = Path(path)
        self.runtime_release = runtime_release or "development-unverified"
        self.freeze_file = Path(freeze_file) if freeze_file else None
        self._lock = threading.Lock()
        self._identity: tuple[int, int] | None = None
        self._size = 0
        self._writer_pid = os.getpid()
        self._writer_instance = str(uuid.uuid4())

    @staticmethod
    def _canonical(obj: dict[str, Any]) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    @classmethod
    def _verify_stream(cls, fh: BinaryIO) -> dict[str, Any]:
        previous, count, chain_id, version = "GENESIS", 0, None, None
        fh.seek(0)

        def result(failure: str | None = None, line: int | None = None) -> dict[str, Any]:
            r = {"valid": failure is None, "records": count, "valid_records": count,
                 "head_hash": previous, "first_invalid_line": line,
                 "failure_type": failure, "chain_id": chain_id, "schema_version": version}
            if failure:
                r["error"] = f"{failure.lower().replace('_', ' ')} at line {line}"
            return r

        for line_number, line in enumerate(fh, 1):
            if not line.endswith(b"\n"):
                return result("TRUNCATED_RECORD", line_number)
            try:
                stored = json.loads(line)
                if not isinstance(stored, dict):
                    return result("MALFORMED_JSON", line_number)
            except (ValueError, UnicodeError):
                return result("MALFORMED_JSON", line_number)
            claimed = stored.pop("record_hash", None)
            if not isinstance(claimed, str) or len(claimed) != 64:
                return result("MISSING_HASH", line_number)
            if stored.get("previous_hash") != previous:
                return result("BROKEN_PREVIOUS_HASH", line_number)
            try:
                actual = hashlib.sha256(cls._canonical(stored)).hexdigest()
            except (ValueError, TypeError):
                return result("MALFORMED_JSON", line_number)
            if actual != claimed:
                return result("HASH_MISMATCH", line_number)
            current_version = stored.get("schema_version", 1)
            if current_version not in (1, 2) or (count and current_version != version):
                return result("SCHEMA_MISMATCH", line_number)
            if current_version == 2:
                if type(stored.get("sequence")) is not int or stored["sequence"] != count + 1:
                    return result("SEQUENCE_GAP", line_number)
                if not isinstance(stored.get("chain_id"), str) or not stored["chain_id"]:
                    return result("CHAIN_ID_MISMATCH", line_number)
                if count and stored["chain_id"] != chain_id:
                    return result("CHAIN_ID_MISMATCH", line_number)
                chain_id = stored["chain_id"]
            version, previous, count = current_version, claimed, count + 1
        return result()

    @staticmethod
    def _tail(fh: BinaryIO) -> dict[str, Any] | None:
        size = fh.seek(0, os.SEEK_END)
        if not size:
            return None
        fh.seek(size - 1)
        if fh.read(1) != b"\n":
            raise AuditIntegrityError("TRUNCATED_RECORD: preserve evidence; refusing append")
        end, chunks = size - 1, []
        while end:
            start = max(0, end - 8192)
            fh.seek(start)
            chunk = fh.read(end - start)
            index = chunk.rfind(b"\n")
            chunks.insert(0, chunk[index + 1:] if index >= 0 else chunk)
            if index >= 0:
                break
            end = start
        try:
            record = json.loads(b"".join(chunks))
            claimed = record["record_hash"]
            body = {k: v for k, v in record.items() if k != "record_hash"}
            if hashlib.sha256(HashChainedAuditLog._canonical(body)).hexdigest() != claimed:
                raise ValueError("tail hash mismatch")
            if record.get("schema_version") != 2:
                raise AuditIntegrityError("MIGRATION_REQUIRED: legacy chain is read-only")
            return record
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditIntegrityError("INVALID_TAIL: preserve evidence; refusing append") from exc

    def append(self, *, action: str, workspace_id: str | None, outcome: str,
               details: dict[str, Any] | None = None, session_id: str | None = None,
               request_id: str | None = None) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            # Open a separate file description per call so distinct instances also
            # serialize within one process. Never replace/truncate this inode.
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "r+b", buffering=0) as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                if self.freeze_file and self.freeze_file.exists():
                    raise AuditIntegrityError("FROZEN: operator resolution required")
                stat = os.fstat(fd)
                identity = (stat.st_dev, stat.st_ino)
                if self._identity is not None and (identity != self._identity or stat.st_size < self._size):
                    raise AuditIntegrityError("LEDGER_REPLACED_OR_TRUNCATED")
                if self._identity is None:
                    verification = self._verify_stream(fh)
                    if not verification["valid"]:
                        raise AuditIntegrityError(verification["error"])
                    if verification["records"] and verification["schema_version"] != 2:
                        raise AuditIntegrityError("MIGRATION_REQUIRED: legacy chain is read-only")
                tail = self._tail(fh)
                if self._writer_pid != os.getpid():
                    self._writer_pid, self._writer_instance = os.getpid(), str(uuid.uuid4())
                record = {
                    "schema_version": 2,
                    "chain_id": tail["chain_id"] if tail else str(uuid.uuid4()),
                    "sequence": tail["sequence"] + 1 if tail else 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "writer_pid": os.getpid(), "writer_instance_id": self._writer_instance,
                    "session_id": session_id or self._writer_instance,
                    "request_id": request_id or str(uuid.uuid4()),
                    "runtime_release": self.runtime_release,
                    "action": action, "workspace_id": workspace_id, "outcome": outcome,
                    "details": details or {},
                    "previous_hash": tail["record_hash"] if tail else "GENESIS",
                }
                stored = {**record, "record_hash": hashlib.sha256(self._canonical(record)).hexdigest()}
                data = self._canonical(stored) + b"\n"
                if os.write(fd, data) != len(data):
                    # Never hide a torn write by retrying, truncating or repairing.
                    raise AuditIntegrityError("SHORT_WRITE: preserve partial record")
                os.fsync(fd)
                if tail is None:
                    directory = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                self._identity, self._size = identity, os.fstat(fd).st_size
                return stored

    def verify(self) -> dict[str, Any]:
        try:
            with self.path.open("rb") as fh:
                fcntl.flock(fh, fcntl.LOCK_SH)
                return self._verify_stream(fh)
        except FileNotFoundError:
            return {"valid": True, "records": 0, "valid_records": 0, "head_hash": "GENESIS",
                    "first_invalid_line": None, "failure_type": None,
                    "chain_id": None, "schema_version": None}


def migrate_snapshot(source: Path, destination: Path, *, expected_sha256: str,
                     incident_receipt_id: str) -> dict[str, Any]:
    """Explicit offline migration from a preserved snapshot, never in-place repair."""
    import io
    if not incident_receipt_id:
        raise ValueError("incident_receipt_id is required")
    with source.open("rb") as fh:
        fcntl.flock(fh, fcntl.LOCK_SH)
        data = fh.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise AuditIntegrityError("snapshot SHA256 mismatch")
    verification = HashChainedAuditLog._verify_stream(io.BytesIO(data))
    return initialize_chain(destination,
        action="legacy_chain_migration",
        details={"legacy_file_sha256": digest, "legacy_valid_prefix": verification["records"],
                 "legacy_last_valid_record_hash": verification["head_hash"],
                 "legacy_failure_type": verification["failure_type"],
                 "incident_receipt_id": incident_receipt_id})


def initialize_chain(destination: Path, *, action: str, details: dict[str, Any]) -> dict[str, Any]:
    """Publish a complete genesis exclusively; no observable empty migration window."""
    import tempfile
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".audit-genesis-", dir=destination.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        record = HashChainedAuditLog(temporary).append(
            action=action, workspace_id=None, outcome="LEGACY_PRESERVED" if details else "PASS", details=details)
        os.link(temporary, destination)  # Fails even when an existing destination is empty.
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return record
    finally:
        temporary.unlink()
