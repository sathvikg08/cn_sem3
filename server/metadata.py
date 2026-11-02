"""SQLite metadata store for backup files and chunks.

A connection is opened per operation, making the store safe to use from the
thread-per-connection server.  In-progress uploads are visible only inside the
store; ``list_files`` and ``get_file`` return completed files by default.
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

VALID_REPLICATION_STATUSES = {
    "not_applicable",
    "pending",
    "replicated",
    "failed",
    "received",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    file_id            TEXT PRIMARY KEY,
    filename           TEXT NOT NULL,
    size               INTEGER NOT NULL CHECK (size >= 0),
    sha256             TEXT NOT NULL,
    chunk_size         INTEGER NOT NULL CHECK (chunk_size > 0),
    chunk_count        INTEGER NOT NULL CHECK (chunk_count >= 0),
    status             TEXT NOT NULL CHECK (status IN ('uploading', 'complete')),
    source_node        TEXT NOT NULL,
    origin_file_id     TEXT,
    replication_status TEXT NOT NULL,
    replication_error  TEXT,
    created_at         TEXT NOT NULL,
    completed_at       TEXT,
    replicated_at      TEXT
);

CREATE TABLE IF NOT EXISTS chunks (
    file_id TEXT NOT NULL,
    idx     INTEGER NOT NULL CHECK (idx >= 0),
    size    INTEGER NOT NULL CHECK (size >= 0),
    sha256  TEXT NOT NULL,
    PRIMARY KEY (file_id, idx),
    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_replication ON files(replication_status);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class MetadataStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create_upload(
        self,
        *,
        file_id: str,
        filename: str,
        size: int,
        sha256: str,
        chunk_size: int,
        chunk_count: int,
        source_node: str,
        origin_file_id: str | None = None,
        replication_status: str = "not_applicable",
    ) -> dict[str, Any]:
        if replication_status not in VALID_REPLICATION_STATUSES:
            raise ValueError(f"invalid replication status: {replication_status}")
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO files (
                    file_id, filename, size, sha256, chunk_size, chunk_count,
                    status, source_node, origin_file_id, replication_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'uploading', ?, ?, ?, ?)
                """,
                (
                    file_id,
                    filename,
                    size,
                    sha256.lower(),
                    chunk_size,
                    chunk_count,
                    source_node,
                    origin_file_id,
                    replication_status,
                    utc_now(),
                ),
            )
        return self.get_file(file_id, include_incomplete=True)

    def add_chunk(self, file_id: str, index: int, size: int, sha256: str) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO chunks (file_id, idx, size, sha256) VALUES (?, ?, ?, ?)",
                (file_id, index, size, sha256.lower()),
            )

    def complete_upload(self, file_id: str, replication_status: str) -> None:
        if replication_status not in VALID_REPLICATION_STATUSES:
            raise ValueError(f"invalid replication status: {replication_status}")
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE files
                   SET status = 'complete', completed_at = ?, replication_status = ?
                 WHERE file_id = ? AND status = 'uploading'
                """,
                (utc_now(), replication_status, file_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"in-progress upload not found: {file_id}")

    def abort_upload(self, file_id: str) -> bool:
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM files WHERE file_id = ? AND status = 'uploading'",
                (file_id,),
            )
            return cursor.rowcount == 1

    def get_file(
        self, file_id: str, *, include_incomplete: bool = False
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM files WHERE file_id = ?"
        params: tuple[Any, ...] = (file_id,)
        if not include_incomplete:
            query += " AND status = 'complete'"
        with self._connection() as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def get_chunks(self, file_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT idx, size, sha256 FROM chunks WHERE file_id = ? ORDER BY idx",
                (file_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_files(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM files WHERE status = 'complete' ORDER BY created_at, rowid"
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_file(self, file_id: str) -> bool:
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM files WHERE file_id = ? AND status = 'complete'",
                (file_id,),
            )
            return cursor.rowcount == 1

    def set_replication_status(
        self,
        file_id: str,
        status: str,
        *,
        error: str | None = None,
        replicated_at: str | None = None,
    ) -> None:
        if status not in VALID_REPLICATION_STATUSES:
            raise ValueError(f"invalid replication status: {status}")
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE files
                   SET replication_status = ?, replication_error = ?, replicated_at = ?
                 WHERE file_id = ?
                """,
                (status, error, replicated_at, file_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"file not found: {file_id}")

    def pending_replication(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM files
                 WHERE status = 'complete'
                   AND replication_status IN ('pending', 'failed')
                 ORDER BY created_at, rowid
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, int]:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS file_count, COALESCE(SUM(size), 0) AS total_bytes
                  FROM files WHERE status = 'complete'
                """
            ).fetchone()
        return {"file_count": int(row["file_count"]), "total_bytes": int(row["total_bytes"])}


def new_file_id() -> str:
    return uuid.uuid4().hex
