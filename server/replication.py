"""Server-to-server replication from the primary (A) to the replica (B)."""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Iterator

from common.transfer import upload_over_socket
from server.metadata import utc_now
from server.storage import ChunkStorage

LOGGER = logging.getLogger("backup.replication")


class Replicator:
    """Push a completed local file to the peer backup server."""

    def __init__(
        self,
        peer: tuple[str, int],
        *,
        node_name: str,
        timeout: float = 30.0,
    ):
        self.peer = (peer[0], int(peer[1]))
        self.node_name = node_name
        self.timeout = timeout

    @property
    def peer_label(self) -> str:
        return f"{self.peer[0]}:{self.peer[1]}"

    def replicate(
        self,
        record: dict[str, Any],
        chunks: list[dict[str, Any]],
        storage: ChunkStorage,
    ) -> dict[str, Any]:
        """Send one file to the peer.

        The origin file id is reused on the peer so a client can restore the
        same id after the primary becomes unavailable.  Re-sending an existing
        replica is idempotent.
        """
        chunk_iter: Iterator[bytes] = storage.iter_chunks(record["file_id"], chunks)
        with socket.create_connection(self.peer, timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            return upload_over_socket(
                sock,
                filename=record["filename"],
                size=record["size"],
                sha256=record["sha256"],
                chunk_size=record["chunk_size"],
                chunk_count=record["chunk_count"],
                chunks=chunk_iter,
                source_node=self.node_name,
                origin_file_id=record["file_id"],
            )

    def retry_pending(self, metadata: Any, storage: ChunkStorage, *, limit: int = 100) -> int:
        """Retry files still marked pending/failed.  Returns success count."""
        succeeded = 0
        for record in metadata.pending_replication(limit=limit):
            chunks = metadata.get_chunks(record["file_id"])
            try:
                self.replicate(record, chunks, storage)
            except Exception as exc:  # keep retrying later
                LOGGER.warning(
                    "replication retry failed for %s: %s", record["file_id"], exc
                )
                metadata.set_replication_status(
                    record["file_id"], "failed", error=str(exc)
                )
            else:
                metadata.set_replication_status(
                    record["file_id"], "replicated", replicated_at=utc_now()
                )
                succeeded += 1
        return succeeded


class ReplicationWorker:
    """Periodically retry failed replications in a daemon thread."""

    def __init__(
        self,
        replicator: Replicator,
        metadata: Any,
        storage: ChunkStorage,
        *,
        interval: float = 30.0,
    ):
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.replicator = replicator
        self.metadata = metadata
        self.storage = storage
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "ReplicationWorker":
        self._thread = threading.Thread(
            target=self._run, name="replication-retry", daemon=True
        )
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.replicator.retry_pending(self.metadata, self.storage)
            except Exception:  # pragma: no cover - defensive thread guard
                LOGGER.exception("replication retry loop failed")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


__all__ = [
    "ReplicationWorker",
    "Replicator",
]
