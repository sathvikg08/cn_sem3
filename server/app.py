"""Backup server application: TCP protocol handling, storage, and metadata."""

from __future__ import annotations

import logging
import re
import socketserver
import threading
from pathlib import Path
from typing import Any

from common.hashing import sha256_bytes
from common.messages import ErrorCode, MessageType, build, error, validate
from common.protocol import ProtocolError, recv_frame, send_frame
from server.metadata import MetadataStore, new_file_id, utc_now
from server.storage import (
    ChecksumError,
    ChunkStorage,
    MissingChunkError,
    StorageError,
)

LOGGER = logging.getLogger("backup.server")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_CHUNK_SIZE = 8 * 1024 * 1024
MAX_FILENAME_LENGTH = 255


def sanitize_filename(filename: Any) -> str:
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")
    candidate = filename.replace("\\", "/").split("/")[-1].strip()
    if not candidate or candidate in {".", ".."}:
        raise ValueError("invalid filename")
    if len(candidate) > MAX_FILENAME_LENGTH:
        raise ValueError("filename too long")
    return candidate


def _require_int(message: dict, field: str, *, minimum: int = 0) -> int:
    value = message.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _require_sha256(message: dict, field: str = "sha256") -> str:
    value = message.get(field)
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a 64-character hex SHA-256")
    return value.lower()


class BackupApplication:
    """Protocol logic independent of the socket server wrapper."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        node_name: str = "A",
        replicator: Any | None = None,
        request_timeout: float = 120.0,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.node_name = node_name
        self.replicator = replicator
        self.request_timeout = request_timeout
        self.metadata = MetadataStore(self.data_dir / "metadata.db")
        self.storage = ChunkStorage(self.data_dir)
        self.log = logging.getLogger(f"backup.server.{node_name}")

    # ------------------------------------------------------------------ public
    def handle_client(self, sock: Any, address: Any) -> None:
        sock.settimeout(self.request_timeout)
        try:
            message, _ = recv_frame(sock)
            validate(message)
            message_type = message["type"]

            if message_type == MessageType.PING:
                self._handle_ping(sock)
            elif message_type == MessageType.LIST:
                self._handle_list(sock)
            elif message_type == MessageType.DOWNLOAD:
                self._handle_download(sock, message)
            elif message_type == MessageType.DELETE:
                self._handle_delete(sock, message)
            elif message_type == MessageType.UPLOAD_BEGIN:
                self._handle_upload(sock, message)
            else:
                self._send_error(
                    sock,
                    ErrorCode.BAD_REQUEST,
                    f"unsupported request in this state: {message_type}",
                )
        except (ConnectionError, ProtocolError, OSError) as exc:
            self.log.info("connection %s ended: %s", address, exc)
        except ValueError as exc:
            self._send_error(sock, ErrorCode.BAD_REQUEST, str(exc))
        except Exception as exc:  # defensive: keep the server alive
            self.log.exception("unhandled error for %s", address)
            self._send_error(sock, ErrorCode.INTERNAL_ERROR, f"internal error: {exc}")

    # --------------------------------------------------------------- requests
    def _handle_ping(self, sock: Any) -> None:
        stats = self.metadata.stats()
        send_frame(
            sock,
            build(
                MessageType.PONG,
                node=self.node_name,
                file_count=stats["file_count"],
                total_bytes=stats["total_bytes"],
            ),
        )

    def _handle_list(self, sock: Any) -> None:
        files = []
        for record in self.metadata.list_files():
            files.append(
                {
                    "file_id": record["file_id"],
                    "filename": record["filename"],
                    "size": record["size"],
                    "sha256": record["sha256"],
                    "chunk_count": record["chunk_count"],
                    "source_node": record["source_node"],
                    "replication_status": record["replication_status"],
                    "created_at": record["created_at"],
                }
            )
        send_frame(sock, build(MessageType.LIST_OK, files=files, server_node=self.node_name))

    def _handle_download(self, sock: Any, message: dict) -> None:
        validate(message, MessageType.DOWNLOAD)
        file_id = message.get("file_id")
        if not isinstance(file_id, str):
            raise ValueError("file_id must be a string")
        record = self.metadata.get_file(file_id)
        if record is None:
            self._send_error(
                sock,
                ErrorCode.FILE_NOT_FOUND,
                f"no complete file with id {file_id}",
                file_id=file_id,
            )
            return
        chunks = self.metadata.get_chunks(file_id)
        send_frame(
            sock,
            build(
                MessageType.FILE_BEGIN,
                file_id=record["file_id"],
                filename=record["filename"],
                size=record["size"],
                sha256=record["sha256"],
                chunk_size=record["chunk_size"],
                chunk_count=record["chunk_count"],
                server_node=self.node_name,
            ),
        )
        try:
            chunk_iter = self.storage.iter_chunks(file_id, chunks)
            for chunk_meta, data in zip(chunks, chunk_iter):
                send_frame(
                    sock,
                    build(
                        MessageType.CHUNK,
                        file_id=record["file_id"],
                        index=chunk_meta["idx"],
                        size=len(data),
                        sha256=sha256_bytes(data),
                    ),
                    data,
                )
        except (MissingChunkError, ChecksumError, StorageError) as exc:
            self.log.error("cannot stream %s: %s", file_id, exc)
            self._send_error(
                sock,
                ErrorCode.CHECKSUM_MISMATCH,
                f"stored file failed verification: {exc}",
                file_id=file_id,
            )
            return
        send_frame(
            sock,
            build(
                MessageType.DOWNLOAD_OK,
                file_id=record["file_id"],
                sha256=record["sha256"],
                size=record["size"],
            ),
        )

    def _handle_delete(self, sock: Any, message: dict) -> None:
        validate(message, MessageType.DELETE)
        file_id = message.get("file_id")
        if not isinstance(file_id, str):
            raise ValueError("file_id must be a string")
        if not self.metadata.delete_file(file_id):
            self._send_error(
                sock,
                ErrorCode.FILE_NOT_FOUND,
                f"no complete file with id {file_id}",
                file_id=file_id,
            )
            return
        self.storage.delete_file(file_id)
        send_frame(sock, build(MessageType.DELETE_OK, file_id=file_id))

    # ----------------------------------------------------------------- upload
    def _handle_upload(self, sock: Any, message: dict) -> None:
        validate(message, MessageType.UPLOAD_BEGIN)
        filename = sanitize_filename(message["filename"])
        size = _require_int(message, "size", minimum=0)
        sha256 = _require_sha256(message)
        chunk_size = _require_int(message, "chunk_size", minimum=1)
        if chunk_size > MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be <= {MAX_CHUNK_SIZE}")
        chunk_count = _require_int(message, "chunk_count", minimum=0)
        expected_chunks = (size + chunk_size - 1) // chunk_size
        if chunk_count != expected_chunks:
            raise ValueError(
                f"chunk_count {chunk_count} does not match size/chunk_size "
                f"({expected_chunks})"
            )
        source_node = message.get("source_node")
        if not isinstance(source_node, str) or not source_node or len(source_node) > 64:
            raise ValueError("source_node must be a non-empty string")

        origin_file_id = message.get("origin_file_id")
        if origin_file_id is not None:
            if not isinstance(origin_file_id, str) or not re.fullmatch(
                r"[0-9a-f]{32}", origin_file_id
            ):
                raise ValueError("origin_file_id must be a 32-character hex id")
            if source_node == "client":
                raise ValueError("client uploads may not set origin_file_id")

            existing = self.metadata.get_file(origin_file_id)
            if existing is not None:
                if existing["sha256"] == sha256 and existing["size"] == size:
                    send_frame(
                        sock,
                        build(
                            MessageType.UPLOAD_READY,
                            file_id=existing["file_id"],
                            chunk_size=existing["chunk_size"],
                            chunk_count=existing["chunk_count"],
                            already_present=True,
                        ),
                    )
                    send_frame(
                        sock,
                        self._upload_ok(existing, replicated=True),
                    )
                    return
                self._send_error(
                    sock,
                    ErrorCode.CONFLICT,
                    "a different file already uses this origin id",
                    file_id=origin_file_id,
                )
                return
            file_id = origin_file_id
        else:
            file_id = new_file_id()

        if self.replicator is not None and origin_file_id is None:
            initial_replication = "pending"
        elif origin_file_id is not None:
            initial_replication = "received"
        else:
            initial_replication = "not_applicable"

        try:
            self.metadata.create_upload(
                file_id=file_id,
                filename=filename,
                size=size,
                sha256=sha256,
                chunk_size=chunk_size,
                chunk_count=chunk_count,
                source_node=source_node,
                origin_file_id=origin_file_id,
                replication_status=initial_replication,
            )
        except Exception as exc:
            self.log.warning("cannot start upload %s: %s", file_id, exc)
            self._send_error(sock, ErrorCode.BAD_REQUEST, f"cannot start upload: {exc}")
            return

        try:
            send_frame(
                sock,
                build(
                    MessageType.UPLOAD_READY,
                    file_id=file_id,
                    chunk_size=chunk_size,
                    chunk_count=chunk_count,
                ),
            )
        except (ConnectionError, OSError):
            self.metadata.abort_upload(file_id)
            self.storage.abort_upload(file_id)
            raise

        try:
            for expected_index in range(chunk_count):
                chunk_message, payload = recv_frame(sock)
                if chunk_message.get("type") == MessageType.ERROR:
                    self.metadata.abort_upload(file_id)
                    self.storage.abort_upload(file_id)
                    return
                validate(chunk_message, MessageType.CHUNK)
                if chunk_message["file_id"] != file_id:
                    raise ValueError("chunk belongs to a different file id")
                if chunk_message["index"] != expected_index:
                    raise ValueError(
                        f"expected chunk {expected_index}, got "
                        f"{chunk_message['index']}"
                    )
                chunk_size_field = _require_int(chunk_message, "size", minimum=0)
                if len(payload) != chunk_size_field:
                    raise ValueError("chunk payload length does not match size field")
                expected_size = (
                    chunk_size
                    if expected_index < chunk_count - 1
                    else size - chunk_size * (chunk_count - 1)
                )
                if len(payload) != expected_size:
                    raise ValueError(
                        f"chunk {expected_index} has wrong size: {len(payload)}"
                    )
                chunk_digest = _require_sha256(chunk_message)
                if sha256_bytes(payload) != chunk_digest:
                    raise ChecksumError(f"chunk {expected_index} checksum mismatch")
                self.storage.save_chunk(file_id, expected_index, payload)
                self.metadata.add_chunk(
                    file_id, expected_index, len(payload), chunk_digest
                )
        except (ValueError, ChecksumError) as exc:
            self.log.warning("upload %s rejected: %s", file_id, exc)
            self.metadata.abort_upload(file_id)
            self.storage.abort_upload(file_id)
            code = (
                ErrorCode.CHECKSUM_MISMATCH
                if isinstance(exc, ChecksumError)
                else ErrorCode.CHUNK_ERROR
            )
            self._send_error(sock, code, str(exc), file_id=file_id)
            return
        except (ConnectionError, ProtocolError, OSError):
            self.log.info("upload %s interrupted; cleaning up", file_id)
            self.metadata.abort_upload(file_id)
            self.storage.abort_upload(file_id)
            raise

        chunks = self.metadata.get_chunks(file_id)
        try:
            self.storage.finalize_upload(
                file_id,
                chunks,
                expected_size=size,
                expected_sha256=sha256,
            )
        except (ChecksumError, StorageError) as exc:
            self.log.warning("upload %s failed verification: %s", file_id, exc)
            self.metadata.abort_upload(file_id)
            self.storage.abort_upload(file_id)
            self._send_error(
                sock, ErrorCode.CHECKSUM_MISMATCH, str(exc), file_id=file_id
            )
            return

        self.metadata.complete_upload(file_id, initial_replication)
        record = self.metadata.get_file(file_id)
        assert record is not None

        replicated = False
        replication_error = None
        if self.replicator is not None and origin_file_id is None:
            try:
                self.replicator.replicate(record, chunks, self.storage)
                self.metadata.set_replication_status(
                    file_id, "replicated", replicated_at=utc_now()
                )
                record = self.metadata.get_file(file_id)
                assert record is not None
                replicated = True
            except Exception as exc:  # replication must not lose the local copy
                replication_error = str(exc)
                self.log.warning("replication of %s failed: %s", file_id, exc)
                self.metadata.set_replication_status(
                    file_id, "failed", error=replication_error
                )
                record = self.metadata.get_file(file_id)
                assert record is not None

        send_frame(sock, self._upload_ok(record, replicated=replicated))

    def _upload_ok(self, record: dict, *, replicated: bool) -> dict:
        fields = {
            "file_id": record["file_id"],
            "filename": record["filename"],
            "size": record["size"],
            "sha256": record["sha256"],
            "chunk_count": record["chunk_count"],
            "replicated": replicated,
            "replication_status": record["replication_status"],
            "server_node": self.node_name,
        }
        if record.get("replication_error"):
            fields["replication_error"] = record["replication_error"]
        return build(MessageType.UPLOAD_OK, **fields)

    # ------------------------------------------------------------------ helper
    @staticmethod
    def _send_error(
        sock: Any,
        code: str,
        message: str,
        *,
        file_id: str | None = None,
    ) -> None:
        extra = {"file_id": file_id} if file_id is not None else {}
        try:
            send_frame(sock, error(code, message, **extra))
        except (ConnectionError, OSError, ProtocolError):
            pass


class BackupRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.app.handle_client(self.request, self.client_address)


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], app: BackupApplication):
        self.app = app
        super().__init__(address, BackupRequestHandler)


class BackupServer:
    """Lifecycle wrapper around the threaded TCP server."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        host: str = "127.0.0.1",
        port: int = 9101,
        node_name: str = "A",
        replicator: Any | None = None,
        request_timeout: float = 120.0,
    ):
        self.host = host
        self.port = port
        self.node_name = node_name
        self.app = BackupApplication(
            data_dir=data_dir,
            node_name=node_name,
            replicator=replicator,
            request_timeout=request_timeout,
        )
        self._tcp_server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._tcp_server is not None:
            return (self.host, self._tcp_server.server_address[1])
        return (self.host, self.port)

    @property
    def endpoint(self) -> str:
        host, port = self.address
        return f"{host}:{port}"

    def _bind(self) -> _ThreadingTCPServer:
        if self._tcp_server is not None:
            raise RuntimeError("server is already bound")
        tcp = _ThreadingTCPServer((self.host, self.port), self.app)
        self._tcp_server = tcp
        self.port = tcp.server_address[1]
        return tcp

    def start(self) -> "BackupServer":
        """Bind and serve in a background daemon thread."""
        tcp = self._bind()
        self._thread = threading.Thread(
            target=lambda: tcp.serve_forever(poll_interval=0.05),
            name=f"backup-server-{self.node_name}",
            daemon=True,
        )
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        """Bind and block in the current thread."""
        tcp = self._bind()
        try:
            tcp.serve_forever(poll_interval=0.05)
        finally:
            tcp.server_close()
            self._tcp_server = None

    def stop(self) -> None:
        tcp = self._tcp_server
        if tcp is None:
            return
        tcp.shutdown()
        tcp.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._tcp_server = None


__all__ = [
    "BackupApplication",
    "BackupServer",
    "MAX_CHUNK_SIZE",
    "sanitize_filename",
]
