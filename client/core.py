"""High-level backup client with automatic failover between servers."""

from __future__ import annotations

import hashlib
import os
import socket
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

from common.chunking import DEFAULT_CHUNK_SIZE, chunk_count, iter_file_chunks
from common.hashing import sha256_bytes, sha256_file
from common.messages import ErrorCode, MessageType, build, validate
from common.protocol import ProtocolError, recv_frame, send_frame
from common.transfer import RemoteError, raise_for_error, upload_over_socket

DEFAULT_SERVERS = ("127.0.0.1:9101", "127.0.0.1:9102")


class BackupError(Exception):
    """High-level client failure."""


class DestinationExists(BackupError):
    """Restore destination exists and overwrite was not requested."""


class IntegrityCheckError(BackupError):
    """A downloaded chunk or file failed SHA-256 verification."""


def parse_endpoint(value: str | Sequence[Any]) -> tuple[str, int]:
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("endpoint tuple must be (host, port)")
        host, port = value
    else:
        if not isinstance(value, str):
            raise ValueError("endpoint must be 'host:port'")
        host, separator, raw_port = value.rpartition(":")
        if not separator or not host:
            raise ValueError(f"invalid endpoint: {value!r}")
        port = raw_port
    try:
        port_number = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid port: {port!r}") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError(f"port out of range: {port_number}")
    return str(host), port_number


def endpoint_label(endpoint: tuple[str, int]) -> str:
    return f"{endpoint[0]}:{endpoint[1]}"


def servers_from_env(value: str | None = None) -> list[tuple[str, int]]:
    raw = value if value is not None else os.environ.get("BACKUP_SERVERS", "")
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    return [parse_endpoint(item) for item in (entries or DEFAULT_SERVERS)]


class BackupClient:
    def __init__(
        self,
        servers: Iterable[str | Sequence[Any]] | None = None,
        *,
        timeout: float = 30.0,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.servers = [parse_endpoint(server) for server in (servers or DEFAULT_SERVERS)]
        if not self.servers:
            raise ValueError("at least one server is required")
        self.timeout = timeout
        self.chunk_size = chunk_size

    # ----------------------------------------------------------------- helpers
    def _connect(self, endpoint: tuple[str, int]) -> socket.socket:
        sock = socket.create_connection(endpoint, timeout=self.timeout)
        sock.settimeout(self.timeout)
        return sock

    def _simple_request(
        self,
        endpoint: tuple[str, int],
        request: dict[str, Any],
        expected_type: str,
    ) -> dict[str, Any]:
        with self._connect(endpoint) as sock:
            send_frame(sock, request)
            response, _ = recv_frame(sock)
            raise_for_error(response)
            validate(response, expected_type)
            return response

    # ------------------------------------------------------------------ upload
    def upload_file(
        self, path: str | os.PathLike[str], remote_name: str | None = None
    ) -> dict[str, Any]:
        source = Path(path)
        if not source.is_file():
            raise BackupError(f"not a regular file: {source}")
        size = source.stat().st_size
        sha256 = sha256_file(source, self.chunk_size)
        chunks = chunk_count(size, self.chunk_size)
        filename = remote_name or source.name

        failures: list[str] = []
        for endpoint in self.servers:
            label = endpoint_label(endpoint)
            try:
                with self._connect(endpoint) as sock:
                    result = upload_over_socket(
                        sock,
                        filename=filename,
                        size=size,
                        sha256=sha256,
                        chunk_size=self.chunk_size,
                        chunk_count=chunks,
                        chunks=iter_file_chunks(source, self.chunk_size),
                    )
            except (OSError, ConnectionError, ProtocolError) as exc:
                failures.append(f"{label}: {exc}")
                continue
            result["endpoint"] = label
            result["node"] = result.get("server_node")
            result["verified"] = True
            return result

        raise BackupError(
            "upload failed on every server" + (f": {'; '.join(failures)}" if failures else "")
        )

    # ----------------------------------------------------------------- restore
    def restore_file(
        self,
        file_id: str,
        destination: str | os.PathLike[str],
        *,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(file_id, str) or not file_id:
            raise BackupError("file id is required")
        failures: list[str] = []
        for endpoint in self.servers:
            label = endpoint_label(endpoint)
            try:
                result = self._restore_from(
                    endpoint, file_id, destination, overwrite=overwrite
                )
            except (OSError, ConnectionError, ProtocolError) as exc:
                failures.append(f"{label}: {exc}")
                continue
            except RemoteError as exc:
                if exc.code == ErrorCode.FILE_NOT_FOUND:
                    failures.append(f"{label}: {exc}")
                    continue
                raise
            result["endpoint"] = label
            result["node"] = result.get("server_node")
            return result

        raise BackupError(
            f"could not restore {file_id} from any server"
            + (f": {'; '.join(failures)}" if failures else "")
        )

    def _restore_from(
        self,
        endpoint: tuple[str, int],
        file_id: str,
        destination: str | os.PathLike[str],
        *,
        overwrite: bool,
    ) -> dict[str, Any]:
        with self._connect(endpoint) as sock:
            send_frame(sock, build(MessageType.DOWNLOAD, file_id=file_id))
            response, _ = recv_frame(sock)
            raise_for_error(response)
            validate(response, MessageType.FILE_BEGIN)
            if response["file_id"] != file_id:
                raise ProtocolError("server announced a different file id")

            filename = Path(str(response["filename"])).name
            if not filename or filename in {".", ".."}:
                filename = "restored.bin"
            target = self._resolve_destination(destination, filename)
            if target.exists() and not overwrite:
                raise DestinationExists(f"destination already exists: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)

            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
            expected_chunks = int(response["chunk_count"])
            expected_size = int(response["size"])
            expected_sha = str(response["sha256"]).lower()
            written = 0
            whole = hashlib.sha256()
            try:
                with open(temporary, "wb") as handle:
                    for expected_index in range(expected_chunks):
                        chunk_frame, payload = recv_frame(sock)
                        raise_for_error(chunk_frame)
                        validate(chunk_frame, MessageType.CHUNK)
                        if chunk_frame["file_id"] != file_id:
                            raise ProtocolError("chunk belongs to a different file id")
                        if chunk_frame["index"] != expected_index:
                            raise ProtocolError(
                                f"expected chunk {expected_index}, got "
                                f"{chunk_frame['index']}"
                            )
                        if chunk_frame["size"] != len(payload):
                            raise ProtocolError("chunk length does not match size field")
                        if sha256_bytes(payload) != chunk_frame["sha256"].lower():
                            raise IntegrityCheckError(
                                f"chunk {expected_index} checksum mismatch"
                            )
                        handle.write(payload)
                        whole.update(payload)
                        written += len(payload)

                final_frame, _ = recv_frame(sock)
                raise_for_error(final_frame)
                validate(final_frame, MessageType.DOWNLOAD_OK)
                if final_frame["file_id"] != file_id:
                    raise ProtocolError("server completed a different file id")
                if written != expected_size or final_frame["size"] != expected_size:
                    raise IntegrityCheckError(
                        f"restored size mismatch: {written} != {expected_size}"
                    )
                digest = whole.hexdigest()
                if digest != expected_sha or final_frame["sha256"].lower() != expected_sha:
                    raise IntegrityCheckError("restored whole-file checksum mismatch")
                os.replace(temporary, target)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise

            return {
                "file_id": file_id,
                "filename": filename,
                "path": str(target),
                "size": written,
                "sha256": digest,
                "verified": True,
                "server_node": response.get("server_node"),
            }

    @staticmethod
    def _resolve_destination(
        destination: str | os.PathLike[str], filename: str
    ) -> Path:
        raw = str(destination)
        path = Path(destination)
        treat_as_directory = raw.endswith(("/", os.sep)) or path.is_dir()
        if treat_as_directory:
            path.mkdir(parents=True, exist_ok=True)
            return path / filename
        return path

    # -------------------------------------------------------------------- list
    def list_files(self) -> dict[str, Any]:
        failures: list[str] = []
        for endpoint in self.servers:
            label = endpoint_label(endpoint)
            try:
                response = self._simple_request(
                    endpoint, build(MessageType.LIST), MessageType.LIST_OK
                )
            except (OSError, ConnectionError, ProtocolError) as exc:
                failures.append(f"{label}: {exc}")
                continue
            response["endpoint"] = label
            response["node"] = response.get("server_node")
            return response
        raise BackupError(
            "could not list files on any server"
            + (f": {'; '.join(failures)}" if failures else "")
        )

    # ------------------------------------------------------------------ delete
    def delete_file(self, file_id: str) -> dict[str, Any]:
        """Delete a file on every reachable server that has it."""
        deleted_on: list[str] = []
        missing_on: list[str] = []
        failures: list[str] = []
        for endpoint in self.servers:
            label = endpoint_label(endpoint)
            try:
                self._simple_request(
                    endpoint,
                    build(MessageType.DELETE, file_id=file_id),
                    MessageType.DELETE_OK,
                )
            except RemoteError as exc:
                if exc.code == ErrorCode.FILE_NOT_FOUND:
                    missing_on.append(label)
                    continue
                failures.append(f"{label}: {exc}")
            except (OSError, ConnectionError, ProtocolError) as exc:
                failures.append(f"{label}: {exc}")
            else:
                deleted_on.append(label)

        if not deleted_on and failures and not missing_on:
            raise BackupError(f"delete failed: {'; '.join(failures)}")
        return {
            "file_id": file_id,
            "deleted_on": deleted_on,
            "missing_on": missing_on,
            "failures": failures,
        }

    # ------------------------------------------------------------------ status
    def status_all(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for endpoint in self.servers:
            label = endpoint_label(endpoint)
            try:
                response = self._simple_request(
                    endpoint, build(MessageType.PING), MessageType.PONG
                )
            except (OSError, ConnectionError, ProtocolError, RemoteError) as exc:
                results.append(
                    {"endpoint": label, "online": False, "error": str(exc)}
                )
            else:
                results.append(
                    {
                        "endpoint": label,
                        "online": True,
                        "node": response["node"],
                        "file_count": response["file_count"],
                        "total_bytes": response["total_bytes"],
                    }
                )
        return results
