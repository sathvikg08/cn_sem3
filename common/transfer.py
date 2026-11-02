"""Client-side upload flow shared by the CLI client and server replication."""

from __future__ import annotations

import socket
from typing import Iterable

from common.hashing import sha256_bytes
from common.messages import ErrorCode, MessageType, build, validate
from common.protocol import ProtocolError, recv_frame, send_frame


class TransferError(Exception):
    """A transfer could not be completed."""


class RemoteError(TransferError):
    """The peer returned a structured ERROR frame."""

    def __init__(self, code: str, message: str, *, file_id: str | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.file_id = file_id


def raise_for_error(message: dict) -> None:
    if message.get("type") == MessageType.ERROR:
        raise RemoteError(
            str(message.get("code", ErrorCode.INTERNAL_ERROR)),
            str(message.get("message", "unknown server error")),
            file_id=message.get("file_id"),
        )


def upload_over_socket(
    sock: socket.socket,
    *,
    filename: str,
    size: int,
    sha256: str,
    chunk_size: int,
    chunk_count: int,
    chunks: Iterable[bytes],
    source_node: str = "client",
    origin_file_id: str | None = None,
) -> dict:
    """Run UPLOAD_BEGIN -> UPLOAD_READY -> CHUNK* -> UPLOAD_OK on ``sock``."""
    begin_fields = {
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "source_node": source_node,
    }
    if origin_file_id is not None:
        begin_fields["origin_file_id"] = origin_file_id
    send_frame(sock, build(MessageType.UPLOAD_BEGIN, **begin_fields))

    reply, _ = recv_frame(sock)
    raise_for_error(reply)
    validate(reply, MessageType.UPLOAD_READY)
    file_id = reply["file_id"]
    already_present = bool(reply.get("already_present", False))

    if not already_present:
        if reply["chunk_size"] != chunk_size or reply["chunk_count"] != chunk_count:
            raise TransferError(
                "server requested a different chunk layout: "
                f"{reply['chunk_size']} x {reply['chunk_count']}"
            )

        sent_chunks = 0
        sent_bytes = 0
        for index, chunk in enumerate(chunks):
            if index >= chunk_count:
                raise TransferError("local file produced more chunks than declared")
            message = build(
                MessageType.CHUNK,
                file_id=file_id,
                index=index,
                size=len(chunk),
                sha256=sha256_bytes(chunk),
            )
            send_frame(sock, message, chunk)
            sent_chunks += 1
            sent_bytes += len(chunk)
        if sent_chunks != chunk_count or sent_bytes != size:
            raise TransferError(
                f"local file changed during upload: {sent_chunks} chunks/"
                f"{sent_bytes} bytes, expected {chunk_count}/{size}"
            )

    result, _ = recv_frame(sock)
    raise_for_error(result)
    validate(result, MessageType.UPLOAD_OK)
    if result["file_id"] != file_id:
        raise TransferError("server acknowledged a different file id")
    if result["sha256"].lower() != sha256.lower():
        raise TransferError("server acknowledged a different SHA-256")
    if result["size"] != size:
        raise TransferError("server acknowledged a different file size")
    return result


def close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


__all__ = [
    "ProtocolError",
    "RemoteError",
    "TransferError",
    "close_quietly",
    "raise_for_error",
    "upload_over_socket",
]
