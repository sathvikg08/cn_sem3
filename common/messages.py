"""The single source of truth for JSON message types and their fields.

Client, server, and replication code must build messages through :func:`build`
and check incoming messages with :func:`validate` so the wire schema never
drifts between modules.
"""

from __future__ import annotations

from typing import Any, Collection


class MessageType:
    UPLOAD_BEGIN = "UPLOAD_BEGIN"
    UPLOAD_READY = "UPLOAD_READY"
    CHUNK = "CHUNK"
    UPLOAD_OK = "UPLOAD_OK"
    LIST = "LIST"
    LIST_OK = "LIST_OK"
    DOWNLOAD = "DOWNLOAD"
    FILE_BEGIN = "FILE_BEGIN"
    DOWNLOAD_OK = "DOWNLOAD_OK"
    DELETE = "DELETE"
    DELETE_OK = "DELETE_OK"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"


class ErrorCode:
    BAD_REQUEST = "BAD_REQUEST"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    CHUNK_ERROR = "CHUNK_ERROR"
    CONFLICT = "CONFLICT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# Required field names for every message type.  Optional fields are documented
# next to the schema; payload bytes are always handled by common.protocol.
REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    MessageType.UPLOAD_BEGIN: frozenset(
        {"filename", "size", "sha256", "chunk_size", "chunk_count", "source_node"}
    ),
    MessageType.UPLOAD_READY: frozenset({"file_id", "chunk_size", "chunk_count"}),
    MessageType.CHUNK: frozenset({"file_id", "index", "size", "sha256"}),
    MessageType.UPLOAD_OK: frozenset(
        {"file_id", "filename", "size", "sha256", "chunk_count", "replicated"}
    ),
    MessageType.LIST: frozenset(),
    MessageType.LIST_OK: frozenset({"files"}),
    MessageType.DOWNLOAD: frozenset({"file_id"}),
    MessageType.FILE_BEGIN: frozenset(
        {"file_id", "filename", "size", "sha256", "chunk_size", "chunk_count"}
    ),
    MessageType.DOWNLOAD_OK: frozenset({"file_id", "sha256", "size"}),
    MessageType.DELETE: frozenset({"file_id"}),
    MessageType.DELETE_OK: frozenset({"file_id"}),
    MessageType.PING: frozenset(),
    MessageType.PONG: frozenset({"node", "file_count", "total_bytes"}),
    MessageType.ERROR: frozenset({"code", "message"}),
}

# Optional fields used by the server / replication path:
#   UPLOAD_BEGIN.origin_file_id  -- set by a replicating server
#   UPLOAD_READY.already_present -- idempotent replica retry
#   UPLOAD_OK.replication_status, .replication_error, .server_node
#   FILE_BEGIN.server_node
#   LIST_OK.server_node
#   ERROR.file_id
OPTIONAL_FIELDS: dict[str, frozenset[str]] = {
    MessageType.UPLOAD_BEGIN: frozenset({"origin_file_id"}),
    MessageType.UPLOAD_READY: frozenset({"already_present"}),
    MessageType.UPLOAD_OK: frozenset(
        {"replication_status", "replication_error", "server_node"}
    ),
    MessageType.FILE_BEGIN: frozenset({"server_node"}),
    MessageType.LIST_OK: frozenset({"server_node"}),
    MessageType.ERROR: frozenset({"file_id"}),
}


def build(message_type: str, **fields: Any) -> dict[str, Any]:
    """Build a validated message dict."""
    if message_type not in REQUIRED_FIELDS:
        raise ValueError(f"unknown message type: {message_type}")
    required = REQUIRED_FIELDS[message_type]
    missing = required.difference(fields)
    if missing:
        raise ValueError(
            f"{message_type} missing required fields: {', '.join(sorted(missing))}"
        )
    return {"type": message_type, **fields}


def validate(
    message: Any, expected: str | Collection[str] | None = None
) -> dict[str, Any]:
    """Validate an incoming message and return it.

    ``expected`` may be a single message type or a collection of allowed types.
    """
    if not isinstance(message, dict):
        raise ValueError("message must be a dict")
    message_type = message.get("type")
    if not isinstance(message_type, str) or message_type not in REQUIRED_FIELDS:
        raise ValueError(f"unknown message type: {message_type!r}")
    if expected is not None:
        allowed = {expected} if isinstance(expected, str) else set(expected)
        if message_type not in allowed:
            raise ValueError(
                f"expected {sorted(allowed)}, got {message_type}"
            )
    missing = REQUIRED_FIELDS[message_type].difference(message)
    if missing:
        raise ValueError(
            f"{message_type} missing required fields: {', '.join(sorted(missing))}"
        )
    return message


def error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    """Build an ERROR message."""
    return build(MessageType.ERROR, code=code, message=message, **extra)
