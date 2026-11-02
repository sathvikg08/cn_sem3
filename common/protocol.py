"""TCP message framing.

Every frame is a 4-byte big-endian JSON header length, the UTF-8 JSON header
itself, and an optional binary payload whose length is stored in the header as
``payload_length``.  Control messages stay JSON while file chunks travel as raw
bytes without base64 overhead.
"""

from __future__ import annotations

import json
import struct
from typing import Any

HEADER_LENGTH = 4
MAX_HEADER_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
PAYLOAD_LENGTH_FIELD = "payload_length"


class ProtocolError(Exception):
    """Raised when a frame is malformed or violates protocol limits."""


def recv_exact(sock: Any, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise ``ConnectionError``."""
    if n < 0:
        raise ValueError("byte count must be non-negative")
    parts: list[bytes] = []
    remaining = n
    while remaining:
        piece = sock.recv(min(remaining, 64 * 1024))
        if not piece:
            raise ConnectionError("connection closed while reading a frame")
        parts.append(piece)
        remaining -= len(piece)
    return b"".join(parts)


def send_frame(sock: Any, message: dict[str, Any], payload: bytes = b"") -> None:
    """Send one JSON message plus optional binary payload."""
    if not isinstance(message, dict):
        raise TypeError("message must be a dict")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    payload = bytes(payload)
    if PAYLOAD_LENGTH_FIELD in message:
        raise ProtocolError(f"{PAYLOAD_LENGTH_FIELD!r} is reserved")

    header = dict(message)
    header[PAYLOAD_LENGTH_FIELD] = len(payload)
    try:
        raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"message is not JSON serialisable: {exc}") from exc
    if not raw:
        raise ProtocolError("empty JSON header")
    if len(raw) > MAX_HEADER_BYTES:
        raise ProtocolError("JSON header too large")

    sock.sendall(struct.pack("!I", len(raw)))
    sock.sendall(raw)
    if payload:
        sock.sendall(payload)


def recv_frame(sock: Any) -> tuple[dict[str, Any], bytes]:
    """Receive one frame, returning ``(message, payload)``."""
    prefix = recv_exact(sock, HEADER_LENGTH)
    (header_length,) = struct.unpack("!I", prefix)
    if header_length == 0 or header_length > MAX_HEADER_BYTES:
        raise ProtocolError(f"invalid header length: {header_length}")

    raw = recv_exact(sock, header_length)
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON header: {exc}") from exc
    if not isinstance(message, dict):
        raise ProtocolError("JSON header must be an object")

    payload_length = message.get(PAYLOAD_LENGTH_FIELD, 0)
    if isinstance(payload_length, bool) or not isinstance(payload_length, int):
        raise ProtocolError("payload_length must be an integer")
    if payload_length < 0 or payload_length > MAX_PAYLOAD_BYTES:
        raise ProtocolError(f"invalid payload length: {payload_length}")

    payload = recv_exact(sock, payload_length) if payload_length else b""
    return message, payload
