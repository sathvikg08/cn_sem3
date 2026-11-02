import json
import socket
import struct
import threading

import pytest

from common.protocol import (
    MAX_HEADER_BYTES,
    ProtocolError,
    recv_exact,
    recv_frame,
    send_frame,
)


class ShortRecvSocket:
    """Socket stub that returns at most one byte per recv call."""

    def __init__(self, data: bytes):
        self._data = bytearray(data)

    def recv(self, _n: int) -> bytes:
        if not self._data:
            return b""
        byte = bytes(self._data[:1])
        del self._data[:1]
        return byte


def test_roundtrip_json_only():
    left, right = socket.socketpair()
    try:
        send_frame(left, {"type": "PING"})
        assert recv_frame(right) == ({"type": "PING", "payload_length": 0}, b"")
    finally:
        left.close()
        right.close()


def test_roundtrip_binary_payload():
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    payload = bytes(range(256)) * 4096
    received: list[tuple[dict, bytes]] = []
    errors: list[BaseException] = []

    def reader():
        try:
            received.append(recv_frame(right))
        except BaseException as exc:  # pragma: no cover - surfaced in assertion
            errors.append(exc)

    thread = threading.Thread(target=reader)
    thread.start()
    try:
        send_frame(left, {"type": "CHUNK", "index": 3}, payload)
        thread.join(timeout=10)
        assert not errors
        message, body = received[0]
        assert message["type"] == "CHUNK"
        assert message["index"] == 3
        assert message["payload_length"] == len(payload)
        assert body == payload
    finally:
        left.close()
        right.close()


def test_multiple_frames_keep_boundaries():
    left, right = socket.socketpair()
    try:
        for index in range(5):
            send_frame(left, {"type": "CHUNK", "index": index}, f"data-{index}".encode())
        for index in range(5):
            message, payload = recv_frame(right)
            assert message["index"] == index
            assert payload == f"data-{index}".encode()
    finally:
        left.close()
        right.close()


def test_recv_exact_handles_partial_reads():
    sock = ShortRecvSocket(b"abcdef")
    assert recv_exact(sock, 6) == b"abcdef"


def test_recv_exact_detects_closed_connection():
    sock = ShortRecvSocket(b"ab")
    with pytest.raises(ConnectionError):
        recv_exact(sock, 5)


def test_reserved_payload_field_rejected():
    left, right = socket.socketpair()
    try:
        with pytest.raises(ProtocolError):
            send_frame(left, {"type": "PING", "payload_length": 1})
    finally:
        left.close()
        right.close()


def test_oversized_header_rejected_on_send():
    left, right = socket.socketpair()
    try:
        with pytest.raises(ProtocolError):
            send_frame(left, {"type": "PING", "blob": "x" * MAX_HEADER_BYTES})
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    "prefix",
    [
        struct.pack("!I", 0),
        struct.pack("!I", MAX_HEADER_BYTES + 1),
    ],
)
def test_invalid_header_length_rejected(prefix):
    sock = ShortRecvSocket(prefix)
    with pytest.raises(ProtocolError):
        recv_frame(sock)


def test_invalid_json_rejected():
    raw = b"not json"
    sock = ShortRecvSocket(struct.pack("!I", len(raw)) + raw)
    with pytest.raises(ProtocolError):
        recv_frame(sock)


def test_non_object_json_rejected():
    raw = json.dumps([1, 2, 3]).encode()
    sock = ShortRecvSocket(struct.pack("!I", len(raw)) + raw)
    with pytest.raises(ProtocolError):
        recv_frame(sock)


def test_invalid_payload_length_rejected():
    raw = json.dumps({"type": "PING", "payload_length": -1}).encode()
    sock = ShortRecvSocket(struct.pack("!I", len(raw)) + raw)
    with pytest.raises(ProtocolError):
        recv_frame(sock)


def test_payload_too_large_rejected_before_reading():
    raw = json.dumps({"type": "PING", "payload_length": 17 * 1024 * 1024}).encode()
    sock = ShortRecvSocket(struct.pack("!I", len(raw)) + raw)
    with pytest.raises(ProtocolError):
        recv_frame(sock)
