import hashlib
import socket
import time

import pytest

from client.core import BackupClient, BackupError, DestinationExists
from common.hashing import sha256_bytes, sha256_file
from common.messages import ErrorCode, MessageType, build
from common.protocol import recv_frame, send_frame
from tests.conftest import make_client
from server.storage import ChunkStorage


def upload_chunked(client: BackupClient, path, remote_name=None):
    return client.upload_file(path, remote_name=remote_name)


def test_ping_and_status(live_server):
    client = make_client(live_server)
    statuses = client.status_all()
    assert len(statuses) == 1
    assert statuses[0]["online"] is True
    assert statuses[0]["node"] == "A"
    assert statuses[0]["file_count"] == 0


def test_upload_list_restore_roundtrip(live_server, tmp_path):
    source = tmp_path / "report.bin"
    data = bytes(range(256)) * 10_000  # 2.56 MB -> three 1 MiB chunks
    source.write_bytes(data)
    client = make_client(live_server)

    uploaded = upload_chunked(client, source)
    assert uploaded["file_id"]
    assert uploaded["size"] == len(data)
    assert uploaded["sha256"] == sha256_bytes(data)
    assert uploaded["chunk_count"] == 3
    assert uploaded["verified"] is True
    assert uploaded["replication_status"] == "not_applicable"

    listed = client.list_files()
    assert [item["file_id"] for item in listed["files"]] == [uploaded["file_id"]]
    assert listed["files"][0]["filename"] == "report.bin"
    assert listed["files"][0]["size"] == len(data)
    assert listed["files"][0]["sha256"] == sha256_bytes(data)

    destination = tmp_path / "restored.bin"
    restored = client.restore_file(uploaded["file_id"], destination)
    assert destination.read_bytes() == data
    assert restored["sha256"] == sha256_bytes(data)
    assert restored["verified"] is True

    chunk_dir = live_server.app.storage.final_dir(uploaded["file_id"])
    assert sorted(path.name for path in chunk_dir.iterdir()) == [
        "0.chunk",
        "1.chunk",
        "2.chunk",
    ]
    assert sha256_file(destination) == uploaded["sha256"]


def test_empty_file_roundtrip(live_server, tmp_path):
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    client = make_client(live_server)

    uploaded = upload_chunked(client, source)
    assert uploaded["chunk_count"] == 0
    assert uploaded["sha256"] == hashlib.sha256(b"").hexdigest()

    destination = tmp_path / "empty-restored.bin"
    client.restore_file(uploaded["file_id"], destination)
    assert destination.read_bytes() == b""


def test_exact_one_mib_boundary(live_server, tmp_path):
    source = tmp_path / "one-mib.bin"
    data = b"x" * (1024 * 1024)
    source.write_bytes(data)
    client = make_client(live_server)

    uploaded = upload_chunked(client, source)
    assert uploaded["chunk_count"] == 1
    destination = tmp_path / "one-mib-restored.bin"
    client.restore_file(uploaded["file_id"], destination)
    assert destination.read_bytes() == data


@pytest.mark.parametrize("node", ["A", "B"])
def test_each_server_works_independently(server_factory, tmp_path, node):
    server = server_factory(node)
    client = BackupClient([server.endpoint])
    source = tmp_path / f"{node}.bin"
    data = f"server-{node}-".encode() * 200_000
    source.write_bytes(data)

    uploaded = client.upload_file(source)
    assert uploaded["node"] == node
    destination = tmp_path / f"{node}-restored.bin"
    restored = client.restore_file(uploaded["file_id"], destination)
    assert destination.read_bytes() == data
    assert restored["sha256"] == uploaded["sha256"]


def test_two_servers_store_independently(server_factory, tmp_path):
    server_a = server_factory("A")
    server_b = server_factory("B")
    client_a = BackupClient([server_a.endpoint])
    client_b = BackupClient([server_b.endpoint])

    source_a = tmp_path / "a.txt"
    source_b = tmp_path / "b.txt"
    source_a.write_text("only on A")
    source_b.write_text("only on B")

    uploaded_a = client_a.upload_file(source_a)
    uploaded_b = client_b.upload_file(source_b)

    assert [item["filename"] for item in client_a.list_files()["files"]] == ["a.txt"]
    assert [item["filename"] for item in client_b.list_files()["files"]] == ["b.txt"]
    assert uploaded_a["file_id"] != uploaded_b["file_id"]


def test_restore_missing_file_reports_failure(live_server, tmp_path):
    client = make_client(live_server)
    with pytest.raises(BackupError, match="could not restore"):
        client.restore_file("0" * 32, tmp_path / "missing.bin")


def test_delete_removes_metadata_and_chunks(live_server, tmp_path):
    source = tmp_path / "delete-me.txt"
    source.write_text("temporary data")
    client = make_client(live_server)
    uploaded = client.upload_file(source)
    file_id = uploaded["file_id"]

    result = client.delete_file(file_id)
    assert result["deleted_on"] == [live_server.endpoint]
    assert client.list_files()["files"] == []
    assert not live_server.app.storage.final_dir(file_id).exists()

    with pytest.raises(BackupError):
        client.restore_file(file_id, tmp_path / "gone.txt")


def test_restore_overwrite_protection(live_server, tmp_path):
    source = tmp_path / "overwrite.txt"
    source.write_text("new contents")
    client = make_client(live_server)
    uploaded = client.upload_file(source)
    destination = tmp_path / "existing.txt"
    destination.write_text("old contents")

    with pytest.raises(DestinationExists):
        client.restore_file(uploaded["file_id"], destination)
    assert destination.read_text() == "old contents"

    client.restore_file(uploaded["file_id"], destination, overwrite=True)
    assert destination.read_text() == "new contents"


def test_restore_into_directory_uses_original_filename(live_server, tmp_path):
    source = tmp_path / "inside.bin"
    source.write_bytes(b"directory restore")
    client = make_client(live_server)
    uploaded = client.upload_file(source)
    output_dir = tmp_path / "restore-dir"
    output_dir.mkdir()

    result = client.restore_file(uploaded["file_id"], output_dir)
    assert (output_dir / "inside.bin").read_bytes() == b"directory restore"
    assert result["path"] == str(output_dir / "inside.bin")


def test_remote_filename_is_sanitized(live_server, tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("name check")
    client = make_client(live_server)
    uploaded = client.upload_file(source, remote_name="../../escape.txt")
    assert uploaded["filename"] == "escape.txt"
    assert client.list_files()["files"][0]["filename"] == "escape.txt"


def test_wrong_whole_file_sha_is_rejected(live_server):
    data = b"payload"
    file_id = None
    with socket.create_connection(("127.0.0.1", live_server.port), timeout=10) as sock:
        send_frame(
            sock,
            build(
                MessageType.UPLOAD_BEGIN,
                filename="bad.bin",
                size=len(data),
                sha256="0" * 64,
                chunk_size=1024 * 1024,
                chunk_count=1,
                source_node="client",
            ),
        )
        ready, _ = recv_frame(sock)
        file_id = ready["file_id"]
        send_frame(
            sock,
            build(
                MessageType.CHUNK,
                file_id=file_id,
                index=0,
                size=len(data),
                sha256=sha256_bytes(data),
            ),
            data,
        )
        response, _ = recv_frame(sock)

    assert response["type"] == MessageType.ERROR
    assert response["code"] == ErrorCode.CHECKSUM_MISMATCH
    assert live_server.app.metadata.get_file(file_id, include_incomplete=True) is None
    assert not ChunkStorage(live_server.app.data_dir).final_dir(file_id).exists()


def test_bad_chunk_sha_is_rejected(live_server):
    data = b"payload"
    with socket.create_connection(
        ("127.0.0.1", live_server.port), timeout=10
    ) as sock:
        send_frame(
            sock,
            build(
                MessageType.UPLOAD_BEGIN,
                filename="bad-chunk.bin",
                size=len(data),
                sha256=sha256_bytes(data),
                chunk_size=1024 * 1024,
                chunk_count=1,
                source_node="client",
            ),
        )
        ready, _ = recv_frame(sock)
        send_frame(
            sock,
            build(
                MessageType.CHUNK,
                file_id=ready["file_id"],
                index=0,
                size=len(data),
                sha256="f" * 64,
            ),
            data,
        )
        response, _ = recv_frame(sock)

    assert response["type"] == MessageType.ERROR
    assert response["code"] == ErrorCode.CHECKSUM_MISMATCH


def test_interrupted_upload_is_cleaned_up(live_server):
    with socket.create_connection(("127.0.0.1", live_server.port), timeout=10) as sock:
        send_frame(
            sock,
            build(
                MessageType.UPLOAD_BEGIN,
                filename="interrupted.bin",
                size=1024,
                sha256="0" * 64,
                chunk_size=1024 * 1024,
                chunk_count=1,
                source_node="client",
            ),
        )
        ready, _ = recv_frame(sock)
        file_id = ready["file_id"]

    deadline = time.time() + 5
    while time.time() < deadline:
        if live_server.app.metadata.get_file(file_id, include_incomplete=True) is None:
            break
        time.sleep(0.02)
    assert live_server.app.metadata.get_file(file_id, include_incomplete=True) is None
    assert not live_server.app.storage.temp_dir(file_id).exists()


def test_server_survives_malformed_client(live_server):
    with socket.create_connection(("127.0.0.1", live_server.port), timeout=10) as sock:
        sock.sendall(b"\x00\x00\x00\x00")
    assert make_client(live_server).status_all()[0]["online"] is True
