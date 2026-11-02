import hashlib

from client.core import BackupClient
from server.replication import ReplicationWorker, Replicator
from tests.conftest import closed_port


def pair(server_factory):
    replica = server_factory("B")
    replicator = Replicator(
        ("127.0.0.1", replica.port), node_name="A", timeout=10
    )
    primary = server_factory("A", replicator=replicator)
    return primary, replica, replicator


def test_upload_to_a_replicates_to_b_and_recovers_when_a_is_down(
    server_factory, tmp_path
):
    primary, replica, _ = pair(server_factory)
    data = bytes(range(256)) * 9000  # 2.3 MB
    source = tmp_path / "important.bin"
    source.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()

    client = BackupClient([primary.endpoint], timeout=10)
    uploaded = client.upload_file(source)
    assert uploaded["node"] == "A"
    assert uploaded["replicated"] is True
    assert uploaded["replication_status"] == "replicated"
    assert uploaded["sha256"] == digest

    replica_record = replica.app.metadata.get_file(uploaded["file_id"])
    assert replica_record is not None
    assert replica_record["source_node"] == "A"
    assert replica_record["replication_status"] == "received"
    assert replica_record["sha256"] == digest
    assert len(replica.app.metadata.get_chunks(uploaded["file_id"])) == 3
    assert replica.app.storage.chunk_path(uploaded["file_id"], 0).is_file()

    # Primary goes away: the same file id must resolve from B.
    primary.stop()
    failover = BackupClient([primary.endpoint, replica.endpoint], timeout=2)
    destination = tmp_path / "recovered.bin"
    restored = failover.restore_file(uploaded["file_id"], destination)
    assert restored["endpoint"] == replica.endpoint
    assert destination.read_bytes() == data
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == digest

    listed = failover.list_files()
    assert listed["endpoint"] == replica.endpoint
    assert listed["files"][0]["file_id"] == uploaded["file_id"]


def test_failed_replication_is_marked_and_retried(server_factory, tmp_path):
    unreachable = closed_port()
    replicator = Replicator(unreachable, node_name="A", timeout=1)
    primary = server_factory("A", replicator=replicator)
    source = tmp_path / "retry.txt"
    source.write_text("retry this file")

    client = BackupClient([primary.endpoint], timeout=10)
    uploaded = client.upload_file(source)
    assert uploaded["replicated"] is False
    assert uploaded["replication_status"] == "failed"

    record = primary.app.metadata.get_file(uploaded["file_id"])
    assert record is not None
    assert record["replication_status"] == "failed"
    assert record["replication_error"]

    # Replica comes online; a retry should publish the existing local copy.
    replica = server_factory("B")
    replicator.peer = ("127.0.0.1", replica.port)
    succeeded = replicator.retry_pending(primary.app.metadata, primary.app.storage)
    assert succeeded == 1

    updated = primary.app.metadata.get_file(uploaded["file_id"])
    assert updated is not None
    assert updated["replication_status"] == "replicated"
    assert updated["replicated_at"]
    assert replica.app.metadata.get_file(uploaded["file_id"]) is not None

    destination = tmp_path / "from-replica.txt"
    BackupClient([replica.endpoint]).restore_file(uploaded["file_id"], destination)
    assert destination.read_text() == "retry this file"


def test_replication_is_idempotent(server_factory, tmp_path):
    primary, replica, replicator = pair(server_factory)
    source = tmp_path / "twice.txt"
    source.write_text("only once")
    uploaded = BackupClient([primary.endpoint]).upload_file(source)

    record = primary.app.metadata.get_file(uploaded["file_id"])
    assert record is not None
    chunks = primary.app.metadata.get_chunks(uploaded["file_id"])
    result = replicator.replicate(record, chunks, primary.app.storage)
    assert result["file_id"] == uploaded["file_id"]

    replica_files = replica.app.metadata.list_files()
    assert [item["file_id"] for item in replica_files] == [uploaded["file_id"]]
    again = replicator.retry_pending(primary.app.metadata, primary.app.storage)
    assert again == 0


def test_replication_worker_retries_in_background(server_factory, tmp_path):
    import time

    unreachable = closed_port()
    replicator = Replicator(unreachable, node_name="A", timeout=1)
    primary = server_factory("A", replicator=replicator)
    source = tmp_path / "background.txt"
    source.write_text("background retry")
    uploaded = BackupClient([primary.endpoint]).upload_file(source)
    assert uploaded["replication_status"] == "failed"

    replica = server_factory("B")
    replicator.peer = ("127.0.0.1", replica.port)
    worker = ReplicationWorker(
        replicator,
        primary.app.metadata,
        primary.app.storage,
        interval=0.05,
    ).start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            record = primary.app.metadata.get_file(uploaded["file_id"])
            if record and record["replication_status"] == "replicated":
                break
            time.sleep(0.05)
    finally:
        worker.stop()

    assert primary.app.metadata.get_file(uploaded["file_id"])["replication_status"] == (
        "replicated"
    )
    assert replica.app.metadata.get_file(uploaded["file_id"]) is not None
