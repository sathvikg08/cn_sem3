import sqlite3

import pytest

from server.metadata import MetadataStore, new_file_id


def make_upload(store: MetadataStore, **overrides):
    fields = {
        "file_id": new_file_id(),
        "filename": "notes.txt",
        "size": 5,
        "sha256": "a" * 64,
        "chunk_size": 1024 * 1024,
        "chunk_count": 1,
        "source_node": "client",
        "replication_status": "not_applicable",
    }
    fields.update(overrides)
    return store.create_upload(**fields)


def test_create_and_complete_upload(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    record = make_upload(store)

    assert record["status"] == "uploading"
    assert len(record["file_id"]) == 32
    assert store.get_file(record["file_id"]) is None

    store.add_chunk(record["file_id"], 0, 5, "b" * 64)
    store.complete_upload(record["file_id"], "not_applicable")

    complete = store.get_file(record["file_id"])
    assert complete is not None
    assert complete["status"] == "complete"
    assert complete["completed_at"]
    assert store.get_chunks(record["file_id"]) == [
        {"idx": 0, "size": 5, "sha256": "b" * 64}
    ]


def test_list_and_stats_only_include_complete_files(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    first = make_upload(store, filename="one.txt", size=10)
    second = make_upload(store, filename="two.txt", size=20)
    make_upload(store, filename="in-progress.txt", size=30)
    store.complete_upload(first["file_id"], "not_applicable")
    store.complete_upload(second["file_id"], "not_applicable")

    names = [item["filename"] for item in store.list_files()]
    assert names == ["one.txt", "two.txt"]
    assert store.stats() == {"file_count": 2, "total_bytes": 30}


def test_abort_upload_removes_metadata_and_chunks(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    record = make_upload(store)
    store.add_chunk(record["file_id"], 0, 5, "b" * 64)

    assert store.abort_upload(record["file_id"])
    assert store.get_file(record["file_id"], include_incomplete=True) is None
    assert store.get_chunks(record["file_id"]) == []
    assert not store.abort_upload(record["file_id"])


def test_delete_file_cascades_chunks(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    record = make_upload(store)
    store.add_chunk(record["file_id"], 0, 5, "b" * 64)
    store.complete_upload(record["file_id"], "not_applicable")

    assert store.delete_file(record["file_id"])
    assert store.get_file(record["file_id"]) is None
    assert store.get_chunks(record["file_id"]) == []
    assert not store.delete_file(record["file_id"])


def test_delete_refuses_incomplete_file(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    record = make_upload(store)
    assert not store.delete_file(record["file_id"])
    assert store.get_file(record["file_id"], include_incomplete=True) is not None


def test_replication_status_and_pending(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    pending = make_upload(store, source_node="client", replication_status="pending")
    received = make_upload(store, source_node="A", replication_status="received")
    local = make_upload(store, source_node="client", replication_status="not_applicable")
    for record in (pending, received, local):
        store.complete_upload(record["file_id"], record["replication_status"])

    assert [item["file_id"] for item in store.pending_replication()] == [
        pending["file_id"]
    ]

    store.set_replication_status(pending["file_id"], "replicated", replicated_at="now")
    assert store.pending_replication() == []
    updated = store.get_file(pending["file_id"])
    assert updated is not None
    assert updated["replication_status"] == "replicated"
    assert updated["replicated_at"] == "now"

    store.set_replication_status(pending["file_id"], "failed", error="offline")
    failed = store.pending_replication()
    assert len(failed) == 1
    assert failed[0]["replication_error"] == "offline"


def test_invalid_replication_status_rejected(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    with pytest.raises(ValueError):
        make_upload(store, replication_status="bogus")


def test_duplicate_file_id_rejected(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    record = make_upload(store)
    with pytest.raises(sqlite3.IntegrityError):
        make_upload(store, file_id=record["file_id"])


def test_unknown_file_updates_raise(tmp_path):
    store = MetadataStore(tmp_path / "metadata.db")
    with pytest.raises(KeyError):
        store.set_replication_status("0" * 32, "replicated")
    with pytest.raises(KeyError):
        store.complete_upload("0" * 32, "not_applicable")


def test_new_file_id_is_valid_hex():
    file_id = new_file_id()
    assert len(file_id) == 32
    int(file_id, 16)
