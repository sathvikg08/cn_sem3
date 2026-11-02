import hashlib
import uuid

import pytest

from server.storage import (
    ChecksumError,
    ChunkStorage,
    MissingChunkError,
    StorageError,
    validate_file_id,
)


def chunk_records(chunks: list[bytes]) -> list[dict]:
    return [
        {"idx": index, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for index, data in enumerate(chunks)
    ]


def stage(storage: ChunkStorage, file_id: str, chunks: list[bytes]) -> list[dict]:
    for index, data in enumerate(chunks):
        storage.save_chunk(file_id, index, data)
    return chunk_records(chunks)


def test_stage_finalize_and_iterate(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    chunks = [b"a" * 10, b"b" * 7]
    records = stage(storage, file_id, chunks)
    digest = hashlib.sha256(b"".join(chunks)).hexdigest()

    assert storage.finalize_upload(
        file_id, records, expected_size=17, expected_sha256=digest
    ) == digest
    assert list(storage.iter_chunks(file_id, records)) == chunks
    assert not storage.temp_dir(file_id).exists()
    assert storage.chunk_path(file_id, 0).is_file()


def test_restore_reassembles_and_verifies(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    chunks = [b"hello ", b"world"]
    records = stage(storage, file_id, chunks)
    digest = hashlib.sha256(b"".join(chunks)).hexdigest()
    storage.finalize_upload(file_id, records, expected_size=11, expected_sha256=digest)

    destination = tmp_path / "restored.txt"
    result = storage.restore_file(
        file_id,
        records,
        destination,
        expected_size=11,
        expected_sha256=digest,
    )
    assert destination.read_bytes() == b"hello world"
    assert result["sha256"] == digest
    assert result["size"] == 11


def test_restore_refuses_existing_destination(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"data"])
    digest = hashlib.sha256(b"data").hexdigest()
    storage.finalize_upload(file_id, records, expected_size=4, expected_sha256=digest)
    destination = tmp_path / "exists.txt"
    destination.write_text("keep me")

    with pytest.raises(FileExistsError):
        storage.restore_file(
            file_id,
            records,
            destination,
            expected_size=4,
            expected_sha256=digest,
        )
    assert destination.read_text() == "keep me"


def test_finalize_detects_chunk_tampering_and_cleans_up(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    chunks = [b"good", b"data"]
    records = stage(storage, file_id, chunks)
    storage.temp_chunk_path(file_id, 0).write_bytes(b"evil")

    with pytest.raises(ChecksumError):
        storage.finalize_upload(
            file_id,
            records,
            expected_size=8,
            expected_sha256=hashlib.sha256(b"evil data").hexdigest(),
        )
    assert not storage.temp_dir(file_id).exists()
    assert not storage.final_dir(file_id).exists()


def test_finalize_detects_whole_file_mismatch(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"hello"])

    with pytest.raises(ChecksumError, match="whole-file"):
        storage.finalize_upload(
            file_id, records, expected_size=5, expected_sha256="0" * 64
        )
    assert not storage.final_dir(file_id).exists()


def test_finalize_detects_size_mismatch(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"hello"])

    with pytest.raises(ChecksumError, match="size mismatch"):
        storage.finalize_upload(
            file_id,
            records,
            expected_size=6,
            expected_sha256=hashlib.sha256(b"hello").hexdigest(),
        )


def test_finalize_requires_contiguous_indices(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    storage.save_chunk(file_id, 1, b"only")
    records = [{"idx": 1, "size": 4, "sha256": hashlib.sha256(b"only").hexdigest()}]

    with pytest.raises(StorageError, match="contiguous"):
        storage.finalize_upload(
            file_id, records, expected_size=4, expected_sha256=hashlib.sha256(b"only").hexdigest()
        )


def test_missing_temp_chunk_detected(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    storage.temp_dir(file_id).mkdir(parents=True)
    records = [{"idx": 0, "size": 4, "sha256": "0" * 64}]

    with pytest.raises(MissingChunkError):
        storage.finalize_upload(
            file_id, records, expected_size=4, expected_sha256="0" * 64
        )


def test_iter_detects_disk_tampering(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"abc"])
    digest = hashlib.sha256(b"abc").hexdigest()
    storage.finalize_upload(file_id, records, expected_size=3, expected_sha256=digest)
    storage.chunk_path(file_id, 0).write_bytes(b"xyz")

    with pytest.raises(ChecksumError):
        list(storage.iter_chunks(file_id, records))


def test_restore_failure_leaves_no_destination_or_temp(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"abc"])
    storage.finalize_upload(
        file_id, records, expected_size=3, expected_sha256=hashlib.sha256(b"abc").hexdigest()
    )
    destination = tmp_path / "out.bin"

    with pytest.raises(ChecksumError):
        storage.restore_file(
            file_id,
            records,
            destination,
            expected_size=3,
            expected_sha256="0" * 64,
        )
    assert not destination.exists()
    assert list(tmp_path.glob(".*.part")) == []


def test_empty_file_roundtrip(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    digest = hashlib.sha256(b"").hexdigest()
    storage.finalize_upload(file_id, [], expected_size=0, expected_sha256=digest)

    destination = tmp_path / "empty.bin"
    storage.restore_file(
        file_id, [], destination, expected_size=0, expected_sha256=digest
    )
    assert destination.read_bytes() == b""


def test_delete_removes_chunks(tmp_path):
    storage = ChunkStorage(tmp_path / "data")
    file_id = uuid.uuid4().hex
    records = stage(storage, file_id, [b"abc"])
    storage.finalize_upload(
        file_id, records, expected_size=3, expected_sha256=hashlib.sha256(b"abc").hexdigest()
    )
    storage.delete_file(file_id)
    assert not storage.final_dir(file_id).exists()


@pytest.mark.parametrize("file_id", ["../escape", "ABC", "", "0" * 31, "0" * 33])
def test_invalid_file_ids_rejected(file_id, tmp_path):
    with pytest.raises(ValueError):
        validate_file_id(file_id)
    storage = ChunkStorage(tmp_path / "data")
    with pytest.raises(ValueError):
        storage.final_dir(file_id)
