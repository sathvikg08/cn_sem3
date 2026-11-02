from common.chunking import (
    DEFAULT_CHUNK_SIZE,
    chunk_count,
    iter_file_chunks,
    validate_chunk_size,
    write_chunks,
)
from common.hashing import sha256_bytes, sha256_file

import pytest


def test_default_chunk_size_is_one_mebibyte():
    assert DEFAULT_CHUNK_SIZE == 1024 * 1024


@pytest.mark.parametrize(
    ("size", "expected"),
    [(0, 0), (1, 1), (1024 * 1024, 1), (1024 * 1024 + 1, 2), (3 * 1024 * 1024, 3)],
)
def test_chunk_count(size, expected):
    assert chunk_count(size) == expected


def test_invalid_chunk_sizes():
    with pytest.raises(ValueError):
        validate_chunk_size(0)
    with pytest.raises(ValueError):
        validate_chunk_size(-1)
    with pytest.raises(ValueError):
        validate_chunk_size(True)
    with pytest.raises(ValueError):
        chunk_count(-1)


def test_iter_file_chunks_exact_boundaries(tmp_path):
    data = b"a" * (2 * DEFAULT_CHUNK_SIZE)
    path = tmp_path / "exact.bin"
    path.write_bytes(data)

    chunks = list(iter_file_chunks(path))
    assert [len(c) for c in chunks] == [DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE]
    assert b"".join(chunks) == data


def test_iter_file_chunks_partial_last_chunk(tmp_path):
    data = b"0123456789" * 250_000  # 2,500,000 bytes
    path = tmp_path / "partial.bin"
    path.write_bytes(data)

    chunks = list(iter_file_chunks(path))
    assert [len(c) for c in chunks] == [
        DEFAULT_CHUNK_SIZE,
        DEFAULT_CHUNK_SIZE,
        2_500_000 - 2 * DEFAULT_CHUNK_SIZE,
    ]
    assert sha256_bytes(b"".join(chunks)) == sha256_file(path)


def test_iter_file_chunks_empty(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    assert list(iter_file_chunks(path)) == []


def test_custom_chunk_size(tmp_path):
    path = tmp_path / "custom.bin"
    path.write_bytes(b"x" * 25)
    assert [len(c) for c in iter_file_chunks(path, chunk_size=10)] == [10, 10, 5]


def test_write_chunks(tmp_path):
    destination = tmp_path / "nested" / "output.bin"
    total = write_chunks(iter([b"abc", b"def", b"ghi"]), destination)
    assert total == 9
    assert destination.read_bytes() == b"abcdefghi"
