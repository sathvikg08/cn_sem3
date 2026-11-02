"""File chunking utilities.  The default chunk size is 1 MiB."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

DEFAULT_CHUNK_SIZE = 1024 * 1024


def validate_chunk_size(chunk_size: int) -> int:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise ValueError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return chunk_size


def chunk_count(size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Number of chunks needed for a payload of ``size`` bytes."""
    if size < 0:
        raise ValueError("size must be non-negative")
    validate_chunk_size(chunk_size)
    return (size + chunk_size - 1) // chunk_size


def iter_file_chunks(
    path: str | os.PathLike[str], chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Iterator[bytes]:
    """Yield a file's contents in chunks of at most ``chunk_size`` bytes."""
    validate_chunk_size(chunk_size)
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            yield block


def write_chunks(
    chunks: Iterator[bytes], destination: str | os.PathLike[str]
) -> int:
    """Write chunks sequentially to ``destination`` and return bytes written."""
    total = 0
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "wb") as handle:
        for block in chunks:
            handle.write(block)
            total += len(block)
    return total
