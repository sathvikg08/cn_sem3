"""SHA-256 helpers shared by the client, server, and replication paths."""

from __future__ import annotations

import hashlib
import os

DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str], chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> str:
    """Return the lowercase hex SHA-256 digest of a file's contents."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def verify_file(path: str | os.PathLike[str], expected_sha256: str) -> bool:
    """Return True when the file's SHA-256 matches ``expected_sha256``."""
    return sha256_file(path) == expected_sha256.lower()
