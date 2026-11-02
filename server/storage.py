"""On-disk chunk storage with SHA-256 verification.

Layout::

    <root>/chunks/<file_id>/<index>.chunk
    <root>/tmp/<file_id>/<index>.part      (in-progress uploads)

Chunks are staged in ``tmp`` and moved into ``chunks`` only after the whole
file's size and SHA-256 have been verified.  Restores are written to a sibling
temporary file and atomically renamed after verification.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Iterator

FILE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class StorageError(Exception):
    """Base class for storage failures."""


class ChecksumError(StorageError):
    """A chunk or whole-file SHA-256 did not match metadata."""


class MissingChunkError(StorageError):
    """A chunk file expected from metadata is absent."""


def validate_file_id(file_id: str) -> str:
    if not isinstance(file_id, str) or not FILE_ID_PATTERN.fullmatch(file_id):
        raise ValueError(f"invalid file id: {file_id!r}")
    return file_id


class ChunkStorage:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.chunks_root = self.root / "chunks"
        self.tmp_root = self.root / "tmp"
        self.chunks_root.mkdir(parents=True, exist_ok=True)
        self.tmp_root.mkdir(parents=True, exist_ok=True)

    def _validate(self, file_id: str) -> str:
        return validate_file_id(file_id)

    def final_dir(self, file_id: str) -> Path:
        return self.chunks_root / self._validate(file_id)

    def temp_dir(self, file_id: str) -> Path:
        return self.tmp_root / self._validate(file_id)

    def chunk_path(self, file_id: str, index: int) -> Path:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError(f"invalid chunk index: {index!r}")
        return self.final_dir(file_id) / f"{index}.chunk"

    def save_chunk(self, file_id: str, index: int, data: bytes) -> str:
        """Stage a chunk and return its SHA-256."""
        directory = self.temp_dir(file_id)
        directory.mkdir(parents=True, exist_ok=True)
        final_path = directory / f"{index}.chunk"
        partial_path = directory / f".{index}.part"
        partial_path.write_bytes(data)
        os.replace(partial_path, final_path)
        return hashlib.sha256(data).hexdigest()

    def temp_chunk_path(self, file_id: str, index: int) -> Path:
        return self.temp_dir(file_id) / f"{index}.chunk"

    def finalize_upload(
        self,
        file_id: str,
        chunks: list[dict[str, Any]],
        *,
        expected_size: int,
        expected_sha256: str,
    ) -> str:
        """Verify staged chunks, then publish them atomically.

        ``chunks`` must contain contiguous indices ``0..len-1``.  Returns the
        verified whole-file SHA-256.  On any failure the upload is cleaned up.
        """
        self._validate(file_id)
        expected_sha256 = expected_sha256.lower()
        ordered = sorted(chunks, key=lambda chunk: chunk["idx"])
        if [chunk["idx"] for chunk in ordered] != list(range(len(ordered))):
            self.abort_upload(file_id)
            raise StorageError("chunk indices are not contiguous")

        whole = hashlib.sha256()
        total = 0
        try:
            for chunk in ordered:
                path = self.temp_chunk_path(file_id, chunk["idx"])
                if not path.is_file():
                    raise MissingChunkError(f"missing chunk {chunk['idx']} for {file_id}")
                data = path.read_bytes()
                if len(data) != chunk["size"]:
                    raise ChecksumError(
                        f"chunk {chunk['idx']} size mismatch: "
                        f"{len(data)} != {chunk['size']}"
                    )
                if hashlib.sha256(data).hexdigest() != chunk["sha256"].lower():
                    raise ChecksumError(f"chunk {chunk['idx']} checksum mismatch")
                whole.update(data)
                total += len(data)

            if total != expected_size:
                raise ChecksumError(f"file size mismatch: {total} != {expected_size}")
            digest = whole.hexdigest()
            if digest != expected_sha256:
                raise ChecksumError("whole-file checksum mismatch")

            final_dir = self.final_dir(file_id)
            if final_dir.exists():
                shutil.rmtree(final_dir)
            final_dir.mkdir(parents=True, exist_ok=True)
            for chunk in ordered:
                source = self.temp_chunk_path(file_id, chunk["idx"])
                os.replace(source, final_dir / f"{chunk['idx']}.chunk")
            shutil.rmtree(self.temp_dir(file_id), ignore_errors=True)
            return digest
        except Exception:
            self.abort_upload(file_id)
            raise

    def iter_chunks(
        self, file_id: str, chunks: list[dict[str, Any]]
    ) -> Iterator[bytes]:
        """Yield verified chunk bytes in index order."""
        ordered = sorted(chunks, key=lambda chunk: chunk["idx"])
        if [chunk["idx"] for chunk in ordered] != list(range(len(ordered))):
            raise StorageError("chunk indices are not contiguous")
        for chunk in ordered:
            path = self.chunk_path(file_id, chunk["idx"])
            if not path.is_file():
                raise MissingChunkError(f"missing chunk {chunk['idx']} for {file_id}")
            data = path.read_bytes()
            if len(data) != chunk["size"]:
                raise ChecksumError(f"chunk {chunk['idx']} size mismatch")
            if hashlib.sha256(data).hexdigest() != chunk["sha256"].lower():
                raise ChecksumError(f"chunk {chunk['idx']} checksum mismatch")
            yield data

    def restore_file(
        self,
        file_id: str,
        chunks: list[dict[str, Any]],
        destination: str | Path,
        *,
        expected_size: int,
        expected_sha256: str,
    ) -> dict[str, Any]:
        """Reassemble a file at ``destination`` after verification."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(destination)
        temporary = destination.with_name(
            f".{destination.name}.{uuid.uuid4().hex}.part"
        )
        whole = hashlib.sha256()
        total = 0
        try:
            with open(temporary, "wb") as handle:
                for data in self.iter_chunks(file_id, chunks):
                    handle.write(data)
                    whole.update(data)
                    total += len(data)
            if total != expected_size:
                raise ChecksumError(f"restored size mismatch: {total} != {expected_size}")
            digest = whole.hexdigest()
            if digest != expected_sha256.lower():
                raise ChecksumError("restored whole-file checksum mismatch")
            os.replace(temporary, destination)
            return {"size": total, "sha256": digest, "path": str(destination)}
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def abort_upload(self, file_id: str) -> None:
        self._validate(file_id)
        shutil.rmtree(self.temp_dir(file_id), ignore_errors=True)
        shutil.rmtree(self.final_dir(file_id), ignore_errors=True)

    def delete_file(self, file_id: str) -> None:
        self.abort_upload(file_id)
