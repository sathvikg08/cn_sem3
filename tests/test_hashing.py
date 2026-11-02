from common.hashing import sha256_bytes, sha256_file, verify_file


def test_sha256_known_vectors():
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256_bytes(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_file_matches_bytes(tmp_path):
    data = b"distributed backup test data\n" * 100_000
    path = tmp_path / "sample.bin"
    path.write_bytes(data)
    assert sha256_file(path) == sha256_bytes(data)
    assert sha256_file(path, chunk_size=7) == sha256_bytes(data)


def test_verify_file(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("hello")
    digest = sha256_file(path)
    assert verify_file(path, digest)
    assert verify_file(path, digest.upper())
    assert not verify_file(path, "0" * 64)
