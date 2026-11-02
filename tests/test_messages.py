import pytest

from common.messages import (
    REQUIRED_FIELDS,
    ErrorCode,
    MessageType,
    build,
    error,
    validate,
)


def test_all_message_types_have_schemas():
    constants = {
        value
        for name, value in vars(MessageType).items()
        if name.isupper() and isinstance(value, str)
    }
    assert constants == set(REQUIRED_FIELDS)


def test_build_and_validate():
    message = build(
        MessageType.UPLOAD_BEGIN,
        filename="report.bin",
        size=10,
        sha256="a" * 64,
        chunk_size=1024 * 1024,
        chunk_count=1,
        source_node="client",
    )
    assert message["type"] == MessageType.UPLOAD_BEGIN
    assert validate(message, MessageType.UPLOAD_BEGIN) is message


def test_build_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing required fields"):
        build(MessageType.DOWNLOAD)


def test_build_rejects_unknown_type():
    with pytest.raises(ValueError, match="unknown message type"):
        build("NOPE")


def test_validate_rejects_wrong_expected_type():
    message = build(MessageType.PING)
    with pytest.raises(ValueError, match="expected"):
        validate(message, MessageType.PONG)


def test_validate_accepts_multiple_expected_types():
    message = build(MessageType.PONG, node="A", file_count=0, total_bytes=0)
    assert validate(message, {MessageType.PONG, MessageType.ERROR}) is message


def test_validate_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing required fields"):
        validate({"type": MessageType.UPLOAD_READY, "file_id": "x"})


def test_validate_rejects_non_dict():
    with pytest.raises(ValueError):
        validate(["not", "a", "dict"])


def test_error_helper():
    message = error(ErrorCode.FILE_NOT_FOUND, "missing", file_id="abc")
    assert message == {
        "type": MessageType.ERROR,
        "code": ErrorCode.FILE_NOT_FOUND,
        "message": "missing",
        "file_id": "abc",
    }
