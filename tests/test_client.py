import pytest

from client.core import BackupClient, BackupError, parse_endpoint, servers_from_env
from tests.conftest import closed_port, make_client


def test_upload_falls_back_to_second_server(server_factory, tmp_path):
    server = server_factory("B")
    dead = closed_port()
    client = BackupClient([dead, server.endpoint], timeout=2)
    source = tmp_path / "fallback.txt"
    source.write_text("survives an offline primary")

    uploaded = client.upload_file(source)
    assert uploaded["endpoint"] == server.endpoint
    assert uploaded["node"] == "B"
    assert client.status_all()[0]["online"] is False

    destination = tmp_path / "restored.txt"
    client.restore_file(uploaded["file_id"], destination)
    assert destination.read_text() == "survives an offline primary"


def test_list_falls_back(server_factory, tmp_path):
    server = server_factory("B")
    source = tmp_path / "listed.txt"
    source.write_text("data")
    make_client(server).upload_file(source)

    client = BackupClient([closed_port(), server.endpoint], timeout=2)
    result = client.list_files()
    assert result["endpoint"] == server.endpoint
    assert [item["filename"] for item in result["files"]] == ["listed.txt"]


def test_all_servers_offline_reports_error(tmp_path):
    client = BackupClient([closed_port()], timeout=1)
    source = tmp_path / "x.txt"
    source.write_text("x")
    with pytest.raises(BackupError, match="every server"):
        client.upload_file(source)
    with pytest.raises(BackupError, match="any server"):
        client.list_files()


def test_parse_endpoint_and_env(monkeypatch):
    assert parse_endpoint("10.0.0.1:9101") == ("10.0.0.1", 9101)
    assert parse_endpoint(("localhost", 9000)) == ("localhost", 9000)
    with pytest.raises(ValueError):
        parse_endpoint("localhost")
    with pytest.raises(ValueError):
        parse_endpoint("localhost:not-a-port")
    with pytest.raises(ValueError):
        parse_endpoint("localhost:70000")

    monkeypatch.setenv("BACKUP_SERVERS", "127.0.0.1:1, 127.0.0.1:2")
    assert servers_from_env() == [("127.0.0.1", 1), ("127.0.0.1", 2)]
    monkeypatch.delenv("BACKUP_SERVERS")
    assert len(servers_from_env()) == 2
