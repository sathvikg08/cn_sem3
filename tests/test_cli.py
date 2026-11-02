import json

from client.__main__ import main
from tests.conftest import make_client


def run_cli(capsys, *args):
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_full_workflow(live_server, tmp_path, capsys):
    source = tmp_path / "cli-source.bin"
    source.write_bytes(b"cli workflow" * 100_000)
    endpoint = live_server.endpoint

    code, out, err = run_cli(
        capsys,
        "upload",
        str(source),
        "--server",
        endpoint,
        "--json",
    )
    assert code == 0, err
    uploaded = json.loads(out)
    assert uploaded["filename"] == "cli-source.bin"
    assert uploaded["verified"] is True

    code, out, err = run_cli(capsys, "status", "--server", endpoint, "--json")
    assert code == 0, err
    statuses = json.loads(out)
    assert statuses[0]["online"] is True
    assert statuses[0]["file_count"] == 1

    code, out, err = run_cli(capsys, "list", "--server", endpoint, "--json")
    assert code == 0, err
    listed = json.loads(out)
    assert listed["files"][0]["file_id"] == uploaded["file_id"]

    destination = tmp_path / "cli-restored.bin"
    code, out, err = run_cli(
        capsys,
        "restore",
        uploaded["file_id"],
        str(destination),
        "--server",
        endpoint,
        "--json",
    )
    assert code == 0, err
    restored = json.loads(out)
    assert restored["verified"] is True
    assert destination.read_bytes() == source.read_bytes()

    code, out, err = run_cli(
        capsys,
        "delete",
        uploaded["file_id"],
        "--server",
        endpoint,
        "--json",
    )
    assert code == 0, err
    deleted = json.loads(out)
    assert deleted["deleted_on"] == [endpoint]
    assert make_client(live_server).list_files()["files"] == []


def test_cli_human_readable_output(live_server, tmp_path, capsys):
    source = tmp_path / "human.txt"
    source.write_text("human readable")
    code, out, err = run_cli(
        capsys, "upload", str(source), "--server", live_server.endpoint
    )
    assert code == 0, err
    assert "Uploaded human.txt" in out
    assert "file_id:" in out
    assert "replication:" in out


def test_cli_errors_return_nonzero(live_server, tmp_path, capsys):
    code, _out, err = run_cli(
        capsys,
        "restore",
        "0" * 32,
        str(tmp_path / "missing.bin"),
        "--server",
        live_server.endpoint,
    )
    assert code == 1
    assert "could not restore" in err

    code, _out, err = run_cli(capsys, "upload", str(tmp_path / "nope.bin"))
    assert code == 1
    assert "not a regular file" in err
