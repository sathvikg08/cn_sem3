# AGENTS.md

## Project

Distributed backup system that runs over ordinary TCP endpoints and is intended
to be placed on an SDN topology later.

Application scope owned here: client, TCP file transfer, backup servers,
chunking, replication, and file restoration.

SDN scope is owned by a separate teammate (Mininet, Open vSwitch, OpenFlow,
OS-Ken controller). Do not implement or redesign the SDN module, and do not add
those packages to `requirements.txt`.

## Stack

- Python 3 (runtime uses only the standard library)
- TCP sockets; length-prefixed JSON control messages with raw binary chunk payloads
- 1 MiB default chunk size; SHA-256 per chunk and per file
- SQLite for backup and chunk metadata
- pytest for tests

## Layout

- `client/` — `BackupClient` failover API and CLI (`python -m client`)
- `common/` — framing, message schema, chunking, hashing, shared upload handshake
- `server/` — server application, SQLite metadata, chunk storage, replication
- `tests/` — pytest unit and localhost integration tests

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m pytest                                      # full suite
python -m pytest tests/test_replication.py -q         # one file
python -m pytest tests/test_chunking.py::test_default_chunk_size_is_one_mebibyte -q

# Two servers (A replicates to B)
python -m server --node B --port 9102 --data-dir data/server-b
python -m server --node A --port 9101 --data-dir data/server-a --peer 127.0.0.1:9102

# Client (defaults to 127.0.0.1:9101 then 127.0.0.1:9102)
python -m client status
python -m client upload ./file.bin
python -m client list
python -m client restore <file-id> ./restored.bin
python -m client delete <file-id>
```

`BACKUP_SERVERS` or repeatable `--server host:port` override client endpoints.
Use `--json` on any client command for machine-readable output.

## Invariants

- Add every wire message and its required fields to
  `common/messages.REQUIRED_FIELDS`; use `messages.build` / `messages.validate`
  instead of ad-hoc dicts.
- Keep framing in `common/protocol.py` unchanged in shape: 4-byte big-endian
  JSON-header length, JSON header, then `payload_length` raw bytes.
- The client sends chunks; the server stages them in `tmp/`, verifies size and
  SHA-256, then publishes to `chunks/<file_id>/`. Never acknowledge before
  whole-file verification.
- Replication reuses the origin `file_id` on B so restore-by-id survives A
  going down. Replication is synchronous on upload; failures are recorded as
  `failed` and retried by `ReplicationWorker`.
- Client failover order is configured endpoints in order. Restore falls back on
  connection failure or `FILE_NOT_FOUND`; upload falls back on connection
  failure. Do not silently fall back on a checksum failure.
- Store all SQL in `server/metadata.py`; do not put SQL in the server app or CLI.
- Keep chunk size configurable through `BackupClient(chunk_size=...)`; 1 MiB is
  the default and the documented behavior.
- Tests use `tests/conftest.py` fixtures with port `0` and `tmp_path`. They must
  stay root-free and must not require Mininet/OVS.
- Application code must not import Mininet/OVS/OS-Ken or hard-code topology
  addresses.
