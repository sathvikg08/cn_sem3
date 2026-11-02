# Distributed Backup System

A distributed backup application with a TCP client, two independent backup
servers, 1 MiB file chunking, SHA-256 integrity checks, SQLite metadata,
server-to-server replication, and automatic client failover.

The SDN layer (Mininet, Open vSwitch, OpenFlow, OS-Ken) is intentionally not
implemented here. The application only uses configurable TCP endpoints so it can
run over an SDN topology later.

## Features

- TCP client and two standalone backup servers (`A` and `B`)
- 4-byte length-prefixed JSON control messages with optional raw binary payloads
- 1 MiB chunks by default, uploaded and stored separately
- Per-chunk and whole-file SHA-256 verification
- SQLite metadata for files, chunks, and replication state
- Synchronous A -> B replication with automatic retry of failed replicas
- Restore fallback: if A is unreachable or lacks the file, the client tries B
- Verification of every chunk and the final file during restoration
- CLI for upload, restore, list, delete, and status
- pytest suite using real localhost TCP servers

## Requirements

- Python 3.10 or newer (tested on Python 3.14)
- No runtime third-party dependencies
- pytest for the test suite

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Server A and Server B

Terminal 1 (replica):

```bash
python -m server --node B --port 9102 --data-dir data/server-b
```

Terminal 2 (primary, replicates to B):

```bash
python -m server --node A --port 9101 --data-dir data/server-a \
    --peer 127.0.0.1:9102
```

Both servers are independent: each has its own SQLite database
(`metadata.db`) and `chunks/` directory. B also accepts direct client uploads.

Useful server options:

| Option | Default | Purpose |
| --- | --- | --- |
| `--node` | `A` | Node name reported by `status` |
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `9101` | Bind port (`0` picks a free port) |
| `--data-dir` | `data/server-a` | Metadata and chunk storage |
| `--peer` | none | Replica endpoint; usually B for node A |
| `--replication-retry-interval` | `30` | Seconds between failed-replication retries (`0` disables) |

## Client Usage

The client tries servers in order. Default endpoints are
`127.0.0.1:9101,127.0.0.1:9102`, and can be overridden with repeatable
`--server` flags or the `BACKUP_SERVERS` environment variable.

```bash
# Upload (A is tried first, B is the fallback)
python -m client upload ./report.pdf
python -m client upload ./report.pdf --name remote-name.pdf

# List files on the first available server
python -m client list

# Restore by file id; destination may be a file path or a directory
python -m client restore <file-id> ./restored.pdf
python -m client restore <file-id> ./restore-dir/

# Status of all configured servers
python -m client status

# Delete on every reachable server that has the file
python -m client delete <file-id>
```

Add `--json` to any command for machine-readable output. To use only one
server, pass `--server 127.0.0.1:9101`. Restoring over an existing file requires
`--overwrite`.

## Integrity and Recovery

1. The client calculates the file SHA-256 and declares size/chunk count.
2. Each chunk is sent with its own SHA-256; the server rejects a bad chunk and
   cleans up the partial upload.
3. The server stages chunks under `data/.../tmp/`, verifies the complete file's
   size and SHA-256, then moves the chunks into `chunks/<file-id>/`.
4. A replays the same file id to B. B stores it under the identical id, so a
   client can restore the same id from either server.
5. If replication fails, A keeps the local copy, records the failure, and a
   background worker retries it.
6. If A is down or returns `FILE_NOT_FOUND`, the client automatically tries B.
7. Restores are written to a temporary sibling file, every chunk and the final
   file are verified, and only then is the destination atomically replaced.

## Project Structure

```text
client/             TCP client API and CLI (python -m client)
common/             framing, message schema, chunking, hashing, upload flow
server/             TCP server, SQLite metadata, storage, replication
tests/              pytest unit and localhost integration tests
```

Key modules:

- `common/protocol.py` — frame format and socket I/O
- `common/messages.py` — every message type and required field
- `common/transfer.py` — shared upload handshake
- `server/app.py` — request dispatch and server lifecycle
- `server/metadata.py` — SQLite schema and queries
- `server/storage.py` — chunk staging, finalization, and verified restore
- `server/replication.py` — A -> B replication and retry worker
- `client/core.py` — high-level client with failover

## Tests

```bash
python -m pytest                       # full suite
python -m pytest tests/test_server.py -q
python -m pytest tests/test_replication.py -q
python -m pytest tests/test_chunking.py::test_default_chunk_size_is_one_mebibyte -q
```

All tests use ephemeral localhost ports and temporary directories. They do not
require root, Mininet, or Open vSwitch.

For a scripted, real-process demonstration (start A+B, upload to A, stop A,
restore from B, compare SHA-256):

```bash
bash scripts/e2e_demo.sh
```

## Limitations

- No frontend, authentication, or encryption; intended for a trusted lab network.
- One replica (B). There is no reverse reconciliation when B accepts an upload
  while A is offline; that file remains only on B.
- Files are stored as chunks, not as a second assembled copy, and are reassembled
  into a temporary file during restore.
- SDN integration is out of scope for this module; endpoints are configurable so
  the SDN team can place the servers on their topology.
