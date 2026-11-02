#!/usr/bin/env bash
# End-to-end demo: start A and B, upload to A, stop A, restore from B.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="python3"
fi

PORT_A="${PORT_A:-19101}"
PORT_B="${PORT_B:-19102}"
DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/backup-demo.XXXXXX")"
A_PID=""
B_PID=""

cleanup() {
    [[ -n "$A_PID" ]] && kill "$A_PID" 2>/dev/null || true
    [[ -n "$B_PID" ]] && kill "$B_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local port="$1"
    "$PYTHON" - "$port" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit(f"server on port {port} did not start")
PY
}

echo "== Demo directory: $DEMO_DIR =="
echo
echo "== Starting Server B (replica) on $PORT_B =="
"$PYTHON" -m server --node B --port "$PORT_B" --data-dir "$DEMO_DIR/server-b" \
    --log-level WARNING >"$DEMO_DIR/server-b.log" 2>&1 &
B_PID=$!
wait_for_port "$PORT_B"

echo "== Starting Server A (primary) on $PORT_A, replicating to B =="
"$PYTHON" -m server --node A --port "$PORT_A" --data-dir "$DEMO_DIR/server-a" \
    --peer "127.0.0.1:$PORT_B" --replication-retry-interval 2 \
    --log-level WARNING >"$DEMO_DIR/server-a.log" 2>&1 &
A_PID=$!
wait_for_port "$PORT_A"

"$PYTHON" - "$DEMO_DIR/source.bin" <<'PY'
import os
import sys

with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(2 * 1024 * 1024 + 12345))
PY
SOURCE_SUM="$(sha256sum "$DEMO_DIR/source.bin" | cut -d' ' -f1)"
echo "Source: $DEMO_DIR/source.bin ($(stat -c%s "$DEMO_DIR/source.bin") bytes)"
echo "Source SHA-256: $SOURCE_SUM"
echo

echo "== Client status before upload =="
"$PYTHON" -m client status --server "127.0.0.1:$PORT_A" \
    --server "127.0.0.1:$PORT_B" --json
echo

echo "== Upload to A (client uses A first) =="
"$PYTHON" -m client upload "$DEMO_DIR/source.bin" \
    --server "127.0.0.1:$PORT_A" --server "127.0.0.1:$PORT_B" \
    --json | tee "$DEMO_DIR/upload.json"
FILE_ID="$("$PYTHON" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["file_id"])' \
    "$DEMO_DIR/upload.json")"
echo

echo "== Verify B holds the replicated copy under the same file id =="
"$PYTHON" -m client list --server "127.0.0.1:$PORT_B" --json \
    | tee "$DEMO_DIR/b-list.json"
"$PYTHON" - "$DEMO_DIR/b-list.json" "$FILE_ID" <<'PY'
import json
import sys

listed = json.load(open(sys.argv[1]))
ids = [item["file_id"] for item in listed["files"]]
assert sys.argv[2] in ids, f"{sys.argv[2]} not replicated to B: {ids}"
print(f"B contains file id {sys.argv[2]}")
PY
echo

echo "== Stop Server A to simulate primary failure =="
kill -TERM "$A_PID"
wait "$A_PID" 2>/dev/null || true
A_PID=""
echo "Server A stopped."
echo

echo "== Client status with A unavailable =="
"$PYTHON" -m client status --server "127.0.0.1:$PORT_A" \
    --server "127.0.0.1:$PORT_B" --json
echo

echo "== Restore with A unavailable; client must fall back to B =="
"$PYTHON" -m client restore "$FILE_ID" "$DEMO_DIR/restored.bin" \
    --server "127.0.0.1:$PORT_A" --server "127.0.0.1:$PORT_B" \
    --json | tee "$DEMO_DIR/restore.json"

RESTORED_SUM="$(sha256sum "$DEMO_DIR/restored.bin" | cut -d' ' -f1)"
echo
echo "Restored SHA-256: $RESTORED_SUM"
if [[ "$SOURCE_SUM" != "$RESTORED_SUM" ]]; then
    echo "MISMATCH: restored file does not match the source" >&2
    exit 1
fi
echo "SHA-256 MATCH: restored file is identical to the source."
"$PYTHON" - "$DEMO_DIR/restore.json" "$PORT_B" <<'PY'
import json
import sys

restored = json.load(open(sys.argv[1]))
assert restored["endpoint"].endswith(":" + sys.argv[2]), restored
assert restored["verified"] is True
print(f"Restore came from {restored['endpoint']} and was verified.")
PY
echo
echo "== Demo complete. Artifacts kept in $DEMO_DIR. =="
