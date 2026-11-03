#!/usr/bin/env bash
# Automated SDN demo: start the controller, build the Mininet topology, fail
# links, and verify rerouting + the backup app over the SDN.  Needs root.
#   sudo bash scripts/run_sdn_demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
LOG="${SDN_RECOVERY_LOG:-$ROOT/sdn_recovery_log.jsonl}"
rm -f "$LOG"

if [[ $EUID -ne 0 ]]; then echo "run as root: sudo bash $0"; exit 1; fi
command -v mn >/dev/null || { echo "Mininet not installed (apt install mininet openvswitch-switch)"; exit 1; }
"$PYTHON" -c "import os_ken" 2>/dev/null || { echo "pip install -r requirements-sdn.txt"; exit 1; }
# make sure Open vSwitch is running
if ! ovs-vsctl --timeout=2 show >/dev/null 2>&1; then
    service openvswitch-switch start 2>/dev/null || true
fi

mn -c >/dev/null 2>&1 || true
SDN_RECOVERY_LOG="$LOG" "$PYTHON" run_sdn_controller.py --port 6653 --log "$LOG" \
    >"$ROOT/sdn_controller.out" 2>&1 &
CTL_PID=$!
trap 'kill $CTL_PID 2>/dev/null || true; mn -c >/dev/null 2>&1 || true' EXIT
sleep 2
if ! kill -0 "$CTL_PID" 2>/dev/null || ! (ss -ltn 2>/dev/null | grep -q ':6653 '); then
    echo "controller failed to start (is port 6653 already in use?):"; cat "$ROOT/sdn_controller.out"; exit 1
fi

"$PYTHON" mininet_dual_path_network_topology.py --demo --app --log "$LOG"
