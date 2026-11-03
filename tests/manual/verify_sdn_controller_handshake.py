"""Root-free OpenFlow handshake check for ``sdn_backup_controller``.

This is a manual integration check, not part of the default pytest suite.
It starts the OS-Ken controller on a free localhost port, attaches a fake
OpenFlow 1.3 switch, sends one ARP packet-in, and verifies from the controller
log that switch, port and host discovery happened.  It needs neither Mininet
nor Open vSwitch nor root privileges.

Run it from the repository root with the OS-Ken virtualenv:

    .venv-sdn/bin/python tests/manual/verify_sdn_controller_handshake.py

Use ``--verbose`` to print the full controller log.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from os_ken.lib.packet import arp, ether_types, ethernet, packet

OFP_VERSION = 4
DPID = 1
SWITCH_IP = "127.0.0.1"
HOST_MAC = "02:00:00:00:00:01"
HOST_IP = "10.0.0.1"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind((SWITCH_IP, 0))
        return sock.getsockname()[1]


def ofp_header(msg_type: int, body: bytes, xid: int) -> bytes:
    return struct.pack("!BBHI", OFP_VERSION, msg_type, 8 + len(body), xid) + body


def switch_features() -> bytes:
    body = struct.pack("!QIBB2xII", DPID, 256, 254, 0, 0, 0)
    return ofp_header(6, body, 1)


def port_description(port_no: int) -> bytes:
    return struct.pack(
        "!I4x6s2x16sIIIIIIII",
        port_no,
        b"\x02\x00\x00\x00\x00" + bytes([port_no]),
        f"s1-eth{port_no}".encode().ljust(16, b"\x00"),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )


def port_desc_reply(count: int = 4) -> bytes:
    ports = b"".join(port_description(index) for index in range(1, count + 1))
    body = struct.pack("!HH4x", 13, 0) + ports
    return ofp_header(19, body, 2)


def arp_request() -> bytes:
    pkt = packet.Packet()
    pkt.add_protocol(
        ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src=HOST_MAC,
            ethertype=ether_types.ETH_TYPE_ARP,
        )
    )
    pkt.add_protocol(
        arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=HOST_MAC,
            src_ip=HOST_IP,
            dst_mac="00:00:00:00:00:00",
            dst_ip="10.0.0.2",
        )
    )
    pkt.serialize()
    return bytes(pkt.data)


def packet_in() -> bytes:
    data = arp_request()
    match = (
        struct.pack("!HH", 1, 12)
        + struct.pack("!HBB", 0x8000, 0, 4)
        + struct.pack("!I", 1)
    )
    match += b"\x00" * (8 - len(match) % 8)
    fixed = struct.pack("!IHBBQ", 0xFFFFFFFF, len(data), 0, 0, 0)
    body = fixed + match + b"\x00\x00" + data
    return ofp_header(10, body, 3)


def wait_for_listener(port: int, proc: subprocess.Popen, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"controller exited with status {proc.returncode}")
        sock = socket.socket()
        sock.settimeout(1.0)
        try:
            sock.connect((SWITCH_IP, port))
            return sock
        except OSError:
            sock.close()
            time.sleep(0.2)
    raise RuntimeError("controller did not listen before the timeout")


def run(timeout: float, verbose: bool) -> int:
    root = Path(__file__).resolve().parents[2]
    port = free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root)

    command = [
        sys.executable,
        "-u",
        "-m",
        "os_ken.cmd.manager",
        "--verbose",
        "--ofp-tcp-listen-port",
        str(port),
        "sdn_backup_controller",
    ]

    log_path = Path(tempfile.gettempdir()) / "sdn-controller-handshake.log"
    proc: subprocess.Popen | None = None
    sock: socket.socket | None = None
    try:
        with log_path.open("wb") as log_file:
            proc = subprocess.Popen(
                command,
                cwd=str(root),
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            print(f"controller pid={proc.pid} port={port}")
            sock = wait_for_listener(port, proc, timeout)

            sock.sendall(ofp_header(0, b"", 0))
            time.sleep(0.3)
            sock.sendall(switch_features())
            time.sleep(0.3)
            sock.sendall(port_desc_reply())
            time.sleep(0.5)
            sock.sendall(packet_in())
            time.sleep(1.0)
    finally:
        if sock is not None:
            sock.close()
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)

    text = log_path.read_text(errors="replace")
    if verbose:
        print("---- controller log ----")
        print(text)

    expected = {
        "switch features": "event=SWITCH_FEATURES",
        "switch enter": "event=SWITCH_ENTER",
        "port discovery": "event=SWITCH_PORTS",
        "host learning": f"event=HOST_LEARN mac={HOST_MAC}",
        "host address": f"ip={HOST_IP}",
    }
    failed = False
    print("---- checks ----")
    for label, marker in expected.items():
        ok = marker in text
        failed = failed or not ok
        print(f"{label}: {'OK' if ok else 'MISSING'} ({marker})")

    if f"port=1" not in text:
        print("host learning on port 1: MISSING")
        failed = True

    print(f"log: {log_path}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="seconds to wait for the controller to listen (default: 10)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print the full controller log",
    )
    args = parser.parse_args()
    return run(args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
