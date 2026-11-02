"""Run a backup server.

Examples:
    python -m server --node A --port 9101 --data-dir data/server-a \
        --peer 127.0.0.1:9102
    python -m server --node B --port 9102 --data-dir data/server-b
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from server.app import BackupServer
from server.replication import ReplicationWorker, Replicator


def parse_peer(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("peer must be host:port")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("peer port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("peer port out of range")
    return host, port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Distributed backup server")
    parser.add_argument("--node", default="A", help="node name (A or B)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address")
    parser.add_argument("--port", type=int, default=9101, help="bind port (0 = ephemeral)")
    parser.add_argument(
        "--data-dir", default="data/server-a", help="metadata and chunk directory"
    )
    parser.add_argument(
        "--peer",
        type=parse_peer,
        default=None,
        help="replica server host:port (normally Server B for node A)",
    )
    parser.add_argument(
        "--replication-retry-interval",
        type=float,
        default=30.0,
        help="seconds between retries of failed replication (0 disables)",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=120.0,
        help="per-connection socket timeout in seconds",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    replicator = None
    if args.peer is not None:
        replicator = Replicator(args.peer, node_name=args.node, timeout=args.request_timeout)

    server = BackupServer(
        data_dir=args.data_dir,
        host=args.host,
        port=args.port,
        node_name=args.node,
        replicator=replicator,
        request_timeout=args.request_timeout,
    )
    server.start()

    worker = None
    if replicator is not None and args.replication_retry_interval > 0:
        worker = ReplicationWorker(
            replicator,
            server.app.metadata,
            server.app.storage,
            interval=args.replication_retry_interval,
        ).start()

    stop = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    print(f"Backup Server {server.node_name} listening on {server.endpoint}", flush=True)
    print(f"Data directory: {server.app.data_dir}", flush=True)
    if replicator is not None:
        print(f"Replicating to: {replicator.peer_label}", flush=True)

    try:
        while not stop.wait(0.5):
            pass
    finally:
        if worker is not None:
            worker.stop()
        server.stop()
        print("Server stopped.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
