"""Command-line client.

Examples:
    python -m client status
    python -m client upload ./report.pdf
    python -m client list
    python -m client restore <file-id> ./restored.pdf
    python -m client delete <file-id>
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from client.core import (
    BackupClient,
    BackupError,
    DestinationExists,
    parse_endpoint,
    servers_from_env,
)
from common.transfer import RemoteError


def human_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server",
        action="append",
        dest="servers",
        metavar="HOST:PORT",
        help="backup server to try (repeatable; default: BACKUP_SERVERS or "
        "127.0.0.1:9101,127.0.0.1:9102)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="socket timeout")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Distributed backup client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upload = subparsers.add_parser("upload", help="upload a file")
    upload.add_argument("path")
    upload.add_argument("--name", help="filename to store on the server")
    add_common_options(upload)

    restore = subparsers.add_parser("restore", help="download and verify a file")
    restore.add_argument("file_id")
    restore.add_argument("destination", help="file path or existing directory")
    restore.add_argument(
        "--overwrite", action="store_true", help="replace an existing destination"
    )
    add_common_options(restore)

    list_cmd = subparsers.add_parser("list", help="list backed-up files")
    add_common_options(list_cmd)

    delete = subparsers.add_parser("delete", help="delete a file on all reachable servers")
    delete.add_argument("file_id")
    add_common_options(delete)

    status = subparsers.add_parser("status", help="show server status")
    add_common_options(status)

    return parser


def make_client(args: argparse.Namespace) -> BackupClient:
    servers = (
        [parse_endpoint(value) for value in args.servers]
        if args.servers
        else servers_from_env()
    )
    return BackupClient(servers, timeout=args.timeout)


def print_upload(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    replicated = result.get("replicated")
    print(f"Uploaded {result['filename']}")
    print(f"  file_id:     {result['file_id']}")
    print(f"  size:        {human_bytes(result['size'])}")
    print(f"  sha256:      {result['sha256']}")
    print(f"  server:      {result.get('node') or '?'} ({result['endpoint']})")
    if replicated is True:
        print("  replication: copied to peer server")
    elif result.get("replication_status") == "failed":
        print(f"  replication: FAILED ({result.get('replication_error', 'unknown')})")
    elif result.get("replication_status") == "received":
        print("  replication: this server holds the replica")
    else:
        print("  replication: not configured")


def print_restore(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print(f"Restored {result['path']}")
    print(f"  file_id:  {result['file_id']}")
    print(f"  size:     {human_bytes(result['size'])}")
    print(f"  sha256:   {result['sha256']} (verified)")
    node = result.get("node") or "?"
    print(f"  server:   {node} ({result['endpoint']})")


def print_list(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    node = result.get("node") or "?"
    print(f"Files on {node} ({result['endpoint']}): {len(result['files'])}")
    if result["files"]:
        print(f"{'FILE ID':32}  {'SIZE':>10}  {'CHUNKS':>6}  FILENAME")
        for item in result["files"]:
            print(
                f"{item['file_id']:32}  {human_bytes(item['size']):>10}  "
                f"{item['chunk_count']:>6}  {item['filename']}"
            )


def print_status(results: list[dict[str, Any]], as_json: bool) -> None:
    if as_json:
        print(json.dumps(results, indent=2))
        return
    for item in results:
        if item["online"]:
            print(
                f"{item['node']} @ {item['endpoint']}: online, "
                f"{item['file_count']} file(s), {human_bytes(item['total_bytes'])}"
            )
        else:
            print(f"? @ {item['endpoint']}: offline ({item['error']})")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client = make_client(args)
        if args.command == "upload":
            print_upload(client.upload_file(args.path, remote_name=args.name), args.json)
        elif args.command == "restore":
            result = client.restore_file(
                args.file_id, args.destination, overwrite=args.overwrite
            )
            print_restore(result, args.json)
        elif args.command == "list":
            print_list(client.list_files(), args.json)
        elif args.command == "delete":
            result = client.delete_file(args.file_id)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(
                    f"Deleted {args.file_id} on: "
                    f"{', '.join(result['deleted_on']) or 'no server'}"
                )
                if result["missing_on"]:
                    print(f"  not present on: {', '.join(result['missing_on'])}")
                if result["failures"]:
                    print(f"  failures: {'; '.join(result['failures'])}")
        elif args.command == "status":
            print_status(client.status_all(), args.json)
        else:  # pragma: no cover - argparse enforces choices
            parser.error("unknown command")
    except (BackupError, RemoteError, DestinationExists, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
