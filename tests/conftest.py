import socket

import pytest

from client.core import BackupClient
from server.app import BackupServer


@pytest.fixture
def server_factory(tmp_path):
    servers: list[BackupServer] = []

    def make(node: str = "A", *, replicator=None, data_dir=None) -> BackupServer:
        root = data_dir or (tmp_path / f"data-{node}-{len(servers)}")
        server = BackupServer(
            data_dir=root,
            host="127.0.0.1",
            port=0,
            node_name=node,
            replicator=replicator,
            request_timeout=30,
        )
        server.start()
        servers.append(server)
        return server

    yield make
    for server in reversed(servers):
        server.stop()


@pytest.fixture
def live_server(server_factory):
    return server_factory("A")


def make_client(server: BackupServer, *, timeout: float = 15) -> BackupClient:
    return BackupClient([server.endpoint], timeout=timeout)


def closed_port() -> tuple[str, int]:
    """Return a localhost port that is very likely closed."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return "127.0.0.1", port
