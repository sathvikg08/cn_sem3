"""Shared description of the SDN topology (single source of truth).

Used by both the Mininet script and the OS-Ken controller so the port
numbers they assume can never drift apart.

    h1 --1[s1]2------1[s2]2------1[s4]3-- srv_a
              3------1[s3]2------2    4-- srv_b
                 (Path A = via s2, Path B = via s3)

Notation ``N[sX]M`` means port N / port M of switch sX.
"""

from __future__ import annotations

# --- Hosts -----------------------------------------------------------------
HOSTS = {
    "h1": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01"},      # client
    "srv_a": {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02"},   # backup server A
    "srv_b": {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03"},   # backup server B
}
CLIENT_MAC = HOSTS["h1"]["mac"]
SERVER_MACS = (HOSTS["srv_a"]["mac"], HOSTS["srv_b"]["mac"])
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# --- Switch ports (dpid == switch number; Mininet derives dpid from "sN") ----
S1, S2, S3, S4 = 1, 2, 3, 4

# (switch, neighbour) -> local port number on `switch`
PORTS = {
    (S1, "h1"): 1,
    (S1, S2): 2,
    (S1, S3): 3,
    (S2, S1): 1,
    (S2, S4): 2,
    (S3, S1): 1,
    (S3, S4): 2,
    (S4, S2): 1,
    (S4, S3): 2,
    (S4, "srv_a"): 3,
    (S4, "srv_b"): 4,
}

# --- Candidate paths between S1 and S4, in order of preference ---------------
PATHS = {
    "A": {"switches": (S1, S2, S4), "middle": S2},
    "B": {"switches": (S1, S3, S4), "middle": S3},
}
PATH_PREFERENCE = ("A", "B")


def path_ports(name: str) -> frozenset:
    """All (dpid, port) pairs whose failure breaks path `name`."""
    mid = PATHS[name]["middle"]
    return frozenset(
        {
            (S1, PORTS[(S1, mid)]),
            (mid, PORTS[(mid, S1)]),
            (mid, PORTS[(mid, S4)]),
            (S4, PORTS[(S4, mid)]),
        }
    )


def uplink_port(dpid: int, path: str) -> int:
    """Port on s1/s4 that leads into `path`."""
    mid = PATHS[path]["middle"]
    return PORTS[(dpid, mid)]
