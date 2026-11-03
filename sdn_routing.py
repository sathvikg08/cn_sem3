"""Pure (OpenFlow-free) routing logic for the dual-path SDN topology.

`PathManager` tracks which switches/ports are up, decides which path is
active (Path A preferred, Path B as backup) and computes the flow table every
switch should hold.  The OS-Ken controller only translates this into
OpenFlow messages, which keeps the logic unit-testable without Mininet.
"""

from __future__ import annotations

from typing import Dict, Iterable, NamedTuple, Optional, Tuple

from sdn_topology import (
    BROADCAST_MAC,
    CLIENT_MAC,
    PATH_PREFERENCE,
    PATHS,
    PORTS,
    S1,
    S2,
    S3,
    S4,
    SERVER_MACS,
    path_ports,
    uplink_port,
)

UNICAST_PRIORITY = 10
BROADCAST_PRIORITY = 20

# A flow key is (priority, ((field, value), ...)); the value is a tuple of out ports.
FlowKey = Tuple[int, Tuple[Tuple[str, object], ...]]
FlowTable = Dict[FlowKey, Tuple[int, ...]]


class Transition(NamedTuple):
    old: Optional[str]
    new: Optional[str]

    @property
    def kind(self) -> str:
        if self.old is None and self.new is not None:
            return "initial"
        if self.new is None:
            return "outage"
        if self.new == PATH_PREFERENCE[0]:
            return "failback"
        return "failover"


def _key(priority: int, **match) -> FlowKey:
    return (priority, tuple(sorted(match.items())))


class PathManager:
    def __init__(self) -> None:
        self.connected: set = set()
        self.down_ports: set = set()
        self.active: Optional[str] = None

    # -- state updates -------------------------------------------------------
    def set_switch_connected(self, dpid: int, connected: bool) -> Optional[Transition]:
        if connected:
            self.connected.add(dpid)
        else:
            self.connected.discard(dpid)
            self.down_ports = {p for p in self.down_ports if p[0] != dpid}
        return self._recompute()

    def set_port_state(self, dpid: int, port: int, up: bool) -> Optional[Transition]:
        if up:
            self.down_ports.discard((dpid, port))
        else:
            self.down_ports.add((dpid, port))
        return self._recompute()

    def reset_switch_ports(self, dpid: int) -> None:
        self.down_ports = {p for p in self.down_ports if p[0] != dpid}

    # -- decisions -----------------------------------------------------------
    def path_healthy(self, name: str) -> bool:
        if not all(sw in self.connected for sw in PATHS[name]["switches"]):
            return False
        return not (path_ports(name) & self.down_ports)

    def _choose(self) -> Optional[str]:
        for name in PATH_PREFERENCE:
            if self.path_healthy(name):
                return name
        return None

    def _recompute(self) -> Optional[Transition]:
        new = self._choose()
        if new == self.active:
            return None
        old, self.active = self.active, new
        return Transition(old, new)

    # -- flow tables ---------------------------------------------------------
    def desired_flows(self, dpid: int) -> FlowTable:
        flows: FlowTable = {}
        active = self.active
        up = lambda sw: uplink_port(sw, active) if active else None  # noqa: E731

        if dpid in (S2, S3):
            toward_s1, toward_s4 = PORTS[(dpid, S1)], PORTS[(dpid, S4)]
            flows[_key(UNICAST_PRIORITY, eth_dst=CLIENT_MAC)] = (toward_s1,)
            for mac in SERVER_MACS:
                flows[_key(UNICAST_PRIORITY, eth_dst=mac)] = (toward_s4,)
            flows[_key(BROADCAST_PRIORITY, in_port=toward_s1, eth_dst=BROADCAST_MAC)] = (toward_s4,)
            flows[_key(BROADCAST_PRIORITY, in_port=toward_s4, eth_dst=BROADCAST_MAC)] = (toward_s1,)

        elif dpid == S1:
            host_port = PORTS[(S1, "h1")]
            flows[_key(UNICAST_PRIORITY, eth_dst=CLIENT_MAC)] = (host_port,)
            for path in PATH_PREFERENCE:  # replies may arrive on either uplink
                flows[_key(BROADCAST_PRIORITY, in_port=uplink_port(S1, path), eth_dst=BROADCAST_MAC)] = (host_port,)
            if active:
                for mac in SERVER_MACS:
                    flows[_key(UNICAST_PRIORITY, eth_dst=mac)] = (up(S1),)
                flows[_key(BROADCAST_PRIORITY, in_port=host_port, eth_dst=BROADCAST_MAC)] = (up(S1),)

        elif dpid == S4:
            a_port, b_port = PORTS[(S4, "srv_a")], PORTS[(S4, "srv_b")]
            flows[_key(UNICAST_PRIORITY, eth_dst=SERVER_MACS[0])] = (a_port,)
            flows[_key(UNICAST_PRIORITY, eth_dst=SERVER_MACS[1])] = (b_port,)
            for path in PATH_PREFERENCE:  # requests may arrive on either uplink
                flows[_key(BROADCAST_PRIORITY, in_port=uplink_port(S4, path), eth_dst=BROADCAST_MAC)] = (a_port, b_port)
            if active:
                flows[_key(UNICAST_PRIORITY, eth_dst=CLIENT_MAC)] = (up(S4),)
                flows[_key(BROADCAST_PRIORITY, in_port=a_port, eth_dst=BROADCAST_MAC)] = (b_port, up(S4))
                flows[_key(BROADCAST_PRIORITY, in_port=b_port, eth_dst=BROADCAST_MAC)] = (a_port, up(S4))
        return flows


def diff_flows(installed: FlowTable, desired: FlowTable):
    """Return (to_delete_keys, to_add_items) turning `installed` into `desired`."""
    to_delete = [k for k in installed if k not in desired]
    to_add = [(k, v) for k, v in desired.items() if installed.get(k) != v]
    return to_delete, to_add
