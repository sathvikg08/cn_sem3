"""Topology model and graph operations for the SDN controller.

The model is intentionally independent of OpenFlow and OS-Ken.  A controller
translates switch/link/host events into these objects, then uses the same graph
for path calculation, ARP tree construction and diagnostics.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Iterator


@dataclass(frozen=True, order=True)
class PortRef:
    """A physical switch port identified by datapath id and port number."""

    dpid: int
    port_no: int

    def __post_init__(self) -> None:
        if self.dpid < 0:
            raise ValueError("dpid must be non-negative")
        if self.port_no < 0:
            raise ValueError("port_no must be non-negative")

    def __str__(self) -> str:
        return f"{self.dpid}:{self.port_no}"


@dataclass(frozen=True)
class Link:
    """An undirected switch-to-switch link.

    Endpoints are normalized so that ``a`` sorts before ``b``.  This makes the
    same physical link map to the same dictionary key regardless of which
    direction an event was reported from.
    """

    a: PortRef
    b: PortRef
    cost: float = 1.0

    def __post_init__(self) -> None:
        if self.a == self.b:
            raise ValueError("a link cannot connect a port to itself")
        if self.cost <= 0:
            raise ValueError("link cost must be positive")
        first, second = self.a, self.b
        if first > second:
            object.__setattr__(self, "a", second)
            object.__setattr__(self, "b", first)

    @property
    def key(self) -> tuple[PortRef, PortRef]:
        return (self.a, self.b)

    @property
    def dpid_a(self) -> int:
        return self.a.dpid

    @property
    def dpid_b(self) -> int:
        return self.b.dpid

    def contains_dpid(self, dpid: int) -> bool:
        return self.a.dpid == dpid or self.b.dpid == dpid

    def endpoint_for(self, dpid: int) -> PortRef:
        if self.a.dpid == dpid:
            return self.a
        if self.b.dpid == dpid:
            return self.b
        raise KeyError(f"link does not touch dpid {dpid}")

    def peer_endpoint_for(self, dpid: int) -> PortRef:
        if self.a.dpid == dpid:
            return self.b
        if self.b.dpid == dpid:
            return self.a
        raise KeyError(f"link does not touch dpid {dpid}")

    def other_dpid(self, dpid: int) -> int:
        if self.a.dpid == dpid:
            return self.b.dpid
        if self.b.dpid == dpid:
            return self.a.dpid
        raise KeyError(f"link does not touch dpid {dpid}")

    def __str__(self) -> str:
        return f"{self.a} <-> {self.b}"


@dataclass
class SwitchNode:
    """Known ports and state for one OpenFlow switch."""

    dpid: int
    name: str | None = None
    ports: dict[int, bool] = field(default_factory=dict)

    def add_port(self, port_no: int, is_up: bool = True) -> None:
        if port_no < 0:
            raise ValueError("port_no must be non-negative")
        self.ports[port_no] = bool(is_up)

    def remove_port(self, port_no: int) -> None:
        self.ports.pop(port_no, None)

    def set_port_state(self, port_no: int, is_up: bool) -> None:
        self.ports[port_no] = bool(is_up)

    def is_port_up(self, port_no: int) -> bool:
        # A discovered link implies a usable port until an explicit down event
        # says otherwise.  Unknown ports are treated as usable so topology
        # races do not create a transient false blackhole.
        return self.ports.get(port_no, True)

    def __str__(self) -> str:
        return f"switch {self.dpid} ports={sorted(self.ports)}"


@dataclass
class HostLocation:
    """A host MAC address attached to an edge port of a switch."""

    mac: str
    dpid: int
    port_no: int
    ip: str | None = None

    def __post_init__(self) -> None:
        value = self.mac.strip().lower()
        if not value:
            raise ValueError("mac is required")
        object.__setattr__(self, "mac", value)
        if self.dpid < 0:
            raise ValueError("dpid must be non-negative")
        if self.port_no < 0:
            raise ValueError("port_no must be non-negative")
        if self.ip is not None:
            object.__setattr__(self, "ip", self.ip.strip())

    @property
    def port(self) -> PortRef:
        return PortRef(self.dpid, self.port_no)

    def __str__(self) -> str:
        ip = f" ip={self.ip}" if self.ip else ""
        return f"{self.mac}@{self.dpid}:{self.port_no}{ip}"


class NetworkGraph:
    """Mutable undirected graph of switches and switch-to-switch links.

    Hosts are not graph nodes.  They are attached to the graph through a
    :class:`HostLocation`, because a host is normally discovered after the
    switch topology and is not an OpenFlow datapath.
    """

    def __init__(self) -> None:
        self._switches: dict[int, SwitchNode] = {}
        self._links: dict[tuple[PortRef, PortRef], Link] = {}
        # Ports that have ever been used as an inter-switch link endpoint.
        # This history is intentionally independent of current link state: a
        # link disappearing must not turn a transit port into a host port.
        self._transit_ports: set[PortRef] = set()

    # ------------------------------------------------------------- switches
    @property
    def switches(self) -> tuple[SwitchNode, ...]:
        return tuple(self._switches[dpid] for dpid in sorted(self._switches))

    def add_switch(
        self,
        dpid: int,
        ports: Iterable[int] = (),
        *,
        name: str | None = None,
    ) -> SwitchNode:
        if dpid < 0:
            raise ValueError("dpid must be non-negative")
        node = self._switches.get(dpid)
        if node is None:
            node = SwitchNode(dpid=dpid, name=name)
            self._switches[dpid] = node
        elif name is not None:
            node.name = name
        for port_no in ports:
            # Do not overwrite an explicit down state with a discovery hint.
            if int(port_no) not in node.ports:
                node.add_port(int(port_no))
        return node

    def remove_switch(self, dpid: int) -> tuple[Link, ...]:
        self._switches.pop(dpid, None)
        # An explicit switch removal is the only event that discards the
        # transit history for that datapath.  Link removal below deliberately
        # preserves the historical role of every other port.
        self._transit_ports = {
            port for port in self._transit_ports if port.dpid != dpid
        }
        return self.remove_links_for_switch(dpid)

    def has_switch(self, dpid: int) -> bool:
        return dpid in self._switches

    def switch(self, dpid: int) -> SwitchNode:
        return self._switches[dpid]

    def set_port_state(self, dpid: int, port_no: int, is_up: bool) -> None:
        node = self._switches.get(dpid)
        if node is None:
            node = self.add_switch(dpid)
        node.add_port(port_no, is_up=is_up)

    def port_is_up(self, dpid: int, port_no: int) -> bool:
        node = self._switches.get(dpid)
        return node is not None and node.is_port_up(port_no)

    def remove_port(self, dpid: int, port_no: int) -> tuple[Link, ...]:
        node = self._switches.get(dpid)
        if node is not None:
            node.remove_port(port_no)
        # Explicit port deletion is the escape hatch that makes a former
        # transit port eligible for host discovery again after it is re-added.
        self._transit_ports.discard(PortRef(dpid, port_no))
        return self.remove_links_on_port(PortRef(dpid, port_no))

    # ---------------------------------------------------------------- links
    @property
    def links(self) -> tuple[Link, ...]:
        return tuple(self._links[key] for key in sorted(self._links))

    @property
    def active_links(self) -> tuple[Link, ...]:
        return tuple(link for link in self.links if self.link_is_up(link))

    def add_link(self, link: Link) -> Link:
        for endpoint in (link.a, link.b):
            node = self._switches.get(endpoint.dpid)
            if node is None:
                node = self.add_switch(endpoint.dpid)
            # A link discovery event must not change an already known port
            # state; only add the endpoint when it is genuinely new.
            if endpoint.port_no not in node.ports:
                node.add_port(endpoint.port_no)
            self._transit_ports.add(endpoint)
        self._links[link.key] = link
        return link

    def remove_link(self, link: Link) -> Link | None:
        return self._links.pop(link.key, None)

    def remove_link_between(self, first: PortRef, second: PortRef) -> Link | None:
        key = Link(first, second).key
        return self._links.pop(key, None)

    def remove_links_on_port(self, port: PortRef) -> tuple[Link, ...]:
        removed = [
            link
            for link in self._links.values()
            if link.a == port or link.b == port
        ]
        for link in removed:
            del self._links[link.key]
        return tuple(removed)

    def remove_links_for_switch(self, dpid: int) -> tuple[Link, ...]:
        removed = [
            link for link in self._links.values() if link.contains_dpid(dpid)
        ]
        for link in removed:
            del self._links[link.key]
        return tuple(removed)

    def link_is_up(self, link: Link) -> bool:
        return (
            self.port_is_up(link.a.dpid, link.a.port_no)
            and self.port_is_up(link.b.dpid, link.b.port_no)
        )

    def links_for_switch(self, dpid: int) -> tuple[Link, ...]:
        return tuple(link for link in self.links if link.contains_dpid(dpid))

    def active_links_for_switch(self, dpid: int) -> tuple[Link, ...]:
        return tuple(
            link
            for link in self.links_for_switch(dpid)
            if self.link_is_up(link)
        )

    def link_ports(self, dpid: int) -> set[int]:
        return {
            link.endpoint_for(dpid).port_no
            for link in self.links_for_switch(dpid)
        }

    def is_transit_port(self, dpid: int, port_no: int) -> bool:
        """Return whether a port has ever been an inter-switch link endpoint."""

        return PortRef(dpid, port_no) in self._transit_ports

    def transit_ports(self, dpid: int) -> set[int]:
        """Return the historical transit ports for one switch."""

        return {
            port.port_no
            for port in self._transit_ports
            if port.dpid == dpid
        }

    def host_ports(self, dpid: int, *, live_only: bool = False) -> set[int]:
        node = self._switches.get(dpid)
        if node is None:
            return set()
        # Subtract the persistent transit history rather than only the links
        # that happen to be present right now.  A transient LLDP expiry must
        # not reclassify a switch-to-switch port as host-facing.
        transit = self.transit_ports(dpid)
        ports = set(node.ports).difference(transit)
        if live_only:
            ports = {port for port in ports if node.is_port_up(port)}
        return ports

    # --------------------------------------------------------------- paths
    @property
    def switch_count(self) -> int:
        return len(self._switches)

    @property
    def link_count(self) -> int:
        return len(self._links)

    def spanning_tree_ports(self) -> dict[int, set[int]]:
        """Return loop-free broadcast ports for every connected component.

        The result contains only switch-to-switch tree ports.  The controller
        adds edge/host ports for ARP packet-outs.  Each component is rooted at
        its lowest DPID for deterministic behavior.
        """
        tree_ports: dict[int, set[int]] = {
            dpid: set() for dpid in self._switches
        }
        visited: set[int] = set()
        for root in sorted(self._switches):
            if root in visited:
                continue
            visited.add(root)
            queue: deque[int] = deque([root])
            while queue:
                dpid = queue.popleft()
                for link in self.active_links_for_switch(dpid):
                    local = link.endpoint_for(dpid)
                    peer = link.peer_endpoint_for(dpid)
                    if peer.dpid in visited:
                        continue
                    visited.add(peer.dpid)
                    tree_ports[dpid].add(local.port_no)
                    tree_ports[peer.dpid].add(peer.port_no)
                    queue.append(peer.dpid)
        return tree_ports

    def broadcast_tree_ports(self, root: int) -> dict[int, set[int]]:
        """Return child-facing ports of a BFS tree rooted at ``root``.

        The parent-facing port of every non-root switch is deliberately
        omitted.  A controller can therefore inject a copy of a broadcast
        packet at each returned switch/port pair without ever sending the
        packet back toward the root.  Only switches reachable from ``root``
        are included, so disconnected components are not flooded.
        """
        if root not in self._switches:
            return {}
        children: dict[int, set[int]] = {root: set()}
        visited: set[int] = {root}
        queue: deque[int] = deque([root])
        while queue:
            dpid = queue.popleft()
            for link in self.active_links_for_switch(dpid):
                local = link.endpoint_for(dpid)
                peer = link.peer_endpoint_for(dpid)
                if peer.dpid in visited:
                    continue
                visited.add(peer.dpid)
                children.setdefault(dpid, set()).add(local.port_no)
                children.setdefault(peer.dpid, set())
                queue.append(peer.dpid)
        return children

    # -------------------------------------------------------------- display
    def to_dict(self) -> dict[str, object]:
        switches: list[dict[str, object]] = []
        for node in self.switches:
            switches.append(
                {
                    "dpid": node.dpid,
                    "name": node.name,
                    "ports": {str(port): up for port, up in sorted(node.ports.items())},
                    "link_ports": sorted(self.link_ports(node.dpid)),
                    "transit_ports": sorted(self.transit_ports(node.dpid)),
                    "host_ports": sorted(self.host_ports(node.dpid)),
                }
            )
        links = [
            {
                "a": str(link.a),
                "b": str(link.b),
                "cost": link.cost,
                "up": self.link_is_up(link),
            }
            for link in self.links
        ]
        return {"switches": switches, "links": links}

    def __iter__(self) -> Iterator[SwitchNode]:
        return iter(self.switches)

    def __str__(self) -> str:
        return (
            f"NetworkGraph(switches={self.switch_count}, "
            f"links={self.link_count})"
        )
