"""Pure forwarding-plan construction for the SDN controller.

The controller uses this module to turn a shortest path into explicit
OpenFlow-style per-switch output rules.  Nothing here imports OS-Ken, Mininet
or Open vSwitch, so the plans can be checked with ordinary pytest.

The second responsibility is controlled broadcast: ARP requests that cannot be
answered by the proxy are sent over a BFS tree rooted at the ingress switch.
Only child-facing and host-facing ports are returned, which makes the flood
loop-free by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from sdn.routing import Path, PathSelection, PathSelector, shortest_paths
from sdn.topology import HostLocation, NetworkGraph, PortRef


@dataclass(frozen=True)
class FlowMatch:
    """Layer-2 match for one forwarding hop."""

    in_port: int
    eth_src: str
    eth_dst: str

    def __post_init__(self) -> None:
        if self.in_port < 0:
            raise ValueError("in_port must be non-negative")
        object.__setattr__(self, "eth_src", self.eth_src.strip().lower())
        object.__setattr__(self, "eth_dst", self.eth_dst.strip().lower())


@dataclass(frozen=True)
class FlowRule:
    """One switch-local forwarding rule produced from a route plan."""

    dpid: int
    match: FlowMatch
    out_port: int

    def __post_init__(self) -> None:
        if self.dpid < 0:
            raise ValueError("dpid must be non-negative")
        if self.out_port < 0:
            raise ValueError("out_port must be non-negative")


@dataclass(frozen=True)
class RoutePlan:
    """Forward and reverse rules for one host pair."""

    selection: PathSelection
    forward: tuple[FlowRule, ...]
    reverse: tuple[FlowRule, ...]

    @property
    def path(self) -> Path:
        return self.selection.path

    @property
    def rules(self) -> tuple[FlowRule, ...]:
        return self.forward + self.reverse


@dataclass(frozen=True, order=True)
class FloodTarget:
    """One switch port that should receive a controlled broadcast copy."""

    dpid: int
    port_no: int


def _rules_for_direction(
    path: Path,
    source: HostLocation,
    destination: HostLocation,
) -> tuple[FlowRule, ...]:
    if source.dpid != path.source:
        raise ValueError("source host is not attached to the path source")
    if destination.dpid != path.destination:
        raise ValueError("destination host is not attached to the path destination")

    rules: list[FlowRule] = []
    last = len(path.nodes) - 1
    for index, dpid in enumerate(path.nodes):
        if index == 0:
            in_port = source.port_no
        else:
            incoming = path.incoming_port(index)
            if incoming is None:  # pragma: no cover - defensive
                raise ValueError("path is missing an incoming port")
            in_port = incoming.port_no

        if index == last:
            out_port = destination.port_no
        else:
            outgoing = path.outgoing_port(index)
            if outgoing is None:  # pragma: no cover - defensive
                raise ValueError("path is missing an outgoing port")
            out_port = outgoing.port_no

        rules.append(
            FlowRule(
                dpid=dpid,
                match=FlowMatch(
                    in_port=in_port,
                    eth_src=source.mac,
                    eth_dst=destination.mac,
                ),
                out_port=out_port,
            )
        )
    return tuple(rules)


def plan_route(
    path: Path,
    source: HostLocation,
    destination: HostLocation,
    selection: PathSelection,
) -> RoutePlan:
    """Build bidirectional rules for a known host pair and selected path."""

    if selection.path != path:
        raise ValueError("path selection does not describe the supplied path")
    reverse_path = Path(
        nodes=tuple(reversed(path.nodes)),
        links=tuple(reversed(path.links)),
    )
    return RoutePlan(
        selection=selection,
        forward=_rules_for_direction(path, source, destination),
        reverse=_rules_for_direction(reverse_path, destination, source),
    )


def _verified_host_attachment(
    graph: NetworkGraph, host: HostLocation
) -> bool:
    """Return True only for a live port that is known to be host-facing."""

    if not graph.has_switch(host.dpid):
        return False
    if graph.is_transit_port(host.dpid, host.port_no):
        return False
    return host.port_no in graph.host_ports(host.dpid, live_only=True)


def route_for_hosts(
    graph: NetworkGraph,
    source: HostLocation,
    destination: HostLocation,
    *,
    flow_key: object,
    selector: PathSelector | None = None,
    max_paths: int = 8,
) -> RoutePlan | None:
    """Run Dijkstra and the path selector for a host pair.

    ``flow_key`` is intentionally supplied by the caller so different host
    pairs (or, later, different transport flows) can be spread over equal-cost
    paths deterministically.

    Both attachments must be verified host-facing ports.  Without this guard a
    corrupted location on a transit port could produce a zero-cost same-switch
    route between two hosts that are not actually attached to that switch.
    """

    if source.mac == destination.mac:
        return None
    if not _verified_host_attachment(graph, source):
        return None
    if not _verified_host_attachment(graph, destination):
        return None
    paths = shortest_paths(
        graph,
        source.dpid,
        destination.dpid,
        max_paths=max_paths,
    )
    if not paths:
        return None
    choice = (selector or PathSelector()).choose(paths, flow_key=flow_key)
    return plan_route(choice.path, source, destination, choice)


def controlled_flood_targets(
    graph: NetworkGraph,
    ingress: PortRef,
) -> tuple[FloodTarget, ...]:
    """Return loop-free egress ports for a controller-driven ARP flood.

    The BFS tree is rooted at the ingress switch so the packet never travels
    back toward its source.  Every switch appears at most once, therefore the
    controller's packet-out copies cannot create a forwarding loop.
    """

    children = graph.broadcast_tree_ports(ingress.dpid)
    targets: list[FloodTarget] = []
    for dpid in sorted(children):
        # BFS child ports are verified current link ports and are the only
        # transit ports a controlled flood may use.  Host-facing additions
        # must never include a historical transit port.
        ports = set(children[dpid])
        ports.update(
            port_no
            for port_no in graph.host_ports(dpid, live_only=True)
            if not graph.is_transit_port(dpid, port_no)
        )
        if dpid == ingress.dpid:
            ports.discard(ingress.port_no)
        for port_no in sorted(ports):
            targets.append(FloodTarget(dpid=dpid, port_no=port_no))
    return tuple(targets)
