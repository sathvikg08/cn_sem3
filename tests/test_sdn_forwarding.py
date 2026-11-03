"""Unit tests for pure route planning and controlled ARP flooding."""

from __future__ import annotations

import pytest

from sdn.forwarding import (
    controlled_flood_targets,
    plan_route,
    route_for_hosts,
)
from sdn.routing import Path, PathSelection
from sdn.topology import HostLocation, Link, NetworkGraph, PortRef


def ring_graph() -> NetworkGraph:
    graph = NetworkGraph()
    graph.add_switch(1, ports=(1, 2, 3))
    graph.add_switch(2, ports=(1, 2))
    graph.add_switch(3, ports=(1, 2))
    graph.add_switch(4, ports=(1, 2, 3, 4))
    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1)))
    graph.add_link(Link(PortRef(1, 3), PortRef(3, 1)))
    graph.add_link(Link(PortRef(2, 2), PortRef(4, 1)))
    graph.add_link(Link(PortRef(3, 2), PortRef(4, 2)))
    return graph


def host_one() -> HostLocation:
    return HostLocation("02:00:00:00:00:01", 1, 1, "10.0.0.1")


def host_two() -> HostLocation:
    return HostLocation("02:00:00:00:00:02", 4, 3, "10.0.0.2")


def path_through(graph: NetworkGraph, dpids: tuple[int, ...]) -> Path:
    links: list[Link] = []
    for first, second in zip(dpids, dpids[1:]):
        matches = [
            link
            for link in graph.links
            if {link.a.dpid, link.b.dpid} == {first, second}
        ]
        assert len(matches) == 1
        links.append(matches[0])
    return Path(nodes=dpids, links=tuple(links))


def test_route_for_hosts_uses_shortest_paths_and_selector() -> None:
    graph = ring_graph()
    source = host_one()
    destination = host_two()

    plan = route_for_hosts(
        graph, source, destination, flow_key=(source.mac, destination.mac)
    )

    assert plan is not None
    assert plan.path.nodes in {(1, 2, 4), (1, 3, 4)}
    assert plan.path.cost == 2.0
    assert plan.selection.reason in {"ecmp", "single-path"}
    assert len(plan.forward) == len(plan.path.nodes)
    assert len(plan.reverse) == len(plan.path.nodes)
    assert all(rule.match.eth_src == source.mac for rule in plan.forward)
    assert all(rule.match.eth_dst == destination.mac for rule in plan.forward)
    assert all(rule.match.eth_src == destination.mac for rule in plan.reverse)
    assert all(rule.match.eth_dst == source.mac for rule in plan.reverse)


def test_plan_route_builds_exact_output_ports_for_both_directions() -> None:
    graph = ring_graph()
    source = host_one()
    destination = host_two()
    path = path_through(graph, (1, 2, 4))
    selection = PathSelection(path=path, reason="test", detail="forced")

    plan = plan_route(path, source, destination, selection)

    forward = [(rule.dpid, rule.match.in_port, rule.out_port) for rule in plan.forward]
    reverse = [(rule.dpid, rule.match.in_port, rule.out_port) for rule in plan.reverse]
    assert forward == [(1, 1, 2), (2, 1, 2), (4, 1, 3)]
    assert reverse == [(4, 3, 1), (2, 2, 1), (1, 2, 1)]


def test_same_switch_pair_gets_local_bidirectional_rules() -> None:
    graph = NetworkGraph()
    graph.add_switch(1, ports=(1, 2))
    first = HostLocation("02:00:00:00:00:0a", 1, 1)
    second = HostLocation("02:00:00:00:00:0b", 1, 2)

    plan = route_for_hosts(
        graph, first, second, flow_key=(first.mac, second.mac)
    )

    assert plan is not None
    assert plan.path.nodes == (1,)
    assert [(rule.dpid, rule.match.in_port, rule.out_port) for rule in plan.forward] == [
        (1, 1, 2)
    ]
    assert [(rule.dpid, rule.match.in_port, rule.out_port) for rule in plan.reverse] == [
        (1, 2, 1)
    ]


def test_route_for_hosts_returns_none_without_a_path() -> None:
    graph = ring_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))
    graph.remove_link(Link(PortRef(1, 3), PortRef(3, 1)))

    assert (
        route_for_hosts(
            graph,
            host_one(),
            host_two(),
            flow_key=("a", "b"),
        )
        is None
    )


def test_route_for_hosts_rejects_transit_attachment() -> None:
    graph = ring_graph()
    source = HostLocation("02:00:00:00:00:03", 1, 2)
    destination = host_two()

    assert (
        route_for_hosts(
            graph,
            source,
            destination,
            flow_key=(source.mac, destination.mac),
        )
        is None
    )


def test_route_for_hosts_rejects_zero_cost_same_switch_transit() -> None:
    graph = NetworkGraph()
    graph.add_switch(1, ports=(1, 2, 3))
    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1)))
    source = HostLocation("02:00:00:00:00:04", 1, 1)
    destination = HostLocation("02:00:00:00:00:05", 1, 2)

    assert graph.is_transit_port(1, 2) is True
    assert (
        route_for_hosts(
            graph,
            source,
            destination,
            flow_key=(source.mac, destination.mac),
        )
        is None
    )


def test_route_for_hosts_rejects_down_host_port() -> None:
    graph = ring_graph()
    graph.set_port_state(1, 1, False)

    assert (
        route_for_hosts(
            graph,
            host_one(),
            host_two(),
            flow_key=("a", "b"),
        )
        is None
    )


def test_route_for_hosts_after_all_links_removed_returns_none() -> None:
    graph = ring_graph()
    for link in graph.links:
        graph.remove_link(link)

    assert graph.host_ports(1) == {1}
    assert graph.host_ports(4) == {3, 4}
    assert (
        route_for_hosts(
            graph,
            host_one(),
            host_two(),
            flow_key=("a", "b"),
        )
        is None
    )


def test_route_selection_is_deterministic_for_same_pair() -> None:
    graph = ring_graph()
    source = host_one()
    destination = host_two()

    first = route_for_hosts(
        graph, source, destination, flow_key=(source.mac, destination.mac)
    )
    second = route_for_hosts(
        graph, source, destination, flow_key=(source.mac, destination.mac)
    )

    assert first is not None and second is not None
    assert first.path == second.path


def test_controlled_flood_targets_are_rooted_and_loop_free() -> None:
    graph = ring_graph()

    targets = controlled_flood_targets(graph, PortRef(1, 1))
    pairs = {(target.dpid, target.port_no) for target in targets}

    # BFS visits s2 before s3, so s4 is claimed by the s2 branch.  s3 has no
    # host-facing port in this graph and therefore needs no packet-out copy.
    assert pairs == {
        (1, 2),
        (1, 3),
        (2, 2),
        (4, 3),
        (4, 4),
    }
    # The source port and every parent-facing port must be excluded.
    assert (1, 1) not in pairs
    assert (2, 1) not in pairs
    assert (3, 1) not in pairs
    assert (4, 1) not in pairs


def full_host_graph() -> NetworkGraph:
    """Ring graph with one host-facing port on every switch."""

    graph = ring_graph()
    graph.add_switch(2, ports=(3,))
    graph.add_switch(3, ports=(3,))
    return graph


@pytest.mark.parametrize(
    ("ingress", "expected"),
    [
        (
            PortRef(1, 1),
            {
                (1, 2),
                (1, 3),
                (2, 2),
                (2, 3),
                (3, 3),
                (4, 3),
                (4, 4),
            },
        ),
        (
            PortRef(2, 3),
            {
                (1, 1),
                (1, 3),
                (2, 1),
                (2, 2),
                (3, 3),
                (4, 3),
                (4, 4),
            },
        ),
        (
            PortRef(3, 3),
            {
                (1, 1),
                (1, 2),
                (2, 3),
                (3, 1),
                (3, 2),
                (4, 3),
                (4, 4),
            },
        ),
        (
            PortRef(4, 3),
            {
                (1, 1),
                (2, 1),
                (2, 3),
                (3, 3),
                (4, 1),
                (4, 2),
                (4, 4),
            },
        ),
    ],
)
def test_controlled_flood_exact_egress_for_each_switch_root(
    ingress: PortRef,
    expected: set[tuple[int, int]],
) -> None:
    targets = controlled_flood_targets(full_host_graph(), ingress)
    pairs = {(target.dpid, target.port_no) for target in targets}

    assert pairs == expected
    assert (ingress.dpid, ingress.port_no) not in pairs


def test_controlled_flood_excludes_down_host_ports() -> None:
    graph = full_host_graph()
    graph.set_port_state(2, 3, False)
    graph.set_port_state(4, 4, False)

    pairs = {
        (target.dpid, target.port_no)
        for target in controlled_flood_targets(graph, PortRef(1, 1))
    }

    assert (2, 3) not in pairs
    assert (4, 4) not in pairs
    assert pairs == {
        (1, 2),
        (1, 3),
        (2, 2),
        (3, 3),
        (4, 3),
    }


def test_controlled_flood_includes_host_ports_on_leaf_switch() -> None:
    graph = ring_graph()
    graph.add_switch(3, ports=(1, 2, 4))

    pairs = {
        (target.dpid, target.port_no)
        for target in controlled_flood_targets(graph, PortRef(1, 1))
    }

    assert (3, 4) in pairs
    assert (3, 1) not in pairs
    assert (3, 2) not in pairs


def test_controlled_flood_does_not_enter_disconnected_component() -> None:
    graph = ring_graph()
    graph.add_switch(10, ports=(1, 2))
    graph.add_switch(11, ports=(1, 2, 3))
    graph.add_link(Link(PortRef(10, 1), PortRef(11, 1)))

    targets = controlled_flood_targets(graph, PortRef(1, 1))
    pairs = {(target.dpid, target.port_no) for target in targets}

    assert {target.dpid for target in targets} <= {1, 2, 3, 4}
    assert {target.dpid for target in targets}.isdisjoint({10, 11})
    assert (10, 2) not in pairs
    assert (11, 2) not in pairs
    assert (11, 3) not in pairs


def test_controlled_flood_unknown_ingress_returns_no_targets() -> None:
    assert controlled_flood_targets(ring_graph(), PortRef(99, 1)) == ()


def test_controlled_flood_excludes_removed_link_ports() -> None:
    graph = ring_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))

    pairs = {
        (target.dpid, target.port_no)
        for target in controlled_flood_targets(graph, PortRef(1, 1))
    }

    assert (1, 2) not in pairs
    assert graph.is_transit_port(1, 2) is True
    # s2 is still reachable through the s3 -> s4 branch, but no flood copy is
    # sent directly out of the removed link.
    assert pairs == {(1, 3), (3, 2), (4, 1), (4, 3), (4, 4)}


def test_controlled_flood_after_all_links_removed_has_no_transit_egress() -> None:
    graph = ring_graph()
    for link in graph.links:
        graph.remove_link(link)

    targets = controlled_flood_targets(graph, PortRef(1, 1))

    assert targets == ()
    for target in targets:
        assert not graph.is_transit_port(target.dpid, target.port_no)


def test_controlled_flood_transit_targets_are_only_current_tree_ports() -> None:
    graph = full_host_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))

    targets = controlled_flood_targets(graph, PortRef(1, 1))

    for target in targets:
        if graph.is_transit_port(target.dpid, target.port_no):
            assert target.port_no in graph.link_ports(target.dpid)
