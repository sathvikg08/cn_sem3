"""Unit tests for pure shortest-path routing and path selection."""

from __future__ import annotations

import pytest

from sdn.routing import Path, PathSelector, shortest_path, shortest_paths
from sdn.topology import Link, NetworkGraph, PortRef


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


def test_shortest_paths_returns_both_equal_cost_paths() -> None:
    graph = ring_graph()

    paths = shortest_paths(graph, 1, 4)

    assert len(paths) == 2
    assert {path.nodes for path in paths} == {(1, 2, 4), (1, 3, 4)}
    assert {path.cost for path in paths} == {2.0}
    assert paths == sorted(paths, key=lambda path: (path.cost, path.signature))


def test_shortest_path_is_deterministic() -> None:
    graph = ring_graph()

    first = shortest_path(graph, 1, 4)
    second = shortest_path(graph, 1, 4)

    assert first is not None
    assert first == second
    assert first.nodes in {(1, 2, 4), (1, 3, 4)}


def test_failed_link_is_excluded_from_routing() -> None:
    graph = ring_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))

    paths = shortest_paths(graph, 1, 4)

    assert [path.nodes for path in paths] == [(1, 3, 4)]


def test_no_path_when_all_alternatives_fail() -> None:
    graph = ring_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))
    graph.remove_link(Link(PortRef(1, 3), PortRef(3, 1)))

    assert shortest_paths(graph, 1, 4) == []
    assert shortest_path(graph, 1, 4) is None


def test_same_switch_is_a_zero_cost_path() -> None:
    graph = ring_graph()

    paths = shortest_paths(graph, 1, 1)

    assert len(paths) == 1
    assert paths[0].nodes == (1,)
    assert paths[0].links == ()
    assert paths[0].cost == 0


def test_unknown_or_invalid_switches_return_no_path() -> None:
    graph = ring_graph()

    assert shortest_paths(graph, 1, 99) == []
    assert shortest_paths(graph, 99, 4) == []
    assert shortest_path(graph, 99, 4) is None


def test_path_exposes_incoming_and_outgoing_ports() -> None:
    graph = ring_graph()
    path = path_through(graph, (1, 2, 4))

    assert path.incoming_port(0) is None
    assert path.outgoing_port(0) == PortRef(1, 2)
    assert path.incoming_port(1) == PortRef(2, 1)
    assert path.outgoing_port(1) == PortRef(2, 2)
    assert path.incoming_port(2) == PortRef(4, 1)
    assert path.outgoing_port(2) is None


def test_path_rejects_repeated_switches() -> None:
    graph = ring_graph()
    link = next(
        link
        for link in graph.links
        if {link.a.dpid, link.b.dpid} == {1, 2}
    )

    with pytest.raises(ValueError):
        Path(nodes=(1, 2, 1), links=(link, link))


def test_link_cost_changes_the_selected_route() -> None:
    graph = ring_graph()
    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1), cost=5.0))

    paths = shortest_paths(graph, 1, 4)

    assert [path.nodes for path in paths] == [(1, 3, 4)]
    assert paths[0].cost == 2.0


def test_max_paths_limits_result_size() -> None:
    graph = ring_graph()

    paths = shortest_paths(graph, 1, 4, max_paths=1)

    assert len(paths) == 1
    assert paths[0].nodes in {(1, 2, 4), (1, 3, 4)}
    with pytest.raises(ValueError):
        shortest_paths(graph, 1, 4, max_paths=0)


def test_selector_is_deterministic_for_the_same_flow() -> None:
    graph = ring_graph()
    paths = shortest_paths(graph, 1, 4)
    selector = PathSelector()

    first = selector.choose(paths, flow_key=("10.0.0.1", "10.0.0.2"))
    second = selector.choose(paths, flow_key=("10.0.0.1", "10.0.0.2"))

    assert first.path == second.path
    assert first.reason == "ecmp"
    assert "deterministic" in first.detail


def test_selector_can_distribute_different_flows() -> None:
    graph = ring_graph()
    paths = shortest_paths(graph, 1, 4)
    selector = PathSelector()

    chosen = {
        selector.choose(paths, flow_key=("10.0.0.1", f"10.0.0.{index}")).path
        for index in range(20)
    }

    assert len(chosen) == 2


def test_selector_uses_supplied_utilization_when_complete() -> None:
    graph = ring_graph()
    paths = shortest_paths(graph, 1, 4)
    selector = PathSelector()
    high, low = paths
    utilization = {high: 90.0, low: 5.0}

    choice = selector.choose(
        paths, flow_key=("10.0.0.1", "10.0.0.2"), utilization=utilization
    )

    assert choice.path == low
    assert choice.reason == "load-aware"
    assert "5" in choice.detail


def test_selector_falls_back_when_utilization_is_incomplete() -> None:
    graph = ring_graph()
    paths = shortest_paths(graph, 1, 4)
    selector = PathSelector()

    choice = selector.choose(
        paths,
        flow_key=("10.0.0.1", "10.0.0.2"),
        utilization={paths[0]: 10.0},
    )

    assert choice.reason == "ecmp"
    assert "incomplete" in choice.detail


def test_selector_single_path_and_empty_input() -> None:
    graph = ring_graph()
    path = path_through(graph, (1, 2, 4))
    selector = PathSelector()

    choice = selector.choose([path], flow_key="only")
    assert choice.path == path
    assert choice.reason == "single-path"

    with pytest.raises(ValueError):
        selector.choose([], flow_key="none")
