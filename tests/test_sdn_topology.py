"""Unit tests for the pure SDN topology graph."""

from __future__ import annotations

import pytest

from sdn.topology import HostLocation, Link, NetworkGraph, PortRef


def ring_graph() -> NetworkGraph:
    graph = NetworkGraph()
    graph.add_switch(1, ports=(1, 2, 3), name="s1")
    graph.add_switch(2, ports=(1, 2), name="s2")
    graph.add_switch(3, ports=(1, 2), name="s3")
    graph.add_switch(4, ports=(1, 2, 3, 4), name="s4")
    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1)))
    graph.add_link(Link(PortRef(1, 3), PortRef(3, 1)))
    graph.add_link(Link(PortRef(2, 2), PortRef(4, 1)))
    graph.add_link(Link(PortRef(3, 2), PortRef(4, 2)))
    return graph


def test_link_endpoints_are_normalized() -> None:
    link = Link(PortRef(2, 1), PortRef(1, 2))

    assert link.a == PortRef(1, 2)
    assert link.b == PortRef(2, 1)
    assert link.key == (PortRef(1, 2), PortRef(2, 1))
    assert link.endpoint_for(2) == PortRef(2, 1)
    assert link.peer_endpoint_for(2) == PortRef(1, 2)
    assert link.other_dpid(2) == 1


def test_invalid_links_are_rejected() -> None:
    with pytest.raises(ValueError):
        Link(PortRef(1, 1), PortRef(1, 1))
    with pytest.raises(ValueError):
        Link(PortRef(1, 1), PortRef(2, 1), cost=0)
    with pytest.raises(KeyError):
        Link(PortRef(1, 1), PortRef(2, 1)).endpoint_for(3)


def test_add_link_autocreates_switches_and_ports() -> None:
    graph = NetworkGraph()

    graph.add_link(Link(PortRef(10, 2), PortRef(20, 7)))

    assert graph.has_switch(10)
    assert graph.has_switch(20)
    assert graph.link_count == 1
    assert graph.link_ports(10) == {2}
    assert graph.link_ports(20) == {7}
    assert graph.host_ports(10) == set()
    assert graph.host_ports(20) == set()


def test_remove_link_updates_adjacency() -> None:
    graph = ring_graph()
    link = Link(PortRef(1, 2), PortRef(2, 1))

    removed = graph.remove_link(link)

    assert removed == link
    assert graph.remove_link(link) is None
    assert graph.link_count == 3
    assert graph.link_ports(1) == {3}
    assert graph.host_ports(1) == {1}
    assert graph.is_transit_port(1, 2) is True


def test_remove_link_between_and_port() -> None:
    graph = ring_graph()

    assert graph.remove_link_between(PortRef(2, 1), PortRef(1, 2)) is not None
    assert graph.link_count == 3

    removed = graph.remove_port(1, 3)
    assert len(removed) == 1
    assert graph.link_count == 2
    assert 3 not in graph.switch(1).ports


def test_add_link_marks_both_endpoints_transit() -> None:
    graph = NetworkGraph()

    graph.add_link(Link(PortRef(10, 2), PortRef(20, 7)))

    assert graph.is_transit_port(10, 2) is True
    assert graph.is_transit_port(20, 7) is True
    assert graph.transit_ports(10) == {2}
    assert graph.transit_ports(20) == {7}
    assert graph.host_ports(10) == set()
    assert graph.host_ports(20) == set()


def test_removed_transit_ports_are_never_host_ports() -> None:
    graph = ring_graph()

    for link in graph.links:
        graph.remove_link(link)

    assert graph.link_count == 0
    assert graph.host_ports(1) == {1}
    assert graph.host_ports(2) == set()
    assert graph.host_ports(3) == set()
    assert graph.host_ports(4) == {3, 4}
    assert graph.transit_ports(1) == {2, 3}
    assert graph.transit_ports(2) == {1, 2}
    assert graph.transit_ports(3) == {1, 2}
    assert graph.transit_ports(4) == {1, 2}


def test_link_down_does_not_clear_transit_role() -> None:
    graph = ring_graph()

    graph.set_port_state(1, 2, False)
    assert graph.is_transit_port(1, 2) is True
    assert 2 not in graph.host_ports(1)

    graph.set_port_state(1, 2, True)
    assert graph.is_transit_port(1, 2) is True
    assert 2 not in graph.host_ports(1)


def test_all_link_removal_paths_preserve_transit_history() -> None:
    graph = ring_graph()

    graph.remove_links_on_port(PortRef(1, 2))
    assert graph.is_transit_port(1, 2) is True

    graph.remove_links_for_switch(1)
    assert graph.is_transit_port(1, 2) is True
    assert graph.is_transit_port(1, 3) is True

    graph.remove_link_between(PortRef(2, 2), PortRef(4, 1))
    assert graph.is_transit_port(2, 2) is True
    assert graph.is_transit_port(4, 1) is True


def test_explicit_port_delete_clears_transit_role() -> None:
    graph = ring_graph()
    graph.remove_link(Link(PortRef(1, 2), PortRef(2, 1)))
    assert graph.is_transit_port(1, 2) is True

    graph.remove_port(1, 2)
    assert graph.is_transit_port(1, 2) is False
    graph.add_switch(1, ports=(2,))
    assert graph.host_ports(1) == {1, 2}

    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1)))
    assert graph.is_transit_port(1, 2) is True
    assert graph.host_ports(1) == {1}


def test_switch_remove_clears_transit_history() -> None:
    graph = ring_graph()

    graph.remove_switch(2)

    assert graph.transit_ports(2) == set()
    assert graph.is_transit_port(2, 1) is False
    assert graph.is_transit_port(2, 2) is False
    # Removing one switch must not clear another switch's history.
    assert graph.is_transit_port(1, 2) is True
    assert graph.is_transit_port(4, 1) is True


def test_snapshot_includes_transit_ports() -> None:
    graph = ring_graph()

    snapshot = graph.to_dict()
    by_dpid = {entry["dpid"]: entry for entry in snapshot["switches"]}

    assert by_dpid[1]["transit_ports"] == [2, 3]
    assert by_dpid[1]["host_ports"] == [1]
    assert by_dpid[4]["transit_ports"] == [1, 2]
    assert by_dpid[4]["host_ports"] == [3, 4]


def test_port_state_controls_link_activity() -> None:
    graph = ring_graph()

    assert len(graph.active_links) == 4
    graph.set_port_state(1, 2, False)
    assert not graph.link_is_up(Link(PortRef(1, 2), PortRef(2, 1)))
    assert len(graph.active_links) == 3

    graph.set_port_state(1, 2, True)
    assert len(graph.active_links) == 4


def test_spanning_tree_is_loop_free_and_covers_all_switches() -> None:
    graph = ring_graph()

    tree_ports = graph.spanning_tree_ports()

    assert set(tree_ports) == {1, 2, 3, 4}
    tree_edges = 0
    for link in graph.links:
        if (
            link.a.port_no in tree_ports[link.a.dpid]
            and link.b.port_no in tree_ports[link.b.dpid]
        ):
            tree_edges += 1
    assert tree_edges == 3
    assert all(ports for ports in tree_ports.values())


def test_spanning_tree_is_a_forest_when_disconnected() -> None:
    graph = NetworkGraph()
    graph.add_switch(1)
    graph.add_switch(2)
    graph.add_switch(3)
    graph.add_switch(4)
    graph.add_link(Link(PortRef(1, 1), PortRef(2, 1)))
    graph.add_link(Link(PortRef(3, 1), PortRef(4, 1)))

    tree_ports = graph.spanning_tree_ports()

    edges = 0
    for link in graph.links:
        if (
            link.a.port_no in tree_ports[link.a.dpid]
            and link.b.port_no in tree_ports[link.b.dpid]
        ):
            edges += 1
    assert edges == 2
    assert all(ports for ports in tree_ports.values())


def test_broadcast_tree_omits_parent_ports() -> None:
    graph = ring_graph()

    children = graph.broadcast_tree_ports(2)

    assert children == {
        1: {3},
        2: {1, 2},
        3: set(),
        4: set(),
    }


def test_broadcast_tree_unknown_root_is_empty() -> None:
    assert ring_graph().broadcast_tree_ports(99) == {}



def test_host_ports_exclude_link_ports_and_can_be_live_only() -> None:
    graph = ring_graph()
    graph.set_port_state(1, 1, False)

    assert graph.host_ports(1) == {1}
    assert graph.host_ports(1, live_only=True) == set()
    assert graph.host_ports(4) == {3, 4}


def test_remove_switch_removes_incident_links() -> None:
    graph = ring_graph()

    removed = graph.remove_switch(2)

    assert len(removed) == 2
    assert not graph.has_switch(2)
    assert graph.link_count == 2
    assert all(link.contains_dpid(2) is False for link in graph.links)


def test_host_location_normalizes_mac_and_keeps_edge_information() -> None:
    host = HostLocation("AA:BB:CC:DD:EE:FF", 4, 3, "10.0.0.2")

    assert host.mac == "aa:bb:cc:dd:ee:ff"
    assert host.port == PortRef(4, 3)
    assert host.ip == "10.0.0.2"


def test_snapshot_is_json_friendly() -> None:
    graph = ring_graph()

    snapshot = graph.to_dict()

    assert len(snapshot["switches"]) == 4
    assert len(snapshot["links"]) == 4
    assert snapshot["switches"][0]["name"] == "s1"
    assert snapshot["links"][0]["up"] is True


def test_link_discovery_preserves_down_port_state() -> None:
    graph = NetworkGraph()
    graph.add_switch(1, ports=(1, 2))
    graph.add_switch(2, ports=(1, 2))
    graph.set_port_state(1, 2, False)
    graph.set_port_state(2, 1, False)

    graph.add_link(Link(PortRef(1, 2), PortRef(2, 1)))

    assert graph.port_is_up(1, 2) is False
    assert graph.port_is_up(2, 1) is False
    assert graph.active_links == ()


def test_unknown_switch_operations_are_safe() -> None:
    graph = NetworkGraph()

    assert graph.host_ports(99) == set()
    assert graph.port_is_up(99, 1) is False
    assert graph.links_for_switch(99) == ()
    with pytest.raises(KeyError):
        graph.switch(99)
