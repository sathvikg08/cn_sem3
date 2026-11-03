"""Unit tests for the SDN path-selection and flow-table logic (no Mininet needed)."""

from sdn_routing import BROADCAST_PRIORITY, UNICAST_PRIORITY, PathManager, diff_flows
from sdn_topology import CLIENT_MAC, PORTS, S1, S2, S3, S4, SERVER_MACS, path_ports


def all_up():
    pm = PathManager()
    for dpid in (S1, S2, S3, S4):
        pm.set_switch_connected(dpid, True)
    return pm


def flow_out(pm, dpid, mac):
    return pm.desired_flows(dpid).get((UNICAST_PRIORITY, (("eth_dst", mac),)))


def test_no_path_until_all_switches_on_path_connected():
    pm = PathManager()
    for dpid in (S1, S4, S3):
        pm.set_switch_connected(dpid, True)
    assert pm.active == "B"  # S2 missing, so A is unusable but B is complete
    t = pm.set_switch_connected(S2, True)
    assert pm.active == "A" and t.kind == "failback"


def test_initial_path_is_a():
    pm = PathManager()
    transitions = [pm.set_switch_connected(d, True) for d in (S1, S2, S3, S4)]
    assert pm.active == "A"
    assert [t for t in transitions if t][-1].new == "A"


def test_link_failure_on_either_end_triggers_failover():
    for dpid, port in sorted(path_ports("A")):
        pm = all_up()
        t = pm.set_port_state(dpid, port, up=False)
        assert (t.old, t.new, t.kind) == ("A", "B", "failover"), (dpid, port)


def test_recovery_returns_to_path_a_only_when_every_port_is_up():
    pm = all_up()
    pm.set_port_state(S1, 2, up=False)
    pm.set_port_state(S4, 1, up=False)
    assert pm.set_port_state(S1, 2, up=True) is None and pm.active == "B"
    t = pm.set_port_state(S4, 1, up=True)
    assert (t.new, t.kind) == ("A", "failback")


def test_both_paths_down_is_an_outage_then_recovers():
    pm = all_up()
    pm.set_port_state(S1, 2, up=False)
    t = pm.set_port_state(S1, 3, up=False)
    assert (t.new, t.kind) == (None, "outage")
    assert flow_out(pm, S1, SERVER_MACS[0]) is None
    t = pm.set_port_state(S1, 3, up=True)
    assert t.new == "B"


def test_failed_middle_switch_forces_failover_and_reconnect_restores():
    pm = all_up()
    t = pm.set_switch_connected(S2, False)
    assert t.new == "B"
    assert pm.set_switch_connected(S2, True).new == "A"


def test_host_facing_port_failure_does_not_reroute():
    pm = all_up()
    assert pm.set_port_state(S4, PORTS[(S4, "srv_a")], up=False) is None
    assert pm.active == "A"


def test_flows_follow_active_path():
    pm = all_up()
    assert flow_out(pm, S1, SERVER_MACS[0]) == (PORTS[(S1, S2)],)
    assert flow_out(pm, S4, CLIENT_MAC) == (PORTS[(S4, S2)],)
    pm.set_port_state(S2, PORTS[(S2, S4)], up=False)
    assert flow_out(pm, S1, SERVER_MACS[0]) == (PORTS[(S1, S3)],)
    assert flow_out(pm, S4, CLIENT_MAC) == (PORTS[(S4, S3)],)


def test_static_flows_do_not_depend_on_active_path():
    pm = all_up()
    before = {d: pm.desired_flows(d) for d in (S2, S3)}
    pm.set_port_state(S1, 2, up=False)
    assert before == {d: pm.desired_flows(d) for d in (S2, S3)}
    assert flow_out(pm, S4, SERVER_MACS[0]) == (PORTS[(S4, "srv_a")],)
    assert flow_out(pm, S4, SERVER_MACS[1]) == (PORTS[(S4, "srv_b")],)
    assert flow_out(pm, S1, CLIENT_MAC) == (PORTS[(S1, "h1")],)


def test_broadcast_flows_never_loop_back_to_ingress_or_use_both_paths():
    pm = all_up()
    for dpid in (S1, S2, S3, S4):
        for (prio, match), outs in pm.desired_flows(dpid).items():
            if prio == BROADCAST_PRIORITY:
                assert dict(match)["in_port"] not in outs
    # From the client, the broadcast leaves on the active uplink only.
    key = (BROADCAST_PRIORITY, (("eth_dst", "ff:ff:ff:ff:ff:ff"), ("in_port", PORTS[(S1, "h1")])))
    assert pm.desired_flows(S1)[key] == (PORTS[(S1, S2)],)
    pm.set_port_state(S1, 2, up=False)
    assert pm.desired_flows(S1)[key] == (PORTS[(S1, S3)],)


def test_diff_flows_only_changes_what_differs():
    pm = all_up()
    before = pm.desired_flows(S1)
    pm.set_port_state(S1, 2, up=False)
    after = pm.desired_flows(S1)
    delete, add = diff_flows(before, after)
    assert delete == []
    assert {k for k, _ in add} == {k for k in after if after[k] != before.get(k)}
    assert all(PORTS[(S1, S3)] in v for _, v in add)
    # Outage removes uplink flows entirely.
    pm.set_port_state(S1, 3, up=False)
    delete, _ = diff_flows(after, pm.desired_flows(S1))
    assert len(delete) == len(after) - len(pm.desired_flows(S1))
