"""Drive the OS-Ken controller with fake datapaths (no Mininet / OVS needed)."""

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("os_ken")

from os_ken.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER  # noqa: E402
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402

from os_ken_openflow_sdn_controller import SDNBackupController  # noqa: E402
from sdn_topology import PORTS, S1, S2, S3, S4  # noqa: E402


class FakeDatapath:
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser
    _xid = 100

    def __init__(self, dpid):
        self.id = dpid
        self.sent = []

    def send_msg(self, msg):
        FakeDatapath._xid += 1
        msg.xid = FakeDatapath._xid
        self.sent.append(msg)


def ports_for(dpid, down=()):
    nums = sorted(p for (d, n), p in PORTS.items() if d == dpid)
    return [SimpleNamespace(port_no=p, state=1 if (dpid, p) in down else 0, config=0) for p in nums]


@pytest.fixture
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("SDN_RECOVERY_LOG", str(tmp_path / "recovery.jsonl"))
    app = SDNBackupController()
    app.dps = {i: FakeDatapath(i) for i in (S1, S2, S3, S4)}
    for dpid, dp in app.dps.items():
        app.datapaths[dpid] = dp
        app.installed[dpid] = {}
        ev = SimpleNamespace(msg=SimpleNamespace(datapath=dp, body=ports_for(dpid)))
        app.port_desc_handler(ev)
    return app


def ack_barriers(app):
    for dpid, dp in app.dps.items():
        for msg in dp.sent:
            if isinstance(msg, ofproto_v1_3_parser.OFPBarrierRequest):
                app.barrier_reply_handler(SimpleNamespace(msg=SimpleNamespace(datapath=dp, xid=msg.xid)))


def port_event(app, dpid, port, up):
    dp = app.dps[dpid]
    desc = SimpleNamespace(port_no=port, state=0 if up else 1, config=0)
    app.port_status_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp, reason=ofproto_v1_3.OFPPR_MODIFY, desc=desc)))


def flow_mods(dp, command):
    return [m for m in dp.sent
            if isinstance(m, ofproto_v1_3_parser.OFPFlowMod) and m.command == command]


def test_initial_rules_installed_on_path_a(ctl):
    assert ctl.paths.active == "A"
    adds = flow_mods(ctl.dps[S1], ofproto_v1_3.OFPFC_ADD)
    outs = {a.port for m in adds for i in m.instructions for a in i.actions}
    assert PORTS[(S1, S2)] in outs and PORTS[(S1, S3)] not in outs


def test_link_failure_reroutes_and_records_recovery(ctl, tmp_path):
    ack_barriers(ctl)
    before = len(ctl.dps[S1].sent)
    port_event(ctl, S1, PORTS[(S1, S2)], up=False)  # PortStatus: s1-s2 link down
    assert ctl.paths.active == "B"
    new = ctl.dps[S1].sent[before:]
    outs = {a.port for m in new if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)
            for i in m.instructions for a in i.actions}
    assert PORTS[(S1, S3)] in outs  # traffic now leaves via Path B
    assert ctl.pending is not None  # waiting for barrier replies
    ack_barriers(ctl)
    assert ctl.pending is None
    rec = ctl.recoveries[-1]
    assert (rec["event"], rec["from"], rec["to"]) == ("failover", "A", "B")
    assert rec["recovery_ms"] >= 0 and rec["trigger"] == "s1 port 2 down"
    logged = [json.loads(l) for l in (tmp_path / "recovery.jsonl").read_text().splitlines()]
    assert logged[-1]["event"] == "failover"


def test_link_restoration_fails_back(ctl):
    ack_barriers(ctl)
    port_event(ctl, S1, PORTS[(S1, S2)], up=False)
    ack_barriers(ctl)
    port_event(ctl, S1, PORTS[(S1, S2)], up=True)
    assert ctl.paths.active == "A"
    ack_barriers(ctl)
    assert ctl.recoveries[-1]["event"] == "failback"


def test_switch_disconnect_is_treated_as_failure(ctl):
    ack_barriers(ctl)
    ev = SimpleNamespace(datapath=ctl.dps[S2], state=DEAD_DISPATCHER)
    ctl.state_change_handler(ev)
    assert ctl.paths.active == "B"
    assert S2 not in ctl.datapaths


def test_total_outage_removes_uplink_rules(ctl):
    ack_barriers(ctl)
    port_event(ctl, S1, PORTS[(S1, S2)], up=False)
    port_event(ctl, S1, PORTS[(S1, S3)], up=False)
    assert ctl.paths.active is None
    assert flow_mods(ctl.dps[S1], ofproto_v1_3.OFPFC_DELETE_STRICT)
    ack_barriers(ctl)
    assert ctl.recoveries[-1]["event"] == "outage"
