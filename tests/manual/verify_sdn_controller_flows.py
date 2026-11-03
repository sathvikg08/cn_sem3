"""Simulated OpenFlow datapath tests for the Stage 3 controller.

These tests instantiate the real OS-Ken application class and a fake datapath
that records every FlowMod and PacketOut.  They verify:

* table-miss, ARP punting and host-punt rules,
* ARP proxy replies and route installation on every switch,
* barrier-gated forwarding: proxy replies and first data packets wait for all
  route switches to acknowledge,
* FlowMod errors, missing datapaths and barrier timeouts never report a route
  as installed,
* per-datapath barrier/error transaction tracking when XIDs collide,
* loop-free controlled ARP flooding,
* flow deletion and route replacement after a link failure,
* data packet forwarding over the selected path,
* port-down/port-up host invalidation via topology, direct port-status and
  multipart port-description reconciliation.

They are intentionally separate from the default pytest suite because they
need the OS-Ken virtualenv and no Mininet/OVS/root.  Run:

    .venv-sdn/bin/python tests/manual/verify_sdn_controller_flows.py
"""

from __future__ import annotations

import struct
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

# Direct script execution puts ``tests/manual`` on sys.path, not the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser as parser

from sdn_backup_controller import (
    FLOW_COOKIE,
    FLOW_COOKIE_MASK,
    LLDP_STALL_SECONDS,
    LOGGER,
    PRIORITY_ARP,
    PRIORITY_HOST_PUNT,
    PRIORITY_ROUTE,
    PRIORITY_TABLE_MISS,
    SDNBackupController,
)

OFPP = ofproto_v1_3
OFP_NO_BUFFER = OFPP.OFP_NO_BUFFER


class FakePort:
    def __init__(
        self, port_no: int, live: bool = True, dpid: int | None = None
    ) -> None:
        self.port_no = port_no
        self.dpid = dpid
        self.name = f"eth{port_no}".encode()
        self._live = live
        self.config = 0 if live else OFPP.OFPPC_PORT_DOWN
        self.state = 0 if live else OFPP.OFPPS_LINK_DOWN

    def is_reserved(self) -> bool:
        return self.port_no > OFPP.OFPP_MAX

    def is_live(self) -> bool:
        return self._live


class FakeDatapath:
    def __init__(
        self,
        dpid: int,
        controller: SDNBackupController | None = None,
        *,
        auto_barrier: bool = True,
    ) -> None:
        self.id = dpid
        self.controller = controller
        self.auto_barrier = auto_barrier
        self.ofproto = OFPP
        self.ofproto_parser = parser
        self.sent: list[object] = []
        self.xid = 0
        self.fail_flow_priorities: set[int] = set()

    def set_xid(self, msg: object) -> int:
        self.xid = (self.xid + 1) & OFPP.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg: object, close_socket: bool = False) -> None:
        if getattr(msg, "xid", None) is None:
            self.set_xid(msg)
        self.sent.append(msg)
        if (
            isinstance(msg, parser.OFPFlowMod)
            and msg.priority in self.fail_flow_priorities
        ):
            self._report_flow_error(msg)
        if (
            isinstance(msg, parser.OFPBarrierRequest)
            and self.auto_barrier
            and self.controller is not None
        ):
            self.controller.barrier_reply_handler(
                SimpleNamespace(
                    msg=SimpleNamespace(datapath=self, xid=msg.xid)
                )
            )

    def _report_flow_error(self, msg: object) -> None:
        if self.controller is None:
            return
        # OFPErrorMsg.data carries the first bytes of the failed request,
        # including its OpenFlow header and transaction id at bytes 4..7.
        data = struct.pack("!BBHI", 4, OFPP.OFPT_FLOW_MOD, 8, msg.xid)
        self.controller.ofp_error_handler(
            SimpleNamespace(
                msg=SimpleNamespace(
                    datapath=self,
                    type=OFPP.OFPET_FLOW_MOD_FAILED,
                    code=OFPP.OFPFMFC_UNKNOWN,
                    data=data,
                )
            )
        )


def flow_entries(messages: list[object], priority: int) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for msg in messages:
        if not isinstance(msg, parser.OFPFlowMod):
            continue
        if msg.command != OFPP.OFPFC_ADD or msg.priority != priority:
            continue
        actions = msg.instructions[0].actions if msg.instructions else []
        entries.append(
            {
                "in_port": msg.match.get("in_port"),
                "eth_src": msg.match.get("eth_src"),
                "eth_dst": msg.match.get("eth_dst"),
                "eth_type": msg.match.get("eth_type"),
                "out_port": actions[0].port if actions else None,
            }
        )
    return entries


def packet_outs(messages: list[object]) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    for msg in messages:
        if isinstance(msg, parser.OFPPacketOut):
            result.append((msg.actions[0].port, bytes(msg.data)))
    return result


def arp_reply_outs(
    messages: list[object],
) -> list[tuple[int, object]]:
    replies: list[tuple[int, object]] = []
    for port, data in packet_outs(messages):
        pkt = packet.Packet(data)
        arp_packet = pkt.get_protocol(arp.arp)
        if arp_packet is not None and arp_packet.opcode == arp.ARP_REPLY:
            replies.append((port, arp_packet))
    return replies


def barrier_count(messages: list[object]) -> int:
    return sum(
        1 for msg in messages if isinstance(msg, parser.OFPBarrierRequest)
    )


def arp_frame(
    opcode: int,
    eth_src: str,
    eth_dst: str,
    src_mac: str,
    src_ip: str,
    dst_mac: str,
    dst_ip: str,
) -> bytes:
    pkt = packet.Packet()
    pkt.add_protocol(
        ethernet.ethernet(
            dst=eth_dst,
            src=eth_src,
            ethertype=ether_types.ETH_TYPE_ARP,
        )
    )
    pkt.add_protocol(
        arp.arp(
            opcode=opcode,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip,
        )
    )
    pkt.serialize()
    return bytes(pkt.data)


def ipv4_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str) -> bytes:
    pkt = packet.Packet()
    pkt.add_protocol(
        ethernet.ethernet(
            dst=dst_mac,
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_IP,
        )
    )
    pkt.add_protocol(
        ipv4.ipv4(src=src_ip, dst=dst_ip, proto=6, ttl=64)
    )
    pkt.serialize()
    return bytes(pkt.data)


class ControllerFlowTests(unittest.TestCase):
    H1_MAC = "02:00:00:00:00:01"
    H1_IP = "10.0.0.1"
    H2_MAC = "02:00:00:00:00:02"
    H2_IP = "10.0.0.2"
    H3_MAC = "02:00:00:00:00:03"
    H3_IP = "10.0.0.3"

    def setUp(self) -> None:
        self.controller = SDNBackupController()

    def enter_switch(
        self,
        dpid: int,
        ports: tuple[int, ...],
        *,
        auto_barrier: bool = True,
    ) -> FakeDatapath:
        datapath = FakeDatapath(
            dpid, self.controller, auto_barrier=auto_barrier
        )
        self.controller.switch_features_handler(
            SimpleNamespace(
                msg=SimpleNamespace(
                    datapath=datapath,
                    n_buffers=256,
                    n_tables=254,
                )
            )
        )
        self.controller.switch_enter_handler(
            SimpleNamespace(
                switch=SimpleNamespace(
                    dp=datapath,
                    ports=[FakePort(port_no) for port_no in ports],
                )
            )
        )
        return datapath

    def add_link(
        self,
        first_dpid: int,
        first_port: int,
        second_dpid: int,
        second_port: int,
    ) -> None:
        self.controller.link_add_handler(
            SimpleNamespace(
                link=SimpleNamespace(
                    src=SimpleNamespace(
                        dpid=first_dpid, port_no=first_port
                    ),
                    dst=SimpleNamespace(
                        dpid=second_dpid, port_no=second_port
                    ),
                )
            )
        )

    def remove_link(
        self,
        first_dpid: int,
        first_port: int,
        second_dpid: int,
        second_port: int,
    ) -> None:
        self.controller.link_delete_handler(
            SimpleNamespace(
                link=SimpleNamespace(
                    src=SimpleNamespace(
                        dpid=first_dpid, port_no=first_port
                    ),
                    dst=SimpleNamespace(
                        dpid=second_dpid, port_no=second_port
                    ),
                )
            )
        )

    def build_ring(
        self, *, auto_barrier: bool = True
    ) -> tuple[FakeDatapath, FakeDatapath, FakeDatapath, FakeDatapath]:
        s1 = self.enter_switch(1, (1, 2, 3), auto_barrier=auto_barrier)
        s2 = self.enter_switch(2, (1, 2), auto_barrier=auto_barrier)
        s3 = self.enter_switch(3, (1, 2), auto_barrier=auto_barrier)
        s4 = self.enter_switch(
            4, (1, 2, 3, 4), auto_barrier=auto_barrier
        )
        self.add_link(1, 2, 2, 1)
        self.add_link(1, 3, 3, 1)
        self.add_link(2, 2, 4, 1)
        self.add_link(3, 2, 4, 2)
        return s1, s2, s3, s4

    def reply_barriers(self, *datapaths: FakeDatapath) -> None:
        for datapath in datapaths:
            for msg in list(datapath.sent):
                if not isinstance(msg, parser.OFPBarrierRequest):
                    continue
                self.controller.barrier_reply_handler(
                    SimpleNamespace(
                        msg=SimpleNamespace(
                            datapath=datapath, xid=msg.xid
                        )
                    )
                )

    def set_port_live(
        self, dpid: int, port_no: int, live: bool
    ) -> None:
        self.controller.port_modify_handler(
            SimpleNamespace(
                port=FakePort(port_no, live=live, dpid=dpid)
            )
        )

    def reconcile_ports(
        self,
        datapath: FakeDatapath,
        ports: list[FakePort],
        *,
        flags: int = 0,
        xid: int = 1,
    ) -> None:
        self.controller.port_desc_stats_reply_handler(
            SimpleNamespace(
                msg=SimpleNamespace(
                    datapath=datapath,
                    body=ports,
                    flags=flags,
                    xid=xid,
                )
            )
        )

    def ofp_port_status(
        self,
        datapath: FakeDatapath,
        port_no: int,
        live: bool,
        *,
        reason: int | None = None,
    ) -> None:
        self.controller.ofp_port_status_handler(
            SimpleNamespace(
                msg=SimpleNamespace(
                    datapath=datapath,
                    reason=(
                        OFPP.OFPPR_MODIFY if reason is None else reason
                    ),
                    desc=FakePort(
                        port_no, live=live, dpid=datapath.id
                    ),
                )
            )
        )

    def packet_in(
        self, datapath: FakeDatapath, in_port: int, data: bytes
    ) -> None:
        self.controller.packet_in_handler(
            SimpleNamespace(
                msg=SimpleNamespace(
                    datapath=datapath,
                    match={"in_port": in_port},
                    data=data,
                )
            )
        )

    def learn_gratuitous(self, datapath: FakeDatapath, port: int) -> None:
        self.learn_host(
            datapath, port, self.H2_MAC, self.H2_IP
        )

    def learn_host(
        self,
        datapath: FakeDatapath,
        port: int,
        mac: str,
        ip: str,
    ) -> None:
        self.packet_in(
            datapath,
            port,
            arp_frame(
                arp.ARP_REQUEST,
                eth_src=mac,
                eth_dst="ff:ff:ff:ff:ff:ff",
                src_mac=mac,
                src_ip=ip,
                dst_mac="00:00:00:00:00:00",
                dst_ip=ip,
            ),
        )

    def learn_expected_hosts(
        self,
        s1: FakeDatapath,
        s4: FakeDatapath,
    ) -> None:
        self.learn_host(s1, 1, self.H1_MAC, self.H1_IP)
        self.learn_host(s4, 3, self.H2_MAC, self.H2_IP)
        self.learn_host(s4, 4, self.H3_MAC, self.H3_IP)

    def assert_host_location(
        self, mac: str, dpid: int, port_no: int
    ) -> None:
        host = self.controller.hosts_by_mac.get(mac)
        self.assertIsNotNone(host)
        self.assertEqual((host.dpid, host.port_no), (dpid, port_no))

    def remove_all_links(self) -> None:
        self.remove_link(1, 2, 2, 1)
        self.remove_link(1, 3, 3, 1)
        self.remove_link(2, 2, 4, 1)
        self.remove_link(3, 2, 4, 2)

    def request_h2(self, datapath: FakeDatapath, port: int) -> None:
        self.packet_in(
            datapath,
            port,
            arp_frame(
                arp.ARP_REQUEST,
                eth_src=self.H1_MAC,
                eth_dst="ff:ff:ff:ff:ff:ff",
                src_mac=self.H1_MAC,
                src_ip=self.H1_IP,
                dst_mac="00:00:00:00:00:00",
                dst_ip=self.H2_IP,
            ),
        )

    def test_base_flows_are_table_miss_drop_and_arp_punt(self) -> None:
        datapath = self.enter_switch(1, (1, 2))

        miss = flow_entries(datapath.sent, PRIORITY_TABLE_MISS)
        arp_flows = flow_entries(datapath.sent, PRIORITY_ARP)

        self.assertEqual(len(miss), 1)
        self.assertIsNone(miss[0]["eth_type"])
        self.assertIsNone(miss[0]["out_port"])
        self.assertEqual(len(arp_flows), 1)
        self.assertEqual(arp_flows[0]["eth_type"], ether_types.ETH_TYPE_ARP)
        self.assertEqual(arp_flows[0]["out_port"], OFPP.OFPP_CONTROLLER)

    def test_arp_proxy_installs_bidirectional_rules_on_every_switch(self) -> None:
        s1 = self.enter_switch(1, (1, 2))
        s2 = self.enter_switch(2, (1, 3))
        self.add_link(1, 2, 2, 1)
        self.learn_gratuitous(s2, 3)

        h2_punts = flow_entries(s2.sent, PRIORITY_HOST_PUNT)
        self.assertIn(
            {
                "in_port": 3,
                "eth_src": self.H2_MAC,
                "eth_dst": None,
                "eth_type": None,
                "out_port": OFPP.OFPP_CONTROLLER,
            },
            h2_punts,
        )

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.request_h2(s1, 1)

        s1_routes = flow_entries(s1.sent, PRIORITY_ROUTE)
        s2_routes = flow_entries(s2.sent, PRIORITY_ROUTE)
        h1_to_h2 = [
            entry
            for entry in s1_routes
            if entry["eth_src"] == self.H1_MAC
            and entry["eth_dst"] == self.H2_MAC
        ]
        h2_to_h1 = [
            entry
            for entry in s1_routes
            if entry["eth_src"] == self.H2_MAC
            and entry["eth_dst"] == self.H1_MAC
        ]
        self.assertEqual(
            [(entry["in_port"], entry["out_port"]) for entry in h1_to_h2],
            [(1, 2)],
        )
        self.assertEqual(
            [(entry["in_port"], entry["out_port"]) for entry in h2_to_h1],
            [(2, 1)],
        )
        self.assertEqual(
            {
                (entry["in_port"], entry["out_port"])
                for entry in s2_routes
                if entry["eth_src"] == self.H1_MAC
                and entry["eth_dst"] == self.H2_MAC
            },
            {(1, 3)},
        )
        self.assertEqual(
            {
                (entry["in_port"], entry["out_port"])
                for entry in s2_routes
                if entry["eth_src"] == self.H2_MAC
                and entry["eth_dst"] == self.H1_MAC
            },
            {(3, 1)},
        )

        outs = packet_outs(s1.sent)
        self.assertTrue(outs)
        proxy_port, proxy_data = outs[-1]
        self.assertEqual(proxy_port, 1)
        proxy_packet = packet.Packet(proxy_data)
        proxy_eth = proxy_packet.get_protocol(ethernet.ethernet)
        proxy_arp = proxy_packet.get_protocol(arp.arp)
        self.assertEqual(proxy_eth.src, self.H2_MAC)
        self.assertEqual(proxy_eth.dst, self.H1_MAC)
        self.assertEqual(proxy_arp.opcode, arp.ARP_REPLY)
        self.assertEqual(proxy_arp.src_mac, self.H2_MAC)
        self.assertEqual(proxy_arp.src_ip, self.H2_IP)
        self.assertEqual(proxy_arp.dst_ip, self.H1_IP)

        text = "\n".join(captured.output)
        self.assertIn("event=ARP_PROXY", text)
        self.assertIn("event=ROUTE_SELECT", text)
        self.assertIn("event=FWD_FLOW_ADD", text)

    def test_unknown_arp_is_flooded_only_over_the_bfs_tree(self) -> None:
        s1 = self.enter_switch(1, (1, 2))
        s2 = self.enter_switch(2, (1, 2, 4))
        s3 = self.enter_switch(3, (1, 3))
        self.add_link(1, 2, 2, 1)
        self.add_link(2, 2, 3, 1)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s1,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        egress = {
            (datapath.id, port)
            for datapath in (s1, s2, s3)
            for port, _ in packet_outs(datapath.sent)
        }
        self.assertEqual(egress, {(1, 2), (2, 2), (2, 4), (3, 3)})
        self.assertNotIn((1, 1), egress)
        self.assertNotIn((2, 1), egress)
        self.assertNotIn((3, 1), egress)

        text = "\n".join(captured.output)
        self.assertIn("event=ARP_FLOOD", text)

    def test_link_failure_deletes_stale_rules_and_replaces_the_route(self) -> None:
        s1 = self.enter_switch(1, (1, 2, 3))
        s2 = self.enter_switch(2, (1, 2))
        s3 = self.enter_switch(3, (1, 2))
        s4 = self.enter_switch(4, (1, 2, 3))
        self.add_link(1, 2, 2, 1)
        self.add_link(1, 3, 3, 1)
        self.add_link(2, 2, 4, 1)
        self.add_link(3, 2, 4, 2)
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)

        routes = flow_entries(s1.sent, PRIORITY_ROUTE)
        active = next(
            entry
            for entry in routes
            if entry["eth_src"] == self.H1_MAC
            and entry["eth_dst"] == self.H2_MAC
        )
        selected_port = active["out_port"]
        self.assertIn(selected_port, {2, 3})

        marker = len(s1.sent)
        if selected_port == 2:
            self.remove_link(1, 2, 2, 1)
            expected_path = (1, 3, 4)
            expected_port = 3
        else:
            self.remove_link(1, 3, 3, 1)
            expected_path = (1, 2, 4)
            expected_port = 2

        new_messages = s1.sent[marker:]
        deletes = [
            msg
            for msg in new_messages
            if isinstance(msg, parser.OFPFlowMod)
            and msg.command == OFPP.OFPFC_DELETE
        ]
        self.assertTrue(deletes)
        self.assertTrue(
            any(
                msg.cookie == FLOW_COOKIE
                and msg.cookie_mask == FLOW_COOKIE_MASK
                for msg in deletes
            )
        )

        new_routes = flow_entries(new_messages, PRIORITY_ROUTE)
        replaced = next(
            entry
            for entry in new_routes
            if entry["eth_src"] == self.H1_MAC
            and entry["eth_dst"] == self.H2_MAC
        )
        self.assertEqual(replaced["out_port"], expected_port)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertEqual(self.controller.route_paths[pair].nodes, expected_path)

    def test_known_data_packet_is_sent_over_the_installed_path(self) -> None:
        s1 = self.enter_switch(1, (1, 2))
        s2 = self.enter_switch(2, (1, 3))
        self.add_link(1, 2, 2, 1)
        self.learn_gratuitous(s2, 3)
        self.request_h2(s1, 1)

        marker = len(s1.sent)
        frame = ipv4_frame(
            self.H1_MAC, self.H2_MAC, self.H1_IP, self.H2_IP
        )
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(s1, 1, frame)

        outs = [
            (port, data)
            for port, data in packet_outs(s1.sent[marker:])
            if data == frame
        ]
        self.assertEqual(outs, [(2, frame)])
        self.assertIn("event=DATA_FORWARD", "\n".join(captured.output))


    def test_arp_proxy_waits_for_every_switch_barrier(self) -> None:
        s1, s2, s3, s4 = self.build_ring(auto_barrier=False)
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.request_h2(s1, 1)

        self.assertNotIn(pair, self.controller.route_paths)
        install = self.controller.route_installs[pair]
        self.assertEqual(len(install.pending_barriers), 3)
        self.assertEqual(arp_reply_outs(s1.sent), [])
        self.assertIn("event=ARP_PROXY_DEFER", "\n".join(captured.output))

        barrier_datapaths = [
            datapath
            for datapath in (s1, s2, s3, s4)
            if barrier_count(datapath.sent)
        ]
        self.assertEqual(len(barrier_datapaths), 3)
        self.reply_barriers(*barrier_datapaths[:2])
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertEqual(arp_reply_outs(s1.sent), [])

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.reply_barriers(barrier_datapaths[2])

        self.assertIn(pair, self.controller.route_paths)
        self.assertTrue(arp_reply_outs(s1.sent))
        text = "\n".join(captured.output)
        self.assertIn("event=ROUTE_INSTALLED", text)
        self.assertNotIn("event=ROUTE_INSTALL_FAILED", text)

    def test_barrier_xids_are_tracked_per_datapath(self) -> None:
        s1 = self.enter_switch(1, (1, 2), auto_barrier=False)
        s2 = self.enter_switch(2, (1, 3), auto_barrier=False)
        self.add_link(1, 2, 2, 1)
        self.learn_gratuitous(s2, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        s1.xid = 100
        s2.xid = 100

        self.request_h2(s1, 1)
        self.assertNotIn(pair, self.controller.route_paths)
        install = self.controller.route_installs[pair]
        self.assertEqual(install.pending_barriers, {1, 2})
        xids_s1 = {xid for dpid, xid in install.xids if dpid == 1}
        xids_s2 = {xid for dpid, xid in install.xids if dpid == 2}
        # Both switches start at xid 100, so the same numeric xids are in use
        # on two datapaths at once.  They must remain independently tracked.
        self.assertTrue(xids_s1 & xids_s2)

        self.reply_barriers(s1)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertEqual(install.pending_barriers, {2})
        self.reply_barriers(s2)
        self.assertIn(pair, self.controller.route_paths)

    def test_flowmod_error_never_reports_route_installed_or_proxy(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        s4.fail_flow_priorities.add(PRIORITY_ROUTE)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.request_h2(s1, 1)

        text = "\n".join(captured.output)
        self.assertIn("event=ROUTE_INSTALL_FAILED", text)
        self.assertIn("event=OFP_ERROR", text)
        self.assertNotIn("event=ROUTE_INSTALLED", text)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertEqual(arp_reply_outs(s1.sent), [])

    def test_barrier_timeout_never_reports_route_installed(self) -> None:
        s1, s2, s3, s4 = self.build_ring(auto_barrier=False)
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        self.request_h2(s1, 1)

        install = self.controller.route_installs[pair]
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller._barrier_timeout(install)

        text = "\n".join(captured.output)
        self.assertIn("event=ROUTE_INSTALL_FAILED", text)
        self.assertIn("reason=barrier-timeout", text)
        self.assertNotIn("event=ROUTE_INSTALLED", text)
        self.assertTrue(install.failed)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertEqual(arp_reply_outs(s1.sent), [])

    def test_missing_datapath_defers_route_install(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        self.controller.datapaths.pop(4)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.request_h2(s1, 1)

        text = "\n".join(captured.output)
        self.assertIn("event=ROUTE_DEFER", text)
        self.assertIn("missing_dpids=", text)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertEqual(arp_reply_outs(s1.sent), [])

        self.controller.datapaths[4] = s4
        self.request_h2(s1, 1)
        self.assertIn(pair, self.controller.route_paths)
        self.assertTrue(arp_reply_outs(s1.sent))

    def test_first_data_packet_waits_for_route_barriers(self) -> None:
        s1, s2, s3, s4 = self.build_ring(auto_barrier=False)
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        frame = ipv4_frame(
            self.H1_MAC, self.H2_MAC, self.H1_IP, self.H2_IP
        )

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(s1, 1, frame)

        self.assertIn("event=DATA_DEFER", "\n".join(captured.output))
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertFalse(
            any(data == frame for _, data in packet_outs(s1.sent))
        )
        barrier_datapaths = [
            datapath
            for datapath in (s1, s2, s3, s4)
            if barrier_count(datapath.sent)
        ]
        self.assertEqual(len(barrier_datapaths), 3)

        self.reply_barriers(*barrier_datapaths)
        self.assertIn(pair, self.controller.route_paths)
        frame_outs = [
            (port, data)
            for port, data in packet_outs(s1.sent)
            if data == frame
        ]
        self.assertEqual(len(frame_outs), 1)
        last_barrier = max(
            index
            for index, msg in enumerate(s1.sent)
            if isinstance(msg, parser.OFPBarrierRequest)
        )
        frame_index = max(
            index
            for index, msg in enumerate(s1.sent)
            if isinstance(msg, parser.OFPPacketOut)
            and bytes(msg.data) == frame
        )
        self.assertGreater(frame_index, last_barrier)

    def test_stale_arp_mapping_never_produces_proxy_reply(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        # Simulate a missed port-down event: the graph knows the port is down
        # but the host/ARP caches still contain the old location.
        self.controller.graph.set_port_state(4, 3, False)
        marker = len(s1.sent)
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.request_h2(s1, 1)

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(self.H2_IP, self.controller.hosts_by_ip)
        self.assertEqual(
            arp_reply_outs(s1.sent[marker:]), []
        )
        text = "\n".join(captured.output)
        self.assertIn("event=ARP_LOOKUP_STALE", text)
        self.assertIn("event=HOST_FORGET", text)
        self.assertIn("reason=stale-arp-mapping", text)

    def test_port_down_forgets_host_and_port_up_relearns(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.set_port_live(4, 3, False)

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(self.H2_IP, self.controller.hosts_by_ip)
        self.assertNotIn(pair, self.controller.route_paths)
        text = "\n".join(captured.output)
        self.assertIn("event=HOST_FORGET", text)
        self.assertIn("reason=port-modify-down", text)

        marker = len(s1.sent)
        self.request_h2(s1, 1)
        self.assertEqual(arp_reply_outs(s1.sent[marker:]), [])

        self.set_port_live(4, 3, True)
        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.learn_gratuitous(s4, 3)
        self.assertIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertEqual(
            self.controller.hosts_by_ip.get(self.H2_IP),
            self.H2_MAC,
        )
        self.request_h2(s1, 1)
        self.assertTrue(arp_reply_outs(s1.sent))

    def test_ofp_port_status_down_forgets_host(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.ofp_port_status(s4, 3, False)

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(self.H2_IP, self.controller.hosts_by_ip)
        self.assertNotIn(pair, self.controller.route_paths)
        text = "\n".join(captured.output)
        self.assertIn("event=PORT_STATUS", text)
        self.assertIn("up=False", text)
        self.assertIn("reason=ofp-port-modify-down", text)

        marker = len(s1.sent)
        self.request_h2(s1, 1)
        self.assertEqual(arp_reply_outs(s1.sent[marker:]), [])

        self.ofp_port_status(s4, 3, True)
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        self.assertTrue(arp_reply_outs(s1.sent))

    def test_port_reconciliation_fallback_detects_missed_down(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.reconcile_ports(
                s4,
                [
                    FakePort(1, dpid=4),
                    FakePort(2, dpid=4),
                    FakePort(3, live=False, dpid=4),
                    FakePort(4, dpid=4),
                ],
            )

        self.assertFalse(self.controller.graph.port_is_up(4, 3))
        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(pair, self.controller.route_paths)
        text = "\n".join(captured.output)
        self.assertIn("event=PORT_RECONCILE", text)
        self.assertIn("down=[3]", text)
        self.assertIn("reason=port-reconcile-down", text)

        marker = len(s1.sent)
        self.request_h2(s1, 1)
        self.assertEqual(arp_reply_outs(s1.sent[marker:]), [])

        self.reconcile_ports(
            s4,
            [
                FakePort(1, dpid=4),
                FakePort(2, dpid=4),
                FakePort(3, dpid=4),
                FakePort(4, dpid=4),
            ],
        )
        self.assertTrue(self.controller.graph.port_is_up(4, 3))
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        self.assertTrue(arp_reply_outs(s1.sent))

    def test_port_reconciliation_ignores_empty_and_partial_replies(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.reconcile_ports(s4, [])
        self.assertIn(
            "event=PORT_RECONCILE_EMPTY", "\n".join(captured.output)
        )
        self.assertIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertTrue(self.controller.graph.port_is_up(4, 3))
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.reconcile_ports(
                s4,
                [FakePort(1, dpid=4), FakePort(2, dpid=4)],
                flags=OFPP.OFPMPF_REPLY_MORE,
                xid=7,
            )
            self.reconcile_ports(
                s4,
                [FakePort(3, dpid=4), FakePort(4, dpid=4)],
                xid=7,
            )
        text = "\n".join(captured.output)
        self.assertIn("event=PORT_RECONCILE_PARTIAL", text)
        self.assertIn("event=PORT_RECONCILE dpid=", text)
        self.assertIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertTrue(self.controller.graph.port_is_up(4, 3))
        self.assertIn(pair, self.controller.route_paths)

    def test_deferred_proxy_is_cancelled_when_target_ip_changes(self) -> None:
        s1, s2, s3, s4 = self.build_ring(auto_barrier=False)
        self.learn_gratuitous(s4, 3)
        pair = (self.H1_MAC, self.H2_MAC)
        self.request_h2(s1, 1)
        self.assertNotIn(pair, self.controller.route_paths)

        # The target re-addresses while the route is still awaiting barriers.
        new_ip = "10.0.0.22"
        self.controller._remember_host(self.H2_MAC, 4, 3, new_ip)
        self.assertEqual(
            self.controller.hosts_by_ip.get(new_ip), self.H2_MAC
        )
        self.assertNotIn(self.H2_IP, self.controller.hosts_by_ip)

        barrier_datapaths = [
            datapath
            for datapath in (s1, s2, s3, s4)
            if barrier_count(datapath.sent)
        ]
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.reply_barriers(*barrier_datapaths)

        self.assertIn(pair, self.controller.route_paths)
        self.assertEqual(arp_reply_outs(s1.sent), [])
        self.assertIn(
            "reason=stale-ip-mapping", "\n".join(captured.output)
        )

    def test_port_delete_forgets_host_and_route(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.port_delete_handler(
                SimpleNamespace(port=FakePort(3, dpid=4))
            )

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(self.H2_IP, self.controller.hosts_by_ip)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertNotIn(3, self.controller.graph.switch(4).ports)
        text = "\n".join(captured.output)
        self.assertIn("event=PORT_DELETE", text)
        self.assertIn("reason=port-delete", text)

    def test_link_reclassification_forgets_host(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.link_add_handler(
                SimpleNamespace(
                    link=SimpleNamespace(
                        src=SimpleNamespace(dpid=4, port_no=3),
                        dst=SimpleNamespace(dpid=5, port_no=1),
                    )
                )
            )

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertIn(
            "reason=port-reclassified-link", "\n".join(captured.output)
        )

    def test_switch_leave_forgets_hosts(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_gratuitous(s4, 3)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.switch_leave_handler(
                SimpleNamespace(
                    switch=SimpleNamespace(dp=SimpleNamespace(id=4))
                )
            )

        self.assertNotIn(self.H2_MAC, self.controller.hosts_by_mac)
        self.assertNotIn(pair, self.controller.route_paths)
        self.assertFalse(self.controller.graph.has_switch(4))
        text = "\n".join(captured.output)
        self.assertIn("event=SWITCH_LEAVE", text)
        self.assertIn("reason=switch-leave", text)

    def test_full_topology_arp_flood_has_exact_egress(self) -> None:
        s1, s2, s3, s4 = self.build_ring()

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s1,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        egress = {
            (datapath.id, port)
            for datapath in (s1, s2, s3, s4)
            for port, _ in packet_outs(datapath.sent)
        }
        self.assertEqual(
            egress,
            {(1, 2), (1, 3), (2, 2), (4, 3), (4, 4)},
        )
        self.assertNotIn((1, 1), egress)
        self.assertNotIn((2, 1), egress)
        self.assertNotIn((3, 1), egress)
        self.assertNotIn((3, 2), egress)
        self.assertIn(
            "event=ARP_FLOOD_FILTER", "\n".join(captured.output)
        )

    def test_all_links_expire_does_not_move_hosts_to_transit_ports(
        self,
    ) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_expected_hosts(s1, s4)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.remove_all_links()

        text = "\n".join(captured.output)
        self.assertEqual(self.controller._topology_state, "degraded")
        self.assertIn("event=TOPOLOGY_DEGRADED", text)
        self.assertIn("reason=all-links-expired-ports-up", text)
        self.assert_host_location(self.H1_MAC, 1, 1)
        self.assert_host_location(self.H2_MAC, 4, 3)
        self.assert_host_location(self.H3_MAC, 4, 4)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s3,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        text = "\n".join(captured.output)
        self.assertIn("event=PACKET_IN_DROP", text)
        self.assertIn("reason=transit-port", text)
        self.assertNotIn("event=HOST_MOVE", text)
        self.assert_host_location(self.H1_MAC, 1, 1)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.host_move_handler(
                SimpleNamespace(
                    dst=SimpleNamespace(
                        mac=self.H1_MAC,
                        port=SimpleNamespace(dpid=3, port_no=1),
                        ipv4=[],
                    )
                )
            )

        text = "\n".join(captured.output)
        self.assertIn("event=HOST_REJECT", text)
        self.assertIn("reason=transit-port", text)
        self.assertIn("preserved=", text)
        self.assertNotIn(
            f"HOST_FORGET mac={self.H1_MAC}", text
        )
        self.assert_host_location(self.H1_MAC, 1, 1)
        self.assert_host_location(self.H2_MAC, 4, 3)
        self.assert_host_location(self.H3_MAC, 4, 4)

        marker = len(s1.sent)
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s1,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        text = "\n".join(captured.output)
        self.assertIn("event=ARP_FLOOD_SUPPRESSED", text)
        self.assertIn("reason=topology-degraded", text)
        self.assertEqual(packet_outs(s1.sent[marker:]), [])
        self.assert_host_location(self.H1_MAC, 1, 1)
        self.assert_host_location(self.H2_MAC, 4, 3)
        self.assert_host_location(self.H3_MAC, 4, 4)

    def test_false_host_move_is_rejected_and_preserves_location(
        self,
    ) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_host(s1, 1, self.H1_MAC, self.H1_IP)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.host_move_handler(
                SimpleNamespace(
                    dst=SimpleNamespace(
                        mac=self.H1_MAC,
                        port=SimpleNamespace(dpid=3, port_no=1),
                        ipv4=[],
                    )
                )
            )

        text = "\n".join(captured.output)
        self.assertIn("event=HOST_REJECT", text)
        self.assertIn("reason=transit-port", text)
        self.assertIn("preserved=", text)
        self.assertNotIn(f"HOST_FORGET mac={self.H1_MAC}", text)
        self.assert_host_location(self.H1_MAC, 1, 1)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.host_add_handler(
                SimpleNamespace(
                    host=SimpleNamespace(
                        mac=self.H1_MAC,
                        port=SimpleNamespace(dpid=3, port_no=1),
                        ipv4=[],
                    )
                )
            )

        text = "\n".join(captured.output)
        self.assertIn("event=HOST_REJECT", text)
        self.assertIn("reason=transit-port", text)
        self.assertNotIn(f"HOST_FORGET mac={self.H1_MAC}", text)
        self.assert_host_location(self.H1_MAC, 1, 1)

    def test_packet_in_on_transit_port_is_dropped(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_host(s1, 1, self.H1_MAC, self.H1_IP)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s3,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        text = "\n".join(captured.output)
        self.assertIn("event=PACKET_IN_DROP", text)
        self.assertIn("reason=transit-port", text)
        self.assertNotIn("event=HOST_MOVE", text)
        self.assert_host_location(self.H1_MAC, 1, 1)

    def test_arp_flood_never_targets_removed_transit_ports(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_host(s1, 1, self.H1_MAC, self.H1_IP)
        self.remove_link(1, 2, 2, 1)

        marker = len(s1.sent)
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s1,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        egress = {
            (datapath.id, port)
            for datapath in (s1, s2, s3, s4)
            for port, _ in packet_outs(datapath.sent)
        }
        self.assertNotIn((1, 2), egress)
        self.assertEqual(
            egress,
            {(1, 3), (3, 2), (4, 1), (4, 3), (4, 4)},
        )
        for dpid, port_no in egress:
            if self.controller.graph.is_transit_port(dpid, port_no):
                self.assertIn(
                    port_no, self.controller.graph.link_ports(dpid)
                )
        self.assertIn(
            "event=ARP_FLOOD", "\n".join(captured.output)
        )

    def test_degraded_topology_suppresses_arp_flood(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_host(s1, 1, self.H1_MAC, self.H1_IP)
        self.remove_all_links()
        self.assertEqual(self.controller._topology_state, "degraded")

        marker = len(s1.sent)
        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.packet_in(
                s1,
                1,
                arp_frame(
                    arp.ARP_REQUEST,
                    eth_src=self.H1_MAC,
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    src_mac=self.H1_MAC,
                    src_ip=self.H1_IP,
                    dst_mac="00:00:00:00:00:00",
                    dst_ip="10.0.0.99",
                ),
            )

        text = "\n".join(captured.output)
        self.assertIn("event=ARP_FLOOD_SUPPRESSED", text)
        self.assertIn("reason=topology-degraded", text)
        self.assertEqual(packet_outs(s1.sent[marker:]), [])

    def test_topology_recovery_restores_routes_and_keeps_hosts(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_expected_hosts(s1, s4)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        self.remove_all_links()
        self.assertEqual(self.controller._topology_state, "degraded")
        self.assertNotIn(pair, self.controller.route_paths)
        self.assert_host_location(self.H1_MAC, 1, 1)
        self.assert_host_location(self.H2_MAC, 4, 3)
        self.assert_host_location(self.H3_MAC, 4, 4)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.add_link(1, 2, 2, 1)
            self.add_link(1, 3, 3, 1)
            self.add_link(2, 2, 4, 1)
            self.add_link(3, 2, 4, 2)

        text = "\n".join(captured.output)
        self.assertIn("event=TOPOLOGY_RECOVERED", text)
        self.assertEqual(self.controller._topology_state, "healthy")
        self.assert_host_location(self.H1_MAC, 1, 1)
        self.assert_host_location(self.H2_MAC, 4, 3)
        self.assert_host_location(self.H3_MAC, 4, 4)
        self.assertIn(pair, self.controller.route_paths)

        marker = len(s1.sent)
        self.request_h2(s1, 1)
        self.assertTrue(arp_reply_outs(s1.sent[marker:]))

    def test_explicit_port_delete_clears_historical_transit_state(
        self,
    ) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.remove_all_links()
        self.assertTrue(self.controller.graph.is_transit_port(4, 2))

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.port_delete_handler(
                SimpleNamespace(port=FakePort(2, dpid=4))
            )

        self.assertFalse(self.controller.graph.is_transit_port(4, 2))
        self.assertNotIn(2, self.controller.graph.switch(4).ports)
        self.assertIn(
            "event=PORT_DELETE", "\n".join(captured.output)
        )

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.port_add_handler(
                SimpleNamespace(port=FakePort(2, dpid=4))
            )

        self.assertIn(2, self.controller.graph.host_ports(4))
        self.assertIn("event=PORT_ADD", "\n".join(captured.output))

    def test_topology_health_detects_lldp_stall(self) -> None:
        self.build_ring()
        self.controller._last_lldp_at = (
            time.monotonic() - (LLDP_STALL_SECONDS + 5.0)
        )

        with self.assertLogs(LOGGER, level="INFO") as captured:
            state = self.controller._evaluate_topology_health()

        self.assertEqual(state, "healthy")
        self.assertIn(
            "event=TOPOLOGY_LLDP_STALL", "\n".join(captured.output)
        )

    def test_confirmed_physical_failure_is_not_reported_as_degraded(
        self,
    ) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.remove_all_links()
        self.assertEqual(self.controller._topology_state, "degraded")

        for node in self.controller.graph.switches:
            for port_no in self.controller.graph.transit_ports(node.dpid):
                self.controller.graph.set_port_state(
                    node.dpid, port_no, False
                )

        with self.assertLogs(LOGGER, level="INFO") as captured:
            state = self.controller._evaluate_topology_health()

        self.assertEqual(state, "down")
        self.assertIn(
            "event=TOPOLOGY_DOWN", "\n".join(captured.output)
        )

    def test_cancelled_barrier_reply_is_stale_not_untracked(
        self,
    ) -> None:
        s1, s2, s3, s4 = self.build_ring(auto_barrier=False)
        self.learn_host(s4, 3, self.H2_MAC, self.H2_IP)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        install = self.controller.route_installs[pair]
        barrier_keys = [
            key
            for key, (owner, kind) in self.controller._xid_owner.items()
            if owner is install and kind == "barrier"
        ]
        self.assertTrue(barrier_keys)

        self.controller._cancel_install(install, "test-cancel")
        self.assertNotIn(pair, self.controller.route_paths)
        dpid, xid = barrier_keys[0]

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.barrier_reply_handler(
                SimpleNamespace(
                    msg=SimpleNamespace(
                        datapath=self.controller.datapaths[dpid],
                        xid=xid,
                    )
                )
            )

        text = "\n".join(captured.output)
        self.assertIn("event=BARRIER_REPLY_STALE", text)
        self.assertNotIn("event=BARRIER_REPLY_UNTRACKED", text)
        self.assertNotIn(pair, self.controller.route_paths)

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.barrier_reply_handler(
                SimpleNamespace(
                    msg=SimpleNamespace(
                        datapath=self.controller.datapaths[dpid],
                        xid=0xFFFFFF,
                    )
                )
            )
        self.assertIn(
            "event=BARRIER_REPLY_UNTRACKED", "\n".join(captured.output)
        )

    def test_duplicate_barrier_reply_after_install_is_stale(self) -> None:
        s1, s2, s3, s4 = self.build_ring()
        self.learn_host(s4, 3, self.H2_MAC, self.H2_IP)
        self.request_h2(s1, 1)
        pair = (self.H1_MAC, self.H2_MAC)
        self.assertIn(pair, self.controller.route_paths)

        barrier_messages = [
            msg
            for msg in s1.sent
            if isinstance(msg, parser.OFPBarrierRequest)
        ]
        self.assertTrue(barrier_messages)
        duplicate = barrier_messages[-1]

        with self.assertLogs(LOGGER, level="INFO") as captured:
            self.controller.barrier_reply_handler(
                SimpleNamespace(
                    msg=SimpleNamespace(
                        datapath=s1, xid=duplicate.xid
                    )
                )
            )

        self.assertIn(
            "event=BARRIER_REPLY_STALE", "\n".join(captured.output)
        )
        self.assertIn(pair, self.controller.route_paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
