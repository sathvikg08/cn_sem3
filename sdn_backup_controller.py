"""OS-Ken SDN controller for the distributed backup network.

Stage 3 scope: topology discovery (Stage 2), explicit shortest-path forwarding,
controlled ARP handling, safe table-miss behavior, and topology-driven route
invalidation/replacement.  Load-aware equal-cost selection remains Stage 5.

The existing ``os_ken_openflow_sdn_controller.py`` is intentionally preserved
as the original reference implementation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from os_ken import cfg
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.dpid import dpid_to_str
from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3
from os_ken.topology import event as topology_event
from os_ken.topology import switches as topology_switches  # noqa: F401

from sdn.forwarding import (
    FloodTarget,
    FlowRule,
    RoutePlan,
    controlled_flood_targets,
    route_for_hosts,
)
from sdn.routing import Path, PathSelector
from sdn.topology import HostLocation, Link, NetworkGraph, PortRef

# The topology application defaults to link discovery disabled.  Enabling it
# here makes the controller self-contained even if the operator omits
# ``--observe-links`` from the command line.  The import above registers the
# options before they are overridden.
cfg.CONF.set_override("observe_links", True)
# OS-Ken installs a high-priority LLDP-to-controller flow by default.  Keep it
# explicit: a table-miss drop flow must not break link discovery.
cfg.CONF.set_override("install_lldp_flow", True)

# Ask OS-Ken to load the topology application and its LLDP machinery.
app_manager.require_app("os_ken.topology.switches")

LOGGER = logging.getLogger(__name__)

# All flow entries owned by this application share one cookie.  LLDP and other
# OS-Ken flows use cookie 0 and are therefore never removed by our purge.
FLOW_COOKIE = 0x5344420000000001
FLOW_COOKIE_MASK = 0xFFFFFFFFFFFFFFFF

PRIORITY_TABLE_MISS = 0
PRIORITY_HOST_PUNT = 50
PRIORITY_ROUTE = 100
PRIORITY_ARP = 200

TABLE_ID = 0

# A switch that does not answer a barrier request within this window is treated
# as a failed route installation.  The timeout is deliberately longer than an
# ordinary localhost control-plane round trip.
BARRIER_TIMEOUT_SECONDS = 3.0

# The topology application normally receives OFPPortStatus messages.  This
# periodic port-description reconciliation is the fallback for a missed or
# suppressed port-down event.
PORT_RECONCILE_INTERVAL_SECONDS = 5.0

# LLDP discovery is considered stale after this long without a packet-in while
# links are still present.  OS-Ken expires a link after roughly two 5-second
# check periods, so this matches the discovery timeout rather than inventing a
# second, unrelated threshold.
LLDP_STALL_SECONDS = 10.0

# Avoid flooding the log with one stall warning every reconciliation tick.
LLDP_STALL_LOG_INTERVAL_SECONDS = 30.0

# A barrier reply can arrive after the install was completed, failed or
# cancelled.  Keep a short tombstone so these late replies are reported as
# stale rather than as untracked protocol noise.  Tombstones are diagnostic
# only: they can never complete an install.
BARRIER_TOMBSTONE_TTL_SECONDS = BARRIER_TIMEOUT_SECONDS * 2
BARRIER_TOMBSTONE_MAX_ENTRIES = 1024


@dataclass
class _RouteInstall:
    """One in-flight route installation awaiting switch barriers."""

    pair: tuple[str, str]
    plan: RoutePlan
    reason: str
    epoch: int
    pending_barriers: set[int] = field(default_factory=set)
    xids: set[tuple[int, int]] = field(default_factory=set)
    success_callbacks: list[Callable[[RoutePlan], None]] = field(
        default_factory=list
    )
    failure_callbacks: list[Callable[[str], None]] = field(
        default_factory=list
    )
    failed: bool = False
    completed: bool = False
    cancelled: bool = False
    failure_reason: str = ""


@dataclass
class _RefreshState:
    """Progress of one topology-wide route refresh."""

    reason: str
    epoch: int
    pending: set[tuple[str, str]]
    installed: int = 0
    failed: int = 0


class SDNBackupController(app_manager.OSKenApp):
    """Topology-aware, shortest-path controller for the backup network."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.graph = NetworkGraph()
        self.hosts_by_mac: dict[str, HostLocation] = {}
        self.hosts_by_ip: dict[str, str] = {}
        self.tree_ports: dict[int, set[int]] = {}
        self.datapaths: dict[int, Any] = {}
        self.selector = PathSelector()
        self.resolved_pairs: set[tuple[str, str]] = set()
        self.route_paths: dict[tuple[str, str], Path] = {}
        self.route_plans: dict[tuple[str, str], RoutePlan] = {}
        self.route_installs: dict[tuple[str, str], _RouteInstall] = {}
        self.route_epoch = 0
        self.logger = LOGGER
        self._xid_owner: dict[
            tuple[int, int], tuple[_RouteInstall, str]
        ] = {}
        self._refresh: _RefreshState | None = None
        self._reconcile_started = False
        self._port_desc_parts: dict[tuple[int, int], list[Any]] = {}
        # Topology-health state (P1).  ``unknown`` is the state before the
        # first link is discovered; ``healthy`` means current links exist and
        # LLDP is not stale; ``degraded`` means links disappeared while the
        # transit ports still report up (a discovery failure); ``down`` means
        # the ports themselves are down (a confirmed physical failure).
        self._last_lldp_at: float | None = None
        self._lldp_packets = 0
        self._max_links_seen = 0
        self._topology_state = "unknown"
        self._topology_state_since = time.monotonic()
        self._last_stall_log_at = 0.0
        # Barrier XIDs removed by cleanup.  A late reply is stale, not
        # untracked, but it must never be able to complete an install.
        self._stale_barriers: dict[tuple[int, int], float] = {}

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _dpid(dpid: int) -> str:
        return dpid_to_str(dpid)

    @staticmethod
    def _port_name(port: Any) -> str:
        name = getattr(port, "name", b"")
        if isinstance(name, bytes):
            try:
                name = name.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - defensive
                name = ""
        return str(name)

    def _port_label(self, dpid: int, port_no: int, name: str = "") -> str:
        label = f"{self._dpid(dpid)}:{port_no}"
        return f"{label}({name})" if name else label

    def _tree_edge_count(self) -> int:
        count = 0
        for link in self.graph.active_links:
            if (
                link.a.port_no in self.tree_ports.get(link.a.dpid, set())
                and link.b.port_no in self.tree_ports.get(link.b.dpid, set())
            ):
                count += 1
        return count

    def _rebuild_tree(self) -> None:
        self.tree_ports = self.graph.spanning_tree_ports()
        self.logger.info(
            "event=BROADCAST_TREE edges=%d ports=%s",
            self._tree_edge_count(),
            {
                self._dpid(dpid): sorted(ports)
                for dpid, ports in sorted(self.tree_ports.items())
            },
        )

    def _log_summary(self) -> None:
        self.logger.info(
            "event=TOPOLOGY_SUMMARY switches=%d links=%d hosts=%d "
            "tree_edges=%d state=%s",
            self.graph.switch_count,
            self.graph.link_count,
            len(self.hosts_by_mac),
            self._tree_edge_count(),
            self._topology_state,
        )

    def _record_lldp_activity(self) -> None:
        self._last_lldp_at = time.monotonic()
        self._lldp_packets += 1
        if self._topology_state == "degraded":
            self.logger.info(
                "event=TOPOLOGY_LLDP_RESUMED packets=%d links=%d",
                self._lldp_packets,
                self.graph.link_count,
            )

    def _transit_ports_up(self) -> list[PortRef]:
        result: list[PortRef] = []
        for node in self.graph.switches:
            for port_no in sorted(self.graph.transit_ports(node.dpid)):
                if self.graph.port_is_up(node.dpid, port_no):
                    result.append(PortRef(node.dpid, port_no))
        return result

    def _set_topology_state(self, state: str, reason: str) -> bool:
        if state == self._topology_state:
            return False
        previous = self._topology_state
        self._topology_state = state
        self._topology_state_since = time.monotonic()
        transit_up = self._transit_ports_up()
        if state == "degraded":
            self.logger.warning(
                "event=TOPOLOGY_DEGRADED reason=%s previous=%s links=%d "
                "active_links=%d transit_ports_up=%s",
                reason,
                previous,
                self.graph.link_count,
                len(self.graph.active_links),
                [str(port) for port in transit_up],
            )
        elif state == "down":
            self.logger.warning(
                "event=TOPOLOGY_DOWN reason=%s previous=%s links=%d "
                "active_links=%d transit_ports_up=%d",
                reason,
                previous,
                self.graph.link_count,
                len(self.graph.active_links),
                len(transit_up),
            )
        elif state == "healthy" and previous in {"degraded", "down"}:
            self.logger.info(
                "event=TOPOLOGY_RECOVERED previous=%s links=%d "
                "active_links=%d lldp_packets=%d",
                previous,
                self.graph.link_count,
                len(self.graph.active_links),
                self._lldp_packets,
            )
        else:
            self.logger.info(
                "event=TOPOLOGY_STATE previous=%s new=%s reason=%s links=%d",
                previous,
                state,
                reason,
                self.graph.link_count,
            )
        return True

    def _evaluate_topology_health(self, now: float | None = None) -> str:
        """Classify the current topology and detect stale LLDP discovery."""

        now = time.monotonic() if now is None else now
        links = self.graph.link_count
        active = len(self.graph.active_links)
        transit_up = self._transit_ports_up()

        if links > 0:
            age = (
                None
                if self._last_lldp_at is None
                else max(0.0, now - self._last_lldp_at)
            )
            if age is not None and age > LLDP_STALL_SECONDS:
                if (
                    now - self._last_stall_log_at
                    >= LLDP_STALL_LOG_INTERVAL_SECONDS
                ):
                    self._last_stall_log_at = now
                    self.logger.warning(
                        "event=TOPOLOGY_LLDP_STALL age=%.1f links=%d "
                        "active_links=%d",
                        age,
                        links,
                        active,
                    )
            if active == 0:
                self._set_topology_state("down", "all-links-down")
            else:
                self._set_topology_state("healthy", "links-present")
            return self._topology_state

        if self._max_links_seen > 0:
            if transit_up:
                # Links expired while every former transit port still reports
                # up: this is a discovery failure, not a physical partition.
                self._set_topology_state(
                    "degraded", "all-links-expired-ports-up"
                )
            else:
                self._set_topology_state(
                    "down", "all-links-expired-ports-down"
                )
            return self._topology_state

        self._set_topology_state("unknown", "no-link-history")
        return self._topology_state

    @staticmethod
    def _is_unicast_mac(mac: str) -> bool:
        try:
            first = int(mac.split(":", 1)[0], 16)
        except (AttributeError, ValueError):
            return False
        return not (first & 1)

    @staticmethod
    def _ofp_port_is_live(port: Any, ofproto: Any) -> bool:
        config = int(getattr(port, "config", 0) or 0)
        state = int(getattr(port, "state", 0) or 0)
        if config & ofproto.OFPPC_PORT_DOWN:
            return False
        if state & ofproto.OFPPS_LINK_DOWN:
            return False
        return True

    def _host_attachment_reason(
        self, host: HostLocation | None
    ) -> str:
        """Return an empty string for a verified attachment, else a reason."""

        if host is None:
            return "unknown-host"
        current = self.hosts_by_mac.get(host.mac)
        if current is not host:
            return "stale-host"
        if not self.graph.has_switch(host.dpid):
            return "unknown-switch"
        if self.graph.is_transit_port(host.dpid, host.port_no):
            return "transit-port"
        node = self.graph.switch(host.dpid)
        if host.port_no not in node.ports:
            return "unknown-port"
        if not node.is_port_up(host.port_no):
            return "port-down"
        if host.port_no not in self.graph.host_ports(
            host.dpid, live_only=True
        ):
            return "not-host-facing"
        return ""

    def _host_is_connected(self, host: HostLocation | None) -> bool:
        """Return True only for a live, host-facing, non-link port."""

        return self._host_attachment_reason(host) == ""

    def _port_attachment_reason(self, dpid: int, port_no: int) -> str:
        """Return an empty string for a verified host port, else a reason."""

        if self.graph.is_transit_port(dpid, port_no):
            return "transit-port"
        if not self.graph.has_switch(dpid):
            return "unknown-switch"
        node = self.graph.switch(dpid)
        if port_no not in node.ports:
            return "unknown-port"
        if not node.is_port_up(port_no):
            return "port-down"
        if port_no not in self.graph.host_ports(dpid, live_only=True):
            return "not-host-facing"
        return ""

    def _host_port_usable(self, dpid: int, port_no: int) -> bool:
        return self._port_attachment_reason(dpid, port_no) == ""

    def _host_event_allowed(
        self, mac: str, dpid: int, port_no: int
    ) -> tuple[bool, str]:
        """Apply one admission policy to every host-learning path.

        During a degraded discovery state an existing host may refresh its
        current location, but a new host or a move to a different port is
        rejected until the topology is verified again.
        """

        reason = self._port_attachment_reason(dpid, port_no)
        if reason:
            return False, reason
        if self._topology_state == "degraded":
            existing = self.hosts_by_mac.get(mac.strip().lower())
            if (
                existing is None
                or existing.dpid != dpid
                or existing.port_no != port_no
            ):
                return False, "topology-degraded"
        return True, ""

    def _preserved_location(self, mac: str) -> str:
        host = self.hosts_by_mac.get(mac.strip().lower())
        if host is None:
            return "-"
        return f"{self._dpid(host.dpid)}:{host.port_no}"

    def _log_host_reject(
        self,
        mac: str,
        dpid: int,
        port_no: int,
        reason: str,
        *,
        event: str = "HOST_REJECT",
    ) -> None:
        self.logger.info(
            "event=%s mac=%s dpid=%s port=%s reason=%s preserved=%s",
            event,
            mac.strip().lower(),
            self._dpid(dpid),
            port_no,
            reason,
            self._preserved_location(mac),
        )

    def _remember_host(
        self,
        mac: str,
        dpid: int,
        port_no: int,
        ip: str | None = None,
    ) -> tuple[HostLocation, bool, bool] | None:
        """Learn/update a host and report ``(host, is_new, moved)``.

        The admission check is repeated here as a final guard so a future
        caller cannot bypass the transit/down-port policy.  A rejected update
        returns ``None`` and never mutates the existing location.
        """

        normalized = mac.strip().lower()
        allowed, reason = self._host_event_allowed(
            normalized, dpid, port_no
        )
        if not allowed:
            self._log_host_reject(normalized, dpid, port_no, reason)
            return None
        existing = self.hosts_by_mac.get(normalized)
        is_new = existing is None
        moved = False

        if is_new:
            host = HostLocation(
                mac=normalized, dpid=dpid, port_no=port_no, ip=ip
            )
            self.hosts_by_mac[normalized] = host
            self.logger.info(
                "event=HOST_LEARN mac=%s dpid=%s port=%s ip=%s",
                normalized,
                self._dpid(dpid),
                port_no,
                ip or "-",
            )
        else:
            host = existing
            if existing.dpid != dpid or existing.port_no != port_no:
                moved = True
                self.logger.info(
                    "event=HOST_MOVE mac=%s old=%s:%s new=%s:%s",
                    normalized,
                    self._dpid(existing.dpid),
                    existing.port_no,
                    self._dpid(dpid),
                    port_no,
                )
                existing.dpid = dpid
                existing.port_no = port_no
            if ip:
                if existing.ip and existing.ip != ip:
                    self.logger.info(
                        "event=HOST_IP_CHANGE mac=%s old=%s new=%s",
                        normalized,
                        existing.ip,
                        ip,
                    )
                    if self.hosts_by_ip.get(existing.ip) == normalized:
                        self.hosts_by_ip.pop(existing.ip, None)
                existing.ip = ip
            host = existing

        if host.ip:
            self.hosts_by_ip[host.ip] = normalized
        return host, is_new, moved

    def _drop_pair_state(self, pair: tuple[str, str]) -> None:
        self.route_paths.pop(pair, None)
        self.route_plans.pop(pair, None)
        install = self.route_installs.get(pair)
        if install is not None:
            self._cancel_install(install, "pair-removed")

    def _forget_host(self, mac: str, reason: str) -> bool:
        normalized = mac.strip().lower()
        host = self.hosts_by_mac.pop(normalized, None)
        if host is None:
            return False
        if host.ip and self.hosts_by_ip.get(host.ip) == normalized:
            self.hosts_by_ip.pop(host.ip, None)
        pairs = [
            pair for pair in self.resolved_pairs if normalized in pair
        ]
        for pair in pairs:
            self.resolved_pairs.discard(pair)
            self._drop_pair_state(pair)
            self._settle_refresh(pair, False, reason)
        self.logger.info(
            "event=HOST_FORGET mac=%s dpid=%s port=%s reason=%s",
            normalized,
            self._dpid(host.dpid),
            host.port_no,
            reason,
        )
        return True

    def _forget_hosts_on_port(
        self, dpid: int, port_no: int, *, reason: str
    ) -> list[str]:
        removed = [
            mac
            for mac, host in self.hosts_by_mac.items()
            if host.dpid == dpid and host.port_no == port_no
        ]
        for mac in removed:
            self._forget_host(mac, reason)
        return removed

    def _forget_hosts_on_switch(self, dpid: int) -> list[str]:
        removed = [
            mac
            for mac, host in self.hosts_by_mac.items()
            if host.dpid == dpid
        ]
        for mac in removed:
            self._forget_host(mac, "switch-leave")
        return removed

    def _install_switch_ports(self, switch: Any) -> None:
        dpid = switch.dp.id
        self.graph.add_switch(dpid)
        for port in switch.ports:
            if port.is_reserved():
                continue
            self.graph.set_port_state(dpid, port.port_no, port.is_live())
            if not port.is_live():
                self._forget_hosts_on_port(
                    dpid, port.port_no, reason="switch-port-down"
                )
        self.logger.info(
            "event=SWITCH_PORTS dpid=%s ports=%s",
            self._dpid(dpid),
            [
                {
                    "port": port.port_no,
                    "name": self._port_name(port),
                    "up": port.is_live(),
                }
                for port in switch.ports
                if not port.is_reserved()
            ],
        )

    # ---------------------------------------------------------- flow helpers
    def _controller_action(self, datapath: Any) -> Any:
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        return parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )

    def _assign_xid(self, datapath: Any, msg: Any) -> int | None:
        if getattr(msg, "xid", None) is not None:
            return msg.xid
        setter = getattr(datapath, "set_xid", None)
        if callable(setter):
            try:
                assigned = setter(msg)
            except Exception:  # pragma: no cover - defensive
                self.logger.warning(
                    "event=FWD_XID_ASSIGN_FAILED dpid=%s",
                    self._dpid(getattr(datapath, "id", -1)),
                )
            else:
                if assigned is not None:
                    return assigned
        return getattr(msg, "xid", None)

    def _track_xid(
        self,
        install: _RouteInstall,
        kind: str,
        dpid: int,
        xid: int | None,
    ) -> None:
        if xid is None:
            return
        key = (dpid, xid)
        install.xids.add(key)
        self._xid_owner[key] = (install, kind)

    def _prune_stale_barriers(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        expired = [
            key
            for key, expiry in self._stale_barriers.items()
            if expiry <= now
        ]
        for key in expired:
            self._stale_barriers.pop(key, None)
        overflow = len(self._stale_barriers) - BARRIER_TOMBSTONE_MAX_ENTRIES
        if overflow > 0:
            oldest = sorted(
                self._stale_barriers.items(), key=lambda item: item[1]
            )
            for key, _ in oldest[:overflow]:
                self._stale_barriers.pop(key, None)

    def _remember_stale_barrier(self, key: tuple[int, int]) -> None:
        self._prune_stale_barriers()
        self._stale_barriers[key] = (
            time.monotonic() + BARRIER_TOMBSTONE_TTL_SECONDS
        )

    def _cleanup_xids(self, install: _RouteInstall) -> None:
        for key in install.xids:
            owner = self._xid_owner.pop(key, None)
            if owner is not None and owner[1] == "barrier":
                self._remember_stale_barrier(key)
        install.xids.clear()

    def _add_flow(
        self,
        datapath: Any,
        priority: int,
        match: Any,
        actions: list[Any],
        description: str,
        *,
        install: _RouteInstall | None = None,
    ) -> Any | None:
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = []
        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=FLOW_COOKIE,
            cookie_mask=0,
            table_id=TABLE_ID,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=priority,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,
            match=match,
            instructions=instructions,
        )
        dpid = datapath.id
        if install is not None:
            xid = self._assign_xid(datapath, mod)
            if xid is None:
                self.logger.warning(
                    "event=FWD_FLOW_XID_MISSING dpid=%s priority=%d "
                    "description=%s",
                    self._dpid(dpid),
                    priority,
                    description,
                )
                self._fail_install(install, "flow-xid-missing")
                return None
            self._track_xid(install, "flow", dpid, xid)
        self.logger.info(
            "event=FWD_FLOW_ADD dpid=%s priority=%d description=%s rule=%s",
            self._dpid(dpid),
            priority,
            description,
            mod.match,
        )
        try:
            datapath.send_msg(mod)
        except Exception as exc:  # pragma: no cover - live socket failure
            self.logger.warning(
                "event=FWD_FLOW_SEND_FAILED dpid=%s priority=%d "
                "description=%s error=%s",
                self._dpid(dpid),
                priority,
                description,
                exc,
            )
            if install is not None:
                self._fail_install(
                    install,
                    f"flow-send-error:{type(exc).__name__}",
                )
            return None
        return mod

    def _send_barrier(self, datapath: Any, install: _RouteInstall) -> bool:
        parser = datapath.ofproto_parser
        dpid = datapath.id
        msg = parser.OFPBarrierRequest(datapath)
        xid = self._assign_xid(datapath, msg)
        if xid is None:
            self.logger.warning(
                "event=BARRIER_XID_MISSING dpid=%s pair=%s",
                self._dpid(dpid),
                install.pair,
            )
            self._fail_install(install, "barrier-xid-missing")
            return False
        self._track_xid(install, "barrier", dpid, xid)
        try:
            datapath.send_msg(msg)
        except Exception as exc:  # pragma: no cover - live socket failure
            self.logger.warning(
                "event=BARRIER_SEND_FAILED dpid=%s pair=%s error=%s",
                self._dpid(dpid),
                install.pair,
                exc,
            )
            self._fail_install(
                install, f"barrier-send-error:{type(exc).__name__}"
            )
            return False
        self.logger.info(
            "event=BARRIER_REQUEST dpid=%s pair=%s awaiting=%s",
            self._dpid(dpid),
            install.pair,
            [self._dpid(item) for item in sorted(install.pending_barriers)],
        )
        return True

    def _install_base_flows(self, datapath: Any) -> None:
        parser = datapath.ofproto_parser
        self._add_flow(
            datapath,
            PRIORITY_TABLE_MISS,
            parser.OFPMatch(),
            [],
            "table-miss drop",
        )
        self._add_flow(
            datapath,
            PRIORITY_ARP,
            parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
            [self._controller_action(datapath)],
            "ARP to controller",
        )
        self.logger.info(
            "event=BASE_FLOWS dpid=%s table_miss=drop arp=controller",
            self._dpid(datapath.id),
        )

    def _install_host_punt(self, datapath: Any, host: HostLocation) -> None:
        parser = datapath.ofproto_parser
        self._add_flow(
            datapath,
            PRIORITY_HOST_PUNT,
            parser.OFPMatch(in_port=host.port_no, eth_src=host.mac),
            [self._controller_action(datapath)],
            f"host punt {host.mac}",
        )
        self.logger.info(
            "event=HOST_PUNT mac=%s dpid=%s port=%s priority=%d",
            host.mac,
            self._dpid(host.dpid),
            host.port_no,
            PRIORITY_HOST_PUNT,
        )

    def _install_route_rule(
        self,
        plan: RoutePlan,
        rule: FlowRule,
        install: _RouteInstall,
    ) -> bool:
        datapath = self.datapaths.get(rule.dpid)
        if datapath is None:
            self.logger.warning(
                "event=FWD_FLOW_SKIP dpid=%s pair=%s reason=no-datapath",
                self._dpid(rule.dpid),
                install.pair,
            )
            self._fail_install(install, "no-datapath")
            return False
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            in_port=rule.match.in_port,
            eth_src=rule.match.eth_src,
            eth_dst=rule.match.eth_dst,
        )
        actions = [
            parser.OFPActionOutput(
                rule.out_port, ofproto.OFPCML_NO_BUFFER
            )
        ]
        mod = self._add_flow(
            datapath,
            PRIORITY_ROUTE,
            match,
            actions,
            f"route {rule.match.eth_src}->{rule.match.eth_dst}",
            install=install,
        )
        if mod is None:
            return False
        self.logger.info(
            "event=ROUTE_RULE dpid=%s in_port=%s eth_src=%s eth_dst=%s "
            "out_port=%s path=%s reason=%s",
            self._dpid(rule.dpid),
            rule.match.in_port,
            rule.match.eth_src,
            rule.match.eth_dst,
            rule.out_port,
            plan.path,
            plan.selection.reason,
        )
        return True

    def _purge_our_flows(self, datapath: Any, reason: str) -> None:
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=FLOW_COOKIE,
            cookie_mask=FLOW_COOKIE_MASK,
            table_id=TABLE_ID,
            command=ofproto.OFPFC_DELETE,
            idle_timeout=0,
            hard_timeout=0,
            priority=0,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(),
        )
        try:
            datapath.send_msg(mod)
        except Exception as exc:  # pragma: no cover - live socket failure
            self.logger.warning(
                "event=FWD_FLOW_DELETE_FAILED dpid=%s cookie=0x%x "
                "reason=%s error=%s",
                self._dpid(datapath.id),
                FLOW_COOKIE,
                reason,
                exc,
            )
            return
        self.logger.info(
            "event=FWD_FLOW_DELETE dpid=%s cookie=0x%x reason=%s",
            self._dpid(datapath.id),
            FLOW_COOKIE,
            reason,
        )

    def _purge_all_flows(self, reason: str) -> None:
        for dpid in sorted(self.datapaths):
            self._purge_our_flows(self.datapaths[dpid], reason)

    def _install_base_flows_all(self) -> None:
        for dpid in sorted(self.datapaths):
            self._install_base_flows(self.datapaths[dpid])

    def _install_host_punts_all(self) -> None:
        for mac in sorted(self.hosts_by_mac):
            host = self.hosts_by_mac.get(mac)
            if host is None:
                continue
            if not self._host_is_connected(host):
                self._forget_host(mac, "stale-host-punt")
                continue
            datapath = self.datapaths.get(host.dpid)
            if datapath is not None:
                self._install_host_punt(datapath, host)

    def _route_plan_usable(self, plan: RoutePlan) -> bool:
        for rule in plan.rules:
            if rule.dpid not in self.datapaths:
                return False
            if not self.graph.port_is_up(
                rule.dpid, rule.match.in_port
            ):
                return False
            if not self.graph.port_is_up(rule.dpid, rule.out_port):
                return False
        return True

    @staticmethod
    def _plan_matches_hosts(
        plan: RoutePlan,
        first: HostLocation,
        second: HostLocation,
    ) -> bool:
        """Return True when the plan still targets the current attachments."""

        if not plan.forward or not plan.reverse:
            return False
        return (
            plan.forward[0].match.in_port == first.port_no
            and plan.forward[-1].out_port == second.port_no
            and plan.reverse[0].match.in_port == second.port_no
            and plan.reverse[-1].out_port == first.port_no
        )

    def _notify_success(
        self,
        callback: Callable[[RoutePlan], None] | None,
        plan: RoutePlan,
    ) -> None:
        if callback is None:
            return
        try:
            callback(plan)
        except Exception:  # pragma: no cover - defensive
            self.logger.exception(
                "event=ROUTE_CALLBACK_ERROR pair=%s kind=success",
                (plan.forward[0].match.eth_src, plan.forward[0].match.eth_dst)
                if plan.forward
                else "?",
            )

    def _notify_failure(
        self,
        callback: Callable[[str], None] | None,
        reason: str,
    ) -> None:
        if callback is None:
            return
        try:
            callback(reason)
        except Exception:  # pragma: no cover - defensive
            self.logger.exception(
                "event=ROUTE_CALLBACK_ERROR kind=failure reason=%s", reason
            )

    def _settle_refresh(
        self,
        pair: tuple[str, str],
        installed: bool,
        reason: str,
    ) -> None:
        refresh = self._refresh
        if refresh is None or refresh.epoch != self.route_epoch:
            return
        if pair not in refresh.pending:
            return
        refresh.pending.discard(pair)
        if installed:
            refresh.installed += 1
        else:
            refresh.failed += 1
        if refresh.pending:
            return
        self.logger.info(
            "event=ROUTE_REFRESH_COMPLETE reason=%s epoch=%d pairs=%d "
            "installed=%d failed=%d",
            refresh.reason,
            refresh.epoch,
            refresh.installed + refresh.failed,
            refresh.installed,
            refresh.failed,
        )
        self._refresh = None

    def _complete_install(self, install: _RouteInstall) -> None:
        if (
            install.completed
            or install.failed
            or install.cancelled
            or install.pending_barriers
        ):
            return
        if install.epoch != self.route_epoch:
            self._cancel_install(install, "stale-epoch")
            return
        first = self.hosts_by_mac.get(install.pair[0])
        second = self.hosts_by_mac.get(install.pair[1])
        if not (
            self._host_is_connected(first)
            and self._host_is_connected(second)
        ):
            self._fail_install(install, "host-attachment-changed")
            return
        if not self._plan_matches_hosts(install.plan, first, second):
            self._fail_install(install, "host-location-changed")
            return
        if not self._route_plan_usable(install.plan):
            self._fail_install(install, "route-no-longer-usable")
            return

        install.completed = True
        self.route_installs.pop(install.pair, None)
        self._cleanup_xids(install)
        self.route_paths[install.pair] = install.plan.path
        self.route_plans[install.pair] = install.plan
        self.logger.info(
            "event=ROUTE_INSTALLED pair=%s path=%s rules=%d switches=%d "
            "reason=%s",
            install.pair,
            install.plan.path,
            len(install.plan.rules),
            len(
                {rule.dpid for rule in install.plan.rules}
            ),
            install.reason,
        )
        self._settle_refresh(install.pair, True, "installed")
        for callback in tuple(install.success_callbacks):
            self._notify_success(callback, install.plan)

    def _fail_install(self, install: _RouteInstall, reason: str) -> None:
        if (
            install.completed
            or install.failed
            or install.cancelled
        ):
            return
        install.failed = True
        install.failure_reason = reason
        self.route_installs.pop(install.pair, None)
        self.route_paths.pop(install.pair, None)
        self.route_plans.pop(install.pair, None)
        pending = [self._dpid(dpid) for dpid in sorted(install.pending_barriers)]
        self._cleanup_xids(install)
        self.logger.warning(
            "event=ROUTE_INSTALL_FAILED pair=%s path=%s reason=%s "
            "awaiting=%s",
            install.pair,
            install.plan.path,
            reason,
            pending,
        )
        self._settle_refresh(install.pair, False, reason)
        for callback in tuple(install.failure_callbacks):
            self._notify_failure(callback, reason)

    def _cancel_install(self, install: _RouteInstall, reason: str) -> None:
        if (
            install.completed
            or install.failed
            or install.cancelled
        ):
            return
        install.cancelled = True
        if self.route_installs.get(install.pair) is install:
            self.route_installs.pop(install.pair, None)
        self._cleanup_xids(install)
        self.logger.info(
            "event=ROUTE_CANCEL pair=%s path=%s reason=%s",
            install.pair,
            install.plan.path,
            reason,
        )
        self._settle_refresh(install.pair, False, reason)

    def _schedule_barrier_timeout(self, install: _RouteInstall) -> None:
        try:
            hub.spawn(self._barrier_timeout_loop, install)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.warning(
                "event=BARRIER_TIMER_FAILED pair=%s error=%s",
                install.pair,
                exc,
            )

    def _barrier_timeout_loop(self, install: _RouteInstall) -> None:
        hub.sleep(BARRIER_TIMEOUT_SECONDS)
        if (
            install.completed
            or install.failed
            or install.cancelled
        ):
            return
        self._barrier_timeout(install)

    def _barrier_timeout(self, install: _RouteInstall) -> None:
        if (
            install.completed
            or install.failed
            or install.cancelled
        ):
            return
        self._fail_install(install, "barrier-timeout")

    def _cancel_pending_installs(self, reason: str) -> None:
        for install in list(self.route_installs.values()):
            self._cancel_install(install, reason)

    def _handle_topology_change(self, reason: str) -> None:
        """Purge stale rules and rebuild base, host-punt and route flows."""

        self._max_links_seen = max(
            self._max_links_seen, self.graph.link_count
        )
        self._evaluate_topology_health()
        self.route_epoch += 1
        self._cancel_pending_installs(f"topology-change:{reason}")
        self._refresh = None
        self.route_paths.clear()
        self.route_plans.clear()
        pairs = tuple(sorted(self.resolved_pairs))
        self.logger.info(
            "event=ROUTE_INVALIDATE reason=%s epoch=%d switches=%d pairs=%d",
            reason,
            self.route_epoch,
            len(self.datapaths),
            len(pairs),
        )
        self._purge_all_flows(reason)
        self._install_base_flows_all()
        self._install_host_punts_all()
        self._refresh = _RefreshState(
            reason=reason,
            epoch=self.route_epoch,
            pending=set(pairs),
        )
        for first, second in pairs:
            self._request_pair_install(
                first, second, reason=reason
            )
        self._settle_refresh_if_idle()
        self._log_summary()

    def _settle_refresh_if_idle(self) -> None:
        refresh = self._refresh
        if refresh is not None and not refresh.pending:
            self.logger.info(
                "event=ROUTE_REFRESH_COMPLETE reason=%s epoch=%d pairs=%d "
                "installed=%d failed=%d",
                refresh.reason,
                refresh.epoch,
                refresh.installed + refresh.failed,
                refresh.installed,
                refresh.failed,
            )
            self._refresh = None

    def _request_pair_install(
        self,
        mac_a: str,
        mac_b: str,
        *,
        reason: str,
        on_success: Callable[[RoutePlan], None] | None = None,
        on_failure: Callable[[str], None] | None = None,
    ) -> RoutePlan | None:
        """Request a route and run callbacks only after all barriers reply.

        The returned plan means the request was accepted.  It does *not* mean
        the route is installed; check ``route_paths`` or wait for the callback.
        """

        first_mac, second_mac = sorted(
            (mac_a.strip().lower(), mac_b.strip().lower())
        )
        pair = (first_mac, second_mac)
        first = self.hosts_by_mac.get(first_mac)
        second = self.hosts_by_mac.get(second_mac)
        if first is None or second is None:
            self.resolved_pairs.discard(pair)
            self._drop_pair_state(pair)
            self.logger.info(
                "event=ROUTE_UNAVAILABLE pair=%s reason=unknown-host",
                pair,
            )
            self._notify_failure(on_failure, "unknown-host")
            self._settle_refresh(pair, False, "unknown-host")
            return None

        if not (
            self._host_is_connected(first)
            and self._host_is_connected(second)
        ):
            first_reason = self._host_attachment_reason(first)
            second_reason = self._host_attachment_reason(second)
            unavailable = (
                "transit-attachment"
                if {first_reason, second_reason} & {"transit-port"}
                else "host-disconnected"
            )
            self.resolved_pairs.discard(pair)
            self._drop_pair_state(pair)
            self.logger.info(
                "event=ROUTE_UNAVAILABLE pair=%s reason=%s "
                "first=%s second=%s first_reason=%s second_reason=%s",
                pair,
                unavailable,
                self._host_is_connected(first),
                self._host_is_connected(second),
                first_reason or "-",
                second_reason or "-",
            )
            self._notify_failure(on_failure, unavailable)
            self._settle_refresh(pair, False, unavailable)
            return None

        self.resolved_pairs.add(pair)

        if self._topology_state == "degraded":
            # Preserve the resolved pair so recovery can reinstall the route,
            # but never install forwarding state from unverified attachments.
            self._drop_pair_state(pair)
            self.logger.info(
                "event=ROUTE_UNAVAILABLE pair=%s reason=topology-degraded "
                "state=%s links=%d",
                pair,
                self._topology_state,
                self.graph.link_count,
            )
            self._notify_failure(on_failure, "topology-degraded")
            self._settle_refresh(pair, False, "topology-degraded")
            return None

        installed_plan = self.route_plans.get(pair)
        if installed_plan is not None and pair in self.route_paths:
            if self._route_plan_usable(installed_plan):
                self._notify_success(on_success, installed_plan)
                return installed_plan
            self.logger.info(
                "event=ROUTE_INVALIDATE pair=%s reason=installed-route-stale",
                pair,
            )
            self.route_paths.pop(pair, None)
            self.route_plans.pop(pair, None)

        pending = self.route_installs.get(pair)
        if pending is not None and not pending.failed and not pending.cancelled:
            if pending.epoch == self.route_epoch:
                if on_success is not None:
                    pending.success_callbacks.append(on_success)
                if on_failure is not None:
                    pending.failure_callbacks.append(on_failure)
                return pending.plan
            self._cancel_install(pending, "stale-epoch")

        plan = route_for_hosts(
            self.graph,
            first,
            second,
            flow_key=pair,
            selector=self.selector,
        )
        if plan is None:
            self.route_paths.pop(pair, None)
            self.route_plans.pop(pair, None)
            self.logger.info(
                "event=ROUTE_UNAVAILABLE pair=%s reason=no-path", pair
            )
            self._notify_failure(on_failure, "no-path")
            self._settle_refresh(pair, False, "no-path")
            return None

        self.logger.info(
            "event=ROUTE_SELECT pair=%s path=%s cost=%.3f reason=%s detail=%s "
            "source=%s",
            pair,
            plan.path,
            plan.path.cost,
            plan.selection.reason,
            plan.selection.detail,
            reason,
        )

        missing = sorted(
            {
                rule.dpid
                for rule in plan.rules
                if rule.dpid not in self.datapaths
            }
        )
        if missing:
            self.logger.info(
                "event=ROUTE_DEFER pair=%s missing_dpids=%s path=%s",
                pair,
                [self._dpid(dpid) for dpid in missing],
                plan.path,
            )
            self._notify_failure(on_failure, "missing-datapath")
            self._settle_refresh(pair, False, "missing-datapath")
            return None

        bad_ports = sorted(
            {
                (rule.dpid, port)
                for rule in plan.rules
                for port in (rule.match.in_port, rule.out_port)
                if not self.graph.port_is_up(rule.dpid, port)
            }
        )
        if bad_ports:
            self.logger.info(
                "event=ROUTE_UNAVAILABLE pair=%s reason=port-down path=%s "
                "ports=%s",
                pair,
                plan.path,
                [
                    f"{self._dpid(dpid)}:{port}"
                    for dpid, port in bad_ports
                ],
            )
            self._notify_failure(on_failure, "port-down")
            self._settle_refresh(pair, False, "port-down")
            return None

        install = _RouteInstall(
            pair=pair,
            plan=plan,
            reason=reason,
            epoch=self.route_epoch,
        )
        if on_success is not None:
            install.success_callbacks.append(on_success)
        if on_failure is not None:
            install.failure_callbacks.append(on_failure)
        self.route_installs[pair] = install

        by_dpid: dict[int, list[FlowRule]] = {}
        for rule in plan.rules:
            by_dpid.setdefault(rule.dpid, []).append(rule)

        for dpid in sorted(by_dpid):
            for rule in by_dpid[dpid]:
                if not self._install_route_rule(plan, rule, install):
                    break
            if install.failed or install.cancelled:
                break
        if install.failed or install.cancelled:
            return None

        # Register every switch before sending the first barrier.  A barrier
        # reply from one switch must not complete a transaction whose FlowMods
        # have not yet been sent to the remaining switches.
        install.pending_barriers = set(by_dpid)
        for dpid in sorted(by_dpid):
            datapath = self.datapaths.get(dpid)
            if datapath is None:
                self._fail_install(install, "no-datapath")
                break
            if not self._send_barrier(datapath, install):
                break
        if install.failed or install.cancelled:
            return None
        if install.completed:
            return install.plan

        self.logger.info(
            "event=ROUTE_INSTALL_PENDING pair=%s path=%s awaiting=%s "
            "reason=%s",
            pair,
            plan.path,
            [self._dpid(dpid) for dpid in sorted(install.pending_barriers)],
            reason,
        )
        self._schedule_barrier_timeout(install)
        return install.plan

    def _ensure_pair_flows(
        self,
        mac_a: str,
        mac_b: str,
        *,
        reason: str,
    ) -> RoutePlan | None:
        """Compatibility wrapper used by forwarding and tests."""

        return self._request_pair_install(mac_a, mac_b, reason=reason)

    # ----------------------------------------------------------- packets I/O
    def _send_packet_out(
        self,
        dpid: int,
        port_no: int,
        data: bytes,
        label: str,
    ) -> bool:
        datapath = self.datapaths.get(dpid)
        if datapath is None:
            self.logger.warning(
                "event=PACKET_OUT_SKIP dpid=%s port=%s label=%s "
                "reason=no-datapath",
                self._dpid(dpid),
                port_no,
                label,
            )
            return False
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        msg = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[
                parser.OFPActionOutput(
                    port_no, ofproto.OFPCML_NO_BUFFER
                )
            ],
            data=data,
        )
        try:
            datapath.send_msg(msg)
        except Exception as exc:  # pragma: no cover - live socket failure
            self.logger.warning(
                "event=PACKET_OUT_FAILED dpid=%s port=%s label=%s error=%s",
                self._dpid(dpid),
                port_no,
                label,
                exc,
            )
            return False
        self.logger.info(
            "event=PACKET_OUT dpid=%s port=%s label=%s bytes=%d",
            self._dpid(dpid),
            port_no,
            label,
            len(data),
        )
        return True

    def _flood_arp(
        self,
        data: bytes,
        ingress_dpid: int,
        ingress_port: int,
        arp_packet: Any,
    ) -> None:
        ingress = PortRef(ingress_dpid, ingress_port)
        if self._topology_state == "degraded":
            self.logger.info(
                "event=ARP_FLOOD_SUPPRESSED ingress=%s:%s "
                "reason=topology-degraded",
                self._dpid(ingress_dpid),
                ingress_port,
            )
            return
        if self.graph.is_transit_port(ingress_dpid, ingress_port):
            self.logger.info(
                "event=ARP_FLOOD_SUPPRESSED ingress=%s:%s "
                "reason=transit-ingress",
                self._dpid(ingress_dpid),
                ingress_port,
            )
            return
        targets: tuple[FloodTarget, ...] = controlled_flood_targets(
            self.graph, ingress
        )
        safe_targets = tuple(
            target
            for target in targets
            if not (
                self.graph.is_transit_port(target.dpid, target.port_no)
                and target.port_no
                not in self.graph.link_ports(target.dpid)
            )
        )
        if len(safe_targets) != len(targets):
            self.logger.warning(
                "event=ARP_FLOOD_FILTER_TRANSIT ingress=%s:%s dropped=%s",
                self._dpid(ingress_dpid),
                ingress_port,
                [
                    f"{self._dpid(target.dpid)}:{target.port_no}"
                    for target in targets
                    if target not in safe_targets
                ],
            )
        targets = safe_targets
        if not targets:
            self.logger.info(
                "event=ARP_FLOOD_SUPPRESSED ingress=%s:%s "
                "reason=no-verified-host-ports",
                self._dpid(ingress_dpid),
                ingress_port,
            )
            return
        for target in targets:
            self._send_packet_out(
                target.dpid,
                target.port_no,
                data,
                f"ARP_FLOOD {arp_packet.src_ip}->{arp_packet.dst_ip}",
            )

        children = self.graph.broadcast_tree_ports(ingress_dpid)
        reachable = set(children)
        excluded_links: list[str] = []
        for dpid in sorted(children):
            tree = children[dpid]
            for link in self.graph.active_links_for_switch(dpid):
                local = link.endpoint_for(dpid)
                if local.port_no not in tree:
                    excluded_links.append(
                        f"{self._dpid(dpid)}:{local.port_no}"
                    )
        disconnected = [
            self._dpid(node.dpid)
            for node in self.graph.switches
            if node.dpid not in reachable
        ]
        down_ports = [
            f"{self._dpid(node.dpid)}:{port_no}"
            for node in self.graph.switches
            for port_no, is_up in sorted(node.ports.items())
            if not is_up
        ]
        self.logger.info(
            "event=ARP_FLOOD source_ip=%s target_ip=%s ingress=%s:%s "
            "egress=%s count=%d",
            arp_packet.src_ip,
            arp_packet.dst_ip,
            self._dpid(ingress_dpid),
            ingress_port,
            [
                f"{self._dpid(target.dpid)}:{target.port_no}"
                for target in targets
            ],
            len(targets),
        )
        self.logger.info(
            "event=ARP_FLOOD_FILTER ingress=%s:%s excluded_link_ports=%s "
            "disconnected_switches=%s down_ports=%s",
            self._dpid(ingress_dpid),
            ingress_port,
            excluded_links,
            disconnected,
            down_ports,
        )

    def _send_proxy_arp_reply(
        self,
        requester: HostLocation,
        target: HostLocation,
        arp_packet: Any,
    ) -> None:
        reply = packet.Packet()
        reply.add_protocol(
            ethernet.ethernet(
                dst=requester.mac,
                src=target.mac,
                ethertype=ether_types.ETH_TYPE_ARP,
            )
        )
        reply.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=target.mac,
                src_ip=arp_packet.dst_ip,
                dst_mac=requester.mac,
                dst_ip=arp_packet.src_ip,
            )
        )
        reply.serialize()
        self._send_packet_out(
            requester.dpid,
            requester.port_no,
            bytes(reply.data),
            f"ARP_PROXY {requester.mac}->{target.mac}",
        )
        self.logger.info(
            "event=ARP_PROXY requester=%s requester_ip=%s target=%s "
            "target_ip=%s",
            requester.mac,
            arp_packet.src_ip,
            target.mac,
            arp_packet.dst_ip,
        )

    def _host_for_ip(
        self, ip: str, *, context: str
    ) -> HostLocation | None:
        mac = self.hosts_by_ip.get(ip)
        if mac is None:
            return None
        host = self.hosts_by_mac.get(mac)
        if (
            host is None
            or host.ip != ip
            or not self._host_is_connected(host)
        ):
            if self.hosts_by_ip.get(ip) == mac:
                self.hosts_by_ip.pop(ip, None)
            self.logger.info(
                "event=ARP_LOOKUP_STALE context=%s ip=%s mac=%s "
                "reason=disconnected-or-stale",
                context,
                ip,
                mac,
            )
            if host is not None:
                self._forget_host(mac, "stale-arp-mapping")
            return None
        return host

    def _finish_proxy_arp(
        self,
        requester_mac: str,
        target_mac: str,
        arp_packet: Any,
    ) -> None:
        requester = self.hosts_by_mac.get(requester_mac)
        target = self.hosts_by_mac.get(target_mac)
        if not (
            self._host_is_connected(requester)
            and self._host_is_connected(target)
        ):
            self.logger.info(
                "event=ARP_PROXY_SKIP requester=%s target=%s "
                "reason=host-disconnected",
                requester_mac,
                target_mac,
            )
            return
        if (
            self.hosts_by_ip.get(arp_packet.src_ip) != requester_mac
            or self.hosts_by_ip.get(arp_packet.dst_ip) != target_mac
        ):
            self.logger.info(
                "event=ARP_PROXY_SKIP requester=%s target=%s "
                "reason=stale-ip-mapping",
                requester_mac,
                target_mac,
            )
            return
        pair = tuple(sorted((requester_mac, target_mac)))
        if pair not in self.route_paths:
            self.logger.info(
                "event=ARP_PROXY_SKIP pair=%s reason=route-not-installed",
                pair,
            )
            return
        self._send_proxy_arp_reply(requester, target, arp_packet)

    def _handle_arp(
        self,
        eth: Any,
        arp_packet: Any,
        data: bytes,
        dpid: int,
        in_port: int,
        host: HostLocation,
    ) -> None:
        if not self._host_is_connected(host):
            self.logger.info(
                "event=ARP_DROP source=%s reason=source-disconnected",
                host.mac,
            )
            self._forget_host(host.mac, "disconnected-source")
            return

        if arp_packet.opcode == arp.ARP_REQUEST:
            if arp_packet.src_ip == arp_packet.dst_ip:
                self.logger.info(
                    "event=ARP_GRATUITOUS mac=%s ip=%s",
                    host.mac,
                    arp_packet.src_ip,
                )
                return

            target = self._host_for_ip(
                arp_packet.dst_ip, context="arp-request"
            )
            if target is not None and target.mac != host.mac:
                if not self._host_is_connected(target):
                    self.logger.info(
                        "event=ARP_PROXY_DENY requester=%s target=%s "
                        "target_ip=%s reason=target-disconnected",
                        host.mac,
                        target.mac,
                        arp_packet.dst_ip,
                    )
                    self._forget_host(
                        target.mac, "disconnected-arp-target"
                    )
                else:
                    pair = tuple(sorted((host.mac, target.mac)))
                    plan = self._request_pair_install(
                        host.mac,
                        target.mac,
                        reason="arp-proxy",
                        on_success=lambda selected: self._finish_proxy_arp(
                            host.mac, target.mac, arp_packet
                        ),
                        on_failure=lambda failure: self.logger.info(
                            "event=ARP_PROXY_FAILED pair=%s reason=%s",
                            pair,
                            failure,
                        ),
                    )
                    if plan is not None:
                        if pair not in self.route_paths:
                            self.logger.info(
                                "event=ARP_PROXY_DEFER pair=%s "
                                "reason=route-install-pending",
                                pair,
                            )
                        return
                    self.logger.info(
                        "event=ARP_PROXY_FALLBACK requester=%s target=%s "
                        "reason=route-unavailable",
                        host.mac,
                        target.mac,
                    )

            self._flood_arp(data, dpid, in_port, arp_packet)
            return

        if arp_packet.opcode == arp.ARP_REPLY:
            requester = self._host_for_ip(
                arp_packet.dst_ip, context="arp-reply"
            )
            if requester is None:
                self.logger.info(
                    "event=ARP_REPLY_DROP source=%s target_ip=%s "
                    "reason=unknown-requester",
                    host.mac,
                    arp_packet.dst_ip,
                )
                return
            if requester.mac == host.mac:
                self.logger.info(
                    "event=ARP_REPLY_DROP source=%s target_ip=%s "
                    "reason=self-reply",
                    host.mac,
                    arp_packet.dst_ip,
                )
                return
            pair = tuple(sorted((host.mac, requester.mac)))
            plan = self._request_pair_install(
                host.mac,
                requester.mac,
                reason="arp-reply",
                on_success=lambda selected: self._deliver_arp_reply(
                    host.mac,
                    requester.mac,
                    data,
                    arp_packet.src_ip,
                    arp_packet.dst_ip,
                ),
                on_failure=lambda failure: self.logger.info(
                    "event=ARP_REPLY_FAILED pair=%s reason=%s",
                    pair,
                    failure,
                ),
            )
            if plan is None:
                self.logger.info(
                    "event=ARP_REPLY_DROP source=%s requester=%s "
                    "reason=route-unavailable",
                    host.mac,
                    requester.mac,
                )
            elif pair not in self.route_paths:
                self.logger.info(
                    "event=ARP_REPLY_DEFER pair=%s "
                    "reason=route-install-pending",
                    pair,
                )
            return

        self.logger.info(
            "event=ARP_DROP source=%s opcode=%s reason=unsupported-opcode",
            host.mac,
            arp_packet.opcode,
        )

    def _deliver_arp_reply(
        self,
        source_mac: str,
        requester_mac: str,
        data: bytes,
        source_ip: str,
        requester_ip: str,
    ) -> None:
        source = self.hosts_by_mac.get(source_mac)
        requester = self.hosts_by_mac.get(requester_mac)
        if not (
            self._host_is_connected(source)
            and self._host_is_connected(requester)
        ):
            self.logger.info(
                "event=ARP_REPLY_DROP source=%s requester=%s "
                "reason=host-disconnected",
                source_mac,
                requester_mac,
            )
            return
        if (
            self.hosts_by_ip.get(source_ip) != source_mac
            or self.hosts_by_ip.get(requester_ip) != requester_mac
        ):
            self.logger.info(
                "event=ARP_REPLY_DROP source=%s requester=%s "
                "reason=stale-ip-mapping",
                source_mac,
                requester_mac,
            )
            return
        pair = tuple(sorted((source_mac, requester_mac)))
        if pair not in self.route_paths:
            self.logger.info(
                "event=ARP_REPLY_DROP pair=%s reason=route-not-installed",
                pair,
            )
            return
        self._send_packet_out(
            requester.dpid,
            requester.port_no,
            data,
            f"ARP_REPLY {source_mac}->{requester_mac}",
        )
        self.logger.info(
            "event=ARP_DELIVER source=%s requester=%s",
            source_mac,
            requester_mac,
        )

    def _forward_data(
        self,
        eth: Any,
        dpid: int,
        in_port: int,
        host: HostLocation,
        data: bytes,
    ) -> None:
        destination_mac = str(eth.dst).lower()
        if not self._is_unicast_mac(destination_mac):
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s dpid=%s port=%s "
                "reason=non-unicast",
                host.mac,
                destination_mac,
                self._dpid(dpid),
                in_port,
            )
            return

        destination = self.hosts_by_mac.get(destination_mac)
        if destination is None:
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s dpid=%s port=%s "
                "reason=unknown-destination",
                host.mac,
                destination_mac,
                self._dpid(dpid),
                in_port,
            )
            return
        if not self._host_is_connected(destination):
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s dpid=%s port=%s "
                "reason=destination-disconnected",
                host.mac,
                destination_mac,
                self._dpid(dpid),
                in_port,
            )
            self._forget_host(
                destination_mac, "disconnected-data-target"
            )
            return
        if destination.mac == host.mac:
            return

        pair = tuple(sorted((host.mac, destination.mac)))
        plan = self._request_pair_install(
            host.mac,
            destination.mac,
            reason="data",
            on_success=lambda selected: self._finish_data_forward(
                selected,
                dpid,
                in_port,
                host.mac,
                destination.mac,
                data,
            ),
            on_failure=lambda failure: self.logger.info(
                "event=DATA_DEFER_FAILED pair=%s reason=%s",
                pair,
                failure,
            ),
        )
        if plan is None:
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s dpid=%s port=%s "
                "reason=route-unavailable",
                host.mac,
                destination.mac,
                self._dpid(dpid),
                in_port,
            )
        elif pair not in self.route_paths:
            self.logger.info(
                "event=DATA_DEFER pair=%s reason=route-install-pending",
                pair,
            )

    def _finish_data_forward(
        self,
        plan: RoutePlan,
        dpid: int,
        in_port: int,
        source_mac: str,
        destination_mac: str,
        data: bytes,
    ) -> None:
        source = self.hosts_by_mac.get(source_mac)
        destination = self.hosts_by_mac.get(destination_mac)
        if not (
            self._host_is_connected(source)
            and self._host_is_connected(destination)
        ):
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s reason=host-disconnected",
                source_mac,
                destination_mac,
            )
            return
        if source.dpid != dpid or source.port_no != in_port:
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s reason=source-moved",
                source_mac,
                destination_mac,
            )
            return
        pair = tuple(sorted((source_mac, destination_mac)))
        if pair not in self.route_paths:
            self.logger.info(
                "event=DATA_DROP pair=%s reason=route-not-installed",
                pair,
            )
            return

        rules = (
            plan.forward
            if plan.forward
            and plan.forward[0].match.eth_src == source_mac
            else plan.reverse
        )
        rule = next(
            (
                candidate
                for candidate in rules
                if candidate.dpid == dpid
                and candidate.match.in_port == in_port
            ),
            None,
        )
        if rule is None:
            self.logger.info(
                "event=DATA_DROP src=%s dst=%s dpid=%s port=%s "
                "reason=no-ingress-rule",
                source_mac,
                destination_mac,
                self._dpid(dpid),
                in_port,
            )
            return

        if not self._send_packet_out(
            dpid,
            rule.out_port,
            data,
            f"DATA {source_mac}->{destination_mac}",
        ):
            return
        self.logger.info(
            "event=DATA_FORWARD src=%s dst=%s dpid=%s in_port=%s "
            "out_port=%s path=%s reason=%s",
            source_mac,
            destination_mac,
            self._dpid(dpid),
            in_port,
            rule.out_port,
            plan.path,
            plan.selection.reason,
        )

    # ---------------------------------------------------------- switch events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        dpid = datapath.id
        if dpid is not None:
            self.datapaths[dpid] = datapath
        self.logger.info(
            "event=SWITCH_FEATURES dpid=%s n_buffers=%s n_tables=%s",
            self._dpid(dpid) if dpid is not None else "?",
            ev.msg.n_buffers,
            ev.msg.n_tables,
        )
        self._start_port_reconciliation()

    def _start_port_reconciliation(self) -> None:
        if self._reconcile_started:
            return
        self._reconcile_started = True
        try:
            hub.spawn(self._port_reconciliation_loop)
        except Exception as exc:  # pragma: no cover - defensive
            self._reconcile_started = False
            self.logger.warning(
                "event=PORT_RECONCILE_START_FAILED error=%s", exc
            )

    def _port_reconciliation_loop(self) -> None:
        while True:
            try:
                self._evaluate_topology_health()
                self._request_port_descriptions("periodic")
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.warning(
                    "event=PORT_RECONCILE_LOOP_ERROR error=%s", exc
                )
            hub.sleep(PORT_RECONCILE_INTERVAL_SECONDS)

    def _request_port_descriptions(self, reason: str) -> int:
        sent = 0
        for dpid in sorted(list(self.datapaths)):
            datapath = self.datapaths.get(dpid)
            if datapath is None:
                continue
            try:
                request = datapath.ofproto_parser.OFPPortDescStatsRequest(
                    datapath, 0
                )
                datapath.send_msg(request)
            except Exception as exc:  # pragma: no cover - live socket failure
                self.logger.warning(
                    "event=PORT_RECONCILE_REQUEST_FAILED dpid=%s "
                    "reason=%s error=%s",
                    self._dpid(dpid),
                    reason,
                    exc,
                )
                continue
            sent += 1
        self.logger.info(
            "event=PORT_RECONCILE_REQUEST reason=%s switches=%d",
            reason,
            sent,
        )
        return sent

    @set_ev_cls(topology_event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev: Any) -> None:
        switch = ev.switch
        dpid = switch.dp.id
        if dpid is None:
            return
        self.datapaths[dpid] = switch.dp
        self.logger.info("event=SWITCH_ENTER dpid=%s", self._dpid(dpid))
        self._install_switch_ports(switch)
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("switch-enter")

    @set_ev_cls(topology_event.EventSwitchReconnected, MAIN_DISPATCHER)
    def switch_reconnected_handler(self, ev: Any) -> None:
        switch = ev.switch
        dpid = switch.dp.id
        if dpid is None:
            return
        self.datapaths[dpid] = switch.dp
        self.logger.info(
            "event=SWITCH_RECONNECTED dpid=%s", self._dpid(dpid)
        )
        self._install_switch_ports(switch)
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("switch-reconnected")

    @set_ev_cls(topology_event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev: Any) -> None:
        switch = ev.switch
        dpid = switch.dp.id
        if dpid is None:
            return
        self.datapaths.pop(dpid, None)
        for key in [
            key for key in self._port_desc_parts if key[0] == dpid
        ]:
            self._port_desc_parts.pop(key, None)
        removed = self.graph.remove_switch(dpid)
        self._forget_hosts_on_switch(dpid)
        self.logger.info(
            "event=SWITCH_LEAVE dpid=%s removed_links=%d",
            self._dpid(dpid),
            len(removed),
        )
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("switch-leave")

    # ------------------------------------------------------------ port events
    def _set_port_state(
        self,
        dpid: int,
        port_no: int,
        is_up: bool,
        *,
        reason: str,
    ) -> bool:
        node = (
            self.graph.switch(dpid)
            if self.graph.has_switch(dpid)
            else None
        )
        known = node is not None and port_no in node.ports
        old_up = node.is_port_up(port_no) if known else True
        self.graph.set_port_state(dpid, port_no, is_up)
        changed = (not known) or old_up != is_up
        forgot: list[str] = []
        if not is_up:
            forgot = self._forget_hosts_on_port(
                dpid, port_no, reason=f"{reason}-down"
            )
        # Removing a host is a topology-relevant change even if the port was
        # already marked down (for example, after a missed event).
        return changed or bool(forgot)

    @set_ev_cls(topology_event.EventPortAdd, MAIN_DISPATCHER)
    def port_add_handler(self, ev: Any) -> None:
        port = ev.port
        if getattr(port, "is_reserved", lambda: False)():
            return
        changed = self._set_port_state(
            port.dpid,
            port.port_no,
            port.is_live(),
            reason="port-add",
        )
        self.logger.info(
            "event=PORT_ADD dpid=%s port=%s name=%s up=%s",
            self._dpid(port.dpid),
            port.port_no,
            self._port_name(port),
            port.is_live(),
        )
        if not changed:
            return
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("port-add")

    @set_ev_cls(topology_event.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev: Any) -> None:
        port = ev.port
        if getattr(port, "is_reserved", lambda: False)():
            return
        changed = self._set_port_state(
            port.dpid,
            port.port_no,
            port.is_live(),
            reason="port-modify",
        )
        self.logger.info(
            "event=PORT_MODIFY dpid=%s port=%s name=%s up=%s changed=%s",
            self._dpid(port.dpid),
            port.port_no,
            self._port_name(port),
            port.is_live(),
            changed,
        )
        self._rebuild_tree()
        if changed:
            self._handle_topology_change("port-modify")

    @set_ev_cls(topology_event.EventPortDelete, MAIN_DISPATCHER)
    def port_delete_handler(self, ev: Any) -> None:
        port = ev.port
        if getattr(port, "is_reserved", lambda: False)():
            return
        node = (
            self.graph.switch(port.dpid)
            if self.graph.has_switch(port.dpid)
            else None
        )
        known = node is not None and port.port_no in node.ports
        forgot = self._forget_hosts_on_port(
            port.dpid, port.port_no, reason="port-delete"
        )
        removed = self.graph.remove_port(port.dpid, port.port_no)
        self.logger.info(
            "event=PORT_DELETE dpid=%s port=%s name=%s removed_links=%d "
            "removed_hosts=%d",
            self._dpid(port.dpid),
            port.port_no,
            self._port_name(port),
            len(removed),
            len(forgot),
        )
        if not known and not removed and not forgot:
            return
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("port-delete")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def ofp_port_status_handler(self, ev: Any) -> None:
        """Apply port status immediately, independent of topology events."""

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        desc = msg.desc
        port_no = desc.port_no
        self.datapaths.setdefault(dpid, datapath)
        if port_no > ofproto.OFPP_MAX:
            self.logger.info(
                "event=PORT_STATUS_SKIP dpid=%s port=%s reason=reserved",
                self._dpid(dpid),
                port_no,
            )
            return
        reason_name = {
            ofproto.OFPPR_ADD: "add",
            ofproto.OFPPR_DELETE: "delete",
            ofproto.OFPPR_MODIFY: "modify",
        }.get(msg.reason, str(msg.reason))

        if msg.reason == ofproto.OFPPR_DELETE:
            node = (
                self.graph.switch(dpid)
                if self.graph.has_switch(dpid)
                else None
            )
            known = node is not None and port_no in node.ports
            forgot = self._forget_hosts_on_port(
                dpid, port_no, reason="ofp-port-delete"
            )
            removed = self.graph.remove_port(dpid, port_no)
            changed = known or bool(removed) or bool(forgot)
            is_up = False
        else:
            is_up = self._ofp_port_is_live(desc, ofproto)
            changed = self._set_port_state(
                dpid, port_no, is_up, reason=f"ofp-port-{reason_name}"
            )

        self.logger.info(
            "event=PORT_STATUS dpid=%s port=%s reason=%s up=%s changed=%s",
            self._dpid(dpid),
            port_no,
            reason_name,
            is_up,
            changed,
        )
        if not changed:
            return
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change(f"ofp-port-{reason_name}")

    @set_ev_cls(
        ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER
    )
    def port_desc_stats_reply_handler(self, ev: Any) -> None:
        """Reconcile port liveness from a periodic port-description reply."""

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        self.datapaths.setdefault(dpid, datapath)
        key = (dpid, msg.xid)
        parts = self._port_desc_parts.setdefault(key, [])
        parts.extend(list(getattr(msg, "body", []) or []))
        flags = int(getattr(msg, "flags", 0) or 0)
        if flags & ofproto.OFPMPF_REPLY_MORE:
            self.logger.info(
                "event=PORT_RECONCILE_PARTIAL dpid=%s xid=%s accumulated=%d "
                "reason=reply-more",
                self._dpid(dpid),
                msg.xid,
                len(parts),
            )
            return
        body = self._port_desc_parts.pop(key, [])
        if not body:
            # An empty reply is not a trustworthy instruction to remove every
            # known port.  Keep the last known state and wait for the next
            # reconciliation or a direct port-status event.
            self.logger.info(
                "event=PORT_RECONCILE_EMPTY dpid=%s reason=no-port-descriptions",
                self._dpid(dpid),
            )
            return
        node = (
            self.graph.switch(dpid)
            if self.graph.has_switch(dpid)
            else None
        )
        reported: set[int] = set()
        down: list[int] = []
        changed = False
        for port in body:
            port_no = int(port.port_no)
            if port_no > ofproto.OFPP_MAX:
                continue
            reported.add(port_no)
            is_up = self._ofp_port_is_live(port, ofproto)
            known = node is not None and port_no in node.ports
            old_up = node.is_port_up(port_no) if known else True
            if (not known) or old_up != is_up:
                changed = True
            self.graph.set_port_state(dpid, port_no, is_up)
            if not is_up:
                down.append(port_no)
                self._forget_hosts_on_port(
                    dpid, port_no, reason="port-reconcile-down"
                )

        removed: list[int] = []
        if node is not None:
            for port_no in sorted(set(node.ports) - reported):
                self._forget_hosts_on_port(
                    dpid, port_no, reason="port-reconcile-missing"
                )
                self.graph.remove_port(dpid, port_no)
                removed.append(port_no)
                changed = True

        self.logger.info(
            "event=PORT_RECONCILE dpid=%s reported=%s down=%s removed=%s "
            "changed=%s",
            self._dpid(dpid),
            sorted(reported),
            down,
            removed,
            changed,
        )
        if not changed:
            return
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("port-reconcile")

    # ------------------------------------------------------------ link events
    @set_ev_cls(topology_event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev: Any) -> None:
        link = ev.link
        # A port that becomes a switch-to-switch link can no longer host a
        # learned endpoint.  Remove any stale host before the graph changes.
        reclassified = self._forget_hosts_on_port(
            link.src.dpid,
            link.src.port_no,
            reason="port-reclassified-link",
        )
        reclassified += self._forget_hosts_on_port(
            link.dst.dpid,
            link.dst.port_no,
            reason="port-reclassified-link",
        )
        model = Link(
            PortRef(link.src.dpid, link.src.port_no),
            PortRef(link.dst.dpid, link.dst.port_no),
        )
        self.graph.add_link(model)
        self.logger.info(
            "event=LINK_ADD %s:%s <-> %s:%s reclassified_hosts=%d",
            self._dpid(link.src.dpid),
            link.src.port_no,
            self._dpid(link.dst.dpid),
            link.dst.port_no,
            len(reclassified),
        )
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("link-add")

    @set_ev_cls(topology_event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev: Any) -> None:
        link = ev.link
        model = Link(
            PortRef(link.src.dpid, link.src.port_no),
            PortRef(link.dst.dpid, link.dst.port_no),
        )
        removed = self.graph.remove_link(model)
        self.logger.info(
            "event=LINK_DELETE %s:%s <-> %s:%s known=%s",
            self._dpid(link.src.dpid),
            link.src.port_no,
            self._dpid(link.dst.dpid),
            link.dst.port_no,
            removed is not None,
        )
        if removed is None:
            # Port/switch cleanup already removed this link and refreshed the
            # forwarding state.  Do not purge a second time for a duplicate
            # topology notification.
            return
        self._rebuild_tree()
        self._log_summary()
        self._handle_topology_change("link-delete")

    # ------------------------------------------------------------ host events
    @set_ev_cls(topology_event.EventHostAdd, MAIN_DISPATCHER)
    def host_add_handler(self, ev: Any) -> None:
        host = ev.host
        allowed, reason = self._host_event_allowed(
            host.mac, host.port.dpid, host.port.port_no
        )
        if not allowed:
            # A rejected add/move must never delete an existing valid
            # location.  Only explicit port/switch invalidation forgets hosts.
            self._log_host_reject(
                host.mac,
                host.port.dpid,
                host.port.port_no,
                reason,
            )
            return
        ip = host.ipv4[0] if host.ipv4 else None
        learned_result = self._remember_host(
            host.mac, host.port.dpid, host.port.port_no, ip
        )
        if learned_result is None:
            return
        learned, is_new, moved = learned_result
        if is_new:
            datapath = self.datapaths.get(learned.dpid)
            if datapath is not None:
                self._install_host_punt(datapath, learned)
        if moved:
            self._handle_topology_change("host-move")
        self._log_summary()

    @set_ev_cls(topology_event.EventHostMove, MAIN_DISPATCHER)
    def host_move_handler(self, ev: Any) -> None:
        host = ev.dst
        allowed, reason = self._host_event_allowed(
            host.mac, host.port.dpid, host.port.port_no
        )
        if not allowed:
            self._log_host_reject(
                host.mac,
                host.port.dpid,
                host.port.port_no,
                reason,
            )
            return
        ip = host.ipv4[0] if host.ipv4 else None
        learned_result = self._remember_host(
            host.mac, host.port.dpid, host.port.port_no, ip
        )
        if learned_result is None:
            return
        learned, _, moved = learned_result
        datapath = self.datapaths.get(learned.dpid)
        if datapath is not None:
            self._install_host_punt(datapath, learned)
        if moved:
            self._handle_topology_change("host-move")
        self._log_summary()

    # -------------------------------------------------------- OpenFlow errors
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        owner = self._xid_owner.get((dpid, msg.xid))
        install: _RouteInstall | None = None
        if owner is not None:
            candidate, kind = owner
            if kind == "barrier":
                install = candidate
        if install is None:
            self._prune_stale_barriers()
            if (dpid, msg.xid) in self._stale_barriers:
                self.logger.info(
                    "event=BARRIER_REPLY_STALE dpid=%s xid=%s",
                    self._dpid(dpid),
                    msg.xid,
                )
            else:
                self.logger.info(
                    "event=BARRIER_REPLY_UNTRACKED dpid=%s xid=%s",
                    self._dpid(dpid),
                    msg.xid,
                )
            return

        install.pending_barriers.discard(dpid)
        self.logger.info(
            "event=BARRIER_REPLY dpid=%s pair=%s remaining=%s",
            self._dpid(dpid),
            install.pair,
            [self._dpid(item) for item in sorted(install.pending_barriers)],
        )
        if not install.pending_barriers:
            self._complete_install(install)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def ofp_error_handler(self, ev: Any) -> None:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        error_type = getattr(msg, "type", None)
        error_code = getattr(msg, "code", None)
        data = bytes(getattr(msg, "data", b"") or b"")
        failed_xid: int | None = None
        if len(data) >= 8:
            failed_xid = int.from_bytes(data[4:8], "big")
        self.logger.warning(
            "event=OFP_ERROR dpid=%s type=%s code=%s failed_xid=%s",
            self._dpid(dpid),
            error_type,
            error_code,
            failed_xid,
        )
        owner = (
            self._xid_owner.get((dpid, failed_xid))
            if failed_xid is not None
            else None
        )
        if owner is None:
            self.logger.info(
                "event=OFP_ERROR_UNTRACKED dpid=%s failed_xid=%s "
                "reason=not-a-route-install",
                self._dpid(dpid),
                failed_xid,
            )
            return
        install, kind = owner
        self.logger.info(
            "event=OFP_ERROR_TRACKED pair=%s kind=%s failed_xid=%s",
            install.pair,
            kind,
            failed_xid,
        )
        self._fail_install(
            install,
            f"ofp-error type={error_type} code={error_code} "
            f"xid={failed_xid}",
        )

    # ----------------------------------------------------------- packet input
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: Any) -> None:
        """Learn hosts and mediate ARP/data forwarding."""

        msg = ev.msg
        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self._record_lldp_activity()
            return

        dpid = msg.datapath.id
        in_port = msg.match["in_port"]
        allowed, reason = self._host_event_allowed(
            str(eth.src), dpid, in_port
        )
        if not allowed:
            self._log_host_reject(
                str(eth.src),
                dpid,
                in_port,
                reason,
                event="PACKET_IN_DROP",
            )
            return
        self.datapaths.setdefault(dpid, msg.datapath)

        arp_packet = (
            pkt.get_protocol(arp.arp)
            if eth.ethertype == ether_types.ETH_TYPE_ARP
            else None
        )
        ipv4_packet = (
            pkt.get_protocol(ipv4.ipv4)
            if eth.ethertype == ether_types.ETH_TYPE_IP
            else None
        )
        source_ip: str | None = None
        if arp_packet is not None:
            source_ip = arp_packet.src_ip
        elif ipv4_packet is not None:
            source_ip = ipv4_packet.src

        learned_result = self._remember_host(
            str(eth.src), dpid, in_port, source_ip
        )
        if learned_result is None:
            return
        host, is_new, moved = learned_result
        if is_new:
            self._install_host_punt(msg.datapath, host)
        if moved:
            self._handle_topology_change("host-move")

        if not self._host_is_connected(host):
            self.logger.info(
                "event=PACKET_IN_DROP mac=%s dpid=%s port=%s "
                "reason=host-disconnected",
                host.mac,
                self._dpid(dpid),
                in_port,
            )
            return

        if arp_packet is not None:
            self._handle_arp(
                eth, arp_packet, data, dpid, in_port, host
            )
        else:
            self._forward_data(eth, dpid, in_port, host, data)
