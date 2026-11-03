"""Pure-Python SDN primitives.

This package deliberately has no dependency on OS-Ken, Mininet or Open vSwitch.
The OS-Ken controller imports these modules, but the graph and path-selection
logic can be tested with ordinary pytest and no root privileges.
"""

from sdn.topology import HostLocation, Link, NetworkGraph, PortRef, SwitchNode

__all__ = [
    "HostLocation",
    "Link",
    "NetworkGraph",
    "PortRef",
    "SwitchNode",
]
