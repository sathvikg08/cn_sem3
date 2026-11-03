"""Shortest-path routing and equal-cost path selection.

Dijkstra operates on the pure topology graph.  The selector is deliberately
policy-oriented: it accepts all equal-cost paths and either uses supplied
utilization measurements (Stage 5) or falls back to deterministic ECMP.
"""

from __future__ import annotations

import hashlib
import heapq
import math
from dataclasses import dataclass
from typing import Hashable, Mapping, Sequence

from sdn.topology import Link, NetworkGraph, PortRef


@dataclass(frozen=True)
class Path:
    """A simple, loop-free path through switches."""

    nodes: tuple[int, ...]
    links: tuple[Link, ...]

    def __post_init__(self) -> None:
        if not self.nodes:
            raise ValueError("path must contain at least one switch")
        if len(set(self.nodes)) != len(self.nodes):
            raise ValueError("path must not contain repeated switches")
        if len(self.links) != max(0, len(self.nodes) - 1):
            raise ValueError("path node and link counts are inconsistent")
        for index, link in enumerate(self.links):
            expected = {self.nodes[index], self.nodes[index + 1]}
            actual = {link.a.dpid, link.b.dpid}
            if expected != actual:
                raise ValueError("path links do not match adjacent nodes")

    @property
    def cost(self) -> float:
        return sum(link.cost for link in self.links)

    @property
    def source(self) -> int:
        return self.nodes[0]

    @property
    def destination(self) -> int:
        return self.nodes[-1]

    @property
    def signature(self) -> tuple[tuple[PortRef, PortRef], ...]:
        return tuple(link.key for link in self.links)

    def incoming_port(self, index: int) -> PortRef | None:
        if index <= 0:
            return None
        return self.links[index - 1].endpoint_for(self.nodes[index])

    def outgoing_port(self, index: int) -> PortRef | None:
        if index >= len(self.links):
            return None
        return self.links[index].endpoint_for(self.nodes[index])

    def __str__(self) -> str:
        return "->".join(str(dpid) for dpid in self.nodes)


def shortest_paths(
    graph: NetworkGraph,
    source: int,
    destination: int,
    *,
    max_paths: int = 8,
) -> list[Path]:
    """Return all equal-cost shortest paths, sorted deterministically.

    A single switch counts as a valid zero-cost local path.  Missing switches
    or a disconnected graph return an empty list.  The number of returned paths
    is capped by ``max_paths`` to keep route-state size bounded.
    """
    if max_paths < 1:
        raise ValueError("max_paths must be positive")
    if not graph.has_switch(source) or not graph.has_switch(destination):
        return []
    if source == destination:
        return [Path(nodes=(source,), links=())]

    distances: dict[int, float] = {source: 0.0}
    predecessors: dict[int, list[tuple[int, Link]]] = {source: []}
    heap: list[tuple[float, int]] = [(0.0, source)]
    settled: set[int] = set()

    while heap:
        distance, dpid = heapq.heappop(heap)
        if dpid in settled:
            continue
        settled.add(dpid)
        if distance != distances.get(dpid):
            continue
        for link in graph.active_links_for_switch(dpid):
            peer = link.other_dpid(dpid)
            candidate = distance + link.cost
            previous = distances.get(peer)
            if previous is None or candidate < previous:
                distances[peer] = candidate
                predecessors[peer] = [(dpid, link)]
                heapq.heappush(heap, (candidate, peer))
            elif math.isclose(candidate, previous, rel_tol=0.0, abs_tol=1e-9):
                predecessors[peer].append((dpid, link))

    if destination not in distances:
        return []

    results: list[Path] = []

    def reconstruct(dpid: int) -> list[tuple[tuple[int, ...], tuple[Link, ...]]]:
        if len(results) >= max_paths:
            return []
        if dpid == source:
            return [((source,), ())]
        built: list[tuple[tuple[int, ...], tuple[Link, ...]]] = []
        for predecessor, link in predecessors.get(dpid, []):
            for nodes, links in reconstruct(predecessor):
                built.append((nodes + (dpid,), links + (link,)))
                if len(results) + len(built) >= max_paths:
                    break
            if len(results) + len(built) >= max_paths:
                break
        return built

    seen: set[tuple[tuple[PortRef, PortRef], ...]] = set()
    for nodes, links in reconstruct(destination):
        path = Path(nodes=nodes, links=links)
        if path.signature in seen:
            continue
        seen.add(path.signature)
        results.append(path)
        if len(results) >= max_paths:
            break

    results.sort(key=lambda path: (path.cost, path.signature, path.nodes))
    return results


def shortest_path(
    graph: NetworkGraph,
    source: int,
    destination: int,
) -> Path | None:
    """Return the deterministic first shortest path, if one exists."""
    paths = shortest_paths(graph, source, destination, max_paths=1)
    return paths[0] if paths else None


@dataclass(frozen=True)
class PathSelection:
    """A selected path together with an auditable selection reason."""

    path: Path
    reason: str
    detail: str = ""


class PathSelector:
    """Choose among equal-cost paths.

    ``utilization`` is optional and is populated by the OpenFlow statistics
    collector in Stage 5.  If it is absent, incomplete or stale-looking, the
    selector falls back to deterministic ECMP based on the flow key.  The
    controller must log the returned reason so a path is never described as
    load-aware unless real measurements were used.
    """

    def choose(
        self,
        paths: Sequence[Path],
        *,
        flow_key: Hashable,
        utilization: Mapping[Path, float] | None = None,
    ) -> PathSelection:
        candidates = tuple(paths)
        if not candidates:
            raise ValueError("at least one path is required")

        ordered = tuple(sorted(candidates, key=lambda path: path.signature))
        if len(ordered) == 1:
            return PathSelection(
                path=ordered[0],
                reason="single-path",
                detail="only one available path",
            )

        if utilization is not None:
            known: dict[Path, float] = {}
            for path in ordered:
                value = utilization.get(path)
                if value is None:
                    continue
                try:
                    numeric = float(value)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(numeric) and numeric >= 0:
                    known[path] = numeric
            if len(known) == len(ordered):
                minimum = min(known.values())
                best = [
                    path
                    for path in ordered
                    if math.isclose(
                        known[path], minimum, rel_tol=1e-9, abs_tol=1e-12
                    )
                ]
                chosen = self._ecmp_choice(best, flow_key)
                return PathSelection(
                    path=chosen,
                    reason="load-aware",
                    detail=(
                        "least utilization "
                        + ", ".join(
                            f"{path}=" + f"{known[path]:.6g}"
                            for path in best
                        )
                    ),
                )

        chosen = self._ecmp_choice(ordered, flow_key)
        detail = "equal-cost deterministic ECMP"
        if utilization:
            detail += " (incomplete utilization data ignored)"
        return PathSelection(path=chosen, reason="ecmp", detail=detail)

    @staticmethod
    def _ecmp_choice(paths: Sequence[Path], flow_key: Hashable) -> Path:
        if len(paths) == 1:
            return paths[0]
        digest = hashlib.blake2b(
            repr(flow_key).encode("utf-8"), digest_size=8
        ).digest()
        index = int.from_bytes(digest, "big") % len(paths)
        return paths[index]
