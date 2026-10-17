"""Mitigation simulation on the Attack-Path Model.

Answers "which single change removes the most attack paths?" by enumerating
bounded endpoint-to-sink paths and counting how many pass through each shared
node, plus an exact minimum vertex cut separating all endpoints from all
sinks. Complements betweenness-based choke points with an explicit "fixing
node X removes N of M paths" statement.
"""

from typing import Any, Dict, List, Set, Tuple

import networkx as nx

from trace_engine.apm.nodes import NodeType

_FLOW_EDGES = {"ROUTES_TO", "CALLS", "ACCESSES", "SINKS_TO", "CONNECTS_TO"}
_TARGET_TYPES = {NodeType.SINK, NodeType.DATABASE, NodeType.EXTERNAL_SERVICE}
_MAX_CUT_NODES = 4000


def _flow_graph(apm) -> nx.DiGraph:
    g = nx.DiGraph()
    for src, dst, data in apm.graph.edges(data=True):
        if data.get("edge_type") in _FLOW_EDGES:
            g.add_edge(src, dst)
    return g


def mitigation_plan(apm, limit: int = 5, cutoff: int = 6, max_paths: int = 2000) -> Dict[str, Any]:
    """Rank single-node fixes by the attack paths they remove."""
    entries = [n.id for n in apm.nodes_data.values() if n.node_type == NodeType.ENDPOINT]
    targets = {n.id for n in apm.nodes_data.values() if n.node_type in _TARGET_TYPES}
    g = _flow_graph(apm)
    plan: Dict[str, Any] = {"total_paths": 0, "truncated": False, "fixes": [], "min_cut": []}
    if not entries or not targets or g.number_of_nodes() == 0:
        return plan

    paths: List[Tuple[str, ...]] = []
    for entry in entries:
        if entry not in g:
            continue
        for target in targets & set(g.nodes):
            if entry == target:
                continue
            try:
                for p in nx.all_simple_paths(g, entry, target, cutoff=cutoff):
                    paths.append(tuple(p))
                    if len(paths) >= max_paths:
                        plan["truncated"] = True
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if plan["truncated"]:
                break
        if plan["truncated"]:
            break
    plan["total_paths"] = len(paths)
    if not paths:
        return plan

    through: Dict[str, int] = {}
    entry_paths: Dict[str, int] = {}
    node_entry_paths: Dict[Tuple[str, str], int] = {}
    for p in paths:
        entry_paths[p[0]] = entry_paths.get(p[0], 0) + 1
        interior = list(p[1:-1]) or [p[0]]  # direct endpoint -> sink: harden the endpoint itself
        for node in set(interior):
            through[node] = through.get(node, 0) + 1
            node_entry_paths[(node, p[0])] = node_entry_paths.get((node, p[0]), 0) + 1

    fixes: List[Dict[str, Any]] = []
    for node, count in through.items():
        covered = [e for e in entry_paths if node_entry_paths.get((node, e), 0) == entry_paths[e]]
        n = apm.nodes_data.get(node)
        fixes.append(
            {
                "node": node,
                "label": n.label if n else node,
                "type": n.node_type.value if n else "UNKNOWN",
                "paths_removed": count,
                "coverage": round(count / len(paths), 4),
                "endpoints_fully_protected": len(covered),
            }
        )
    fixes.sort(key=lambda f: (-f["paths_removed"], -f["endpoints_fully_protected"], f["node"]))
    plan["fixes"] = fixes[:limit]
    plan["min_cut"] = _min_cut(apm, g, entries, targets)
    return plan


def _min_cut(apm, g: nx.DiGraph, entries: List[str], targets: Set[str]) -> List[str]:
    """Cheapest node set whose removal disconnects every entry from every sink.

    Interior nodes cost 1, hardening an endpoint itself costs 3 (so shared
    code is preferred), sinks cannot be cut. Solved as a min cut on the
    node-split flow network.
    """
    if g.number_of_nodes() > _MAX_CUT_NODES:
        return []
    inf = float("inf")
    entry_set = set(entries)
    flow = nx.DiGraph()
    src, dst = "__entries__", "__sinks__"
    for node in g.nodes:
        cap = inf if node in targets else (3 if node in entry_set else 1)
        flow.add_edge((node, "in"), (node, "out"), capacity=cap)
    for u, v in g.edges:
        flow.add_edge((u, "out"), (v, "in"), capacity=inf)
    for e in entry_set & set(g.nodes):
        flow.add_edge(src, (e, "in"), capacity=inf)
    for t in targets & set(g.nodes):
        flow.add_edge((t, "out"), dst, capacity=inf)
    if src not in flow or dst not in flow:
        return []
    try:
        value, (reachable, _) = nx.minimum_cut(flow, src, dst)
    except nx.NetworkXUnbounded:
        return []
    if value == inf:
        return []
    labels = []
    for node in sorted(g.nodes):
        if (node, "in") in reachable and (node, "out") not in reachable:
            n = apm.nodes_data.get(node)
            labels.append(n.label if n else node)
    return sorted(labels)
