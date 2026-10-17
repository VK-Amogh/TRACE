"""Attack-Path Model (APM) graph representation using NetworkX."""

import networkx as nx
from typing import List, Dict, Any, Optional, Set
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType

_EXACT_BETWEENNESS_MAX_NODES = 2000
_BETWEENNESS_SAMPLE_SOURCES = 256


class AttackPathModel:
    """Core Attack-Path Model representing application architecture and attack surface."""

    def __init__(self, name: str = "project"):
        self.name = name
        self.graph = nx.DiGraph()
        self.nodes_data: Dict[str, APMNode] = {}
        self.edges_data: List[APMEdge] = []

    def add_node(self, node: APMNode) -> None:
        """Add an APM node to the graph."""
        self.nodes_data[node.id] = node
        self.graph.add_node(
            node.id,
            node_type=node.node_type.value,
            label=node.label,
            source_location=node.location.model_dump() if node.location else None,
            **node.properties,
        )

    def add_edge(self, edge: APMEdge) -> None:
        """Add a directed APM edge to the graph."""
        self.edges_data.append(edge)
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type.value,
            **edge.properties,
        )

    def get_node(self, node_id: str) -> Optional[APMNode]:
        return self.nodes_data.get(node_id)

    def get_endpoints(self) -> List[APMNode]:
        """Return all endpoint nodes in the graph."""
        return [
            node
            for node in self.nodes_data.values()
            if node.node_type == NodeType.ENDPOINT
        ]

    def find_paths_from_endpoint(self, endpoint_id: str, max_depth: int = 4, limit: int = 25) -> List[List[str]]:
        """Find downstream paths from an endpoint up to max_depth, capped at limit paths."""
        if endpoint_id not in self.graph:
            return []

        paths: List[List[str]] = []
        visited = set()

        def dfs(curr: str, current_path: List[str], depth: int):
            if len(paths) >= limit:
                return
            if depth > max_depth or curr in visited:
                return
            current_path.append(curr)
            visited.add(curr)

            successors = list(self.graph.successors(curr))
            if not successors:
                paths.append(list(current_path))
            else:
                for succ in successors:
                    if len(paths) >= limit:
                        break
                    dfs(succ, current_path, depth + 1)

            visited.remove(curr)
            current_path.pop()

        dfs(endpoint_id, [], 0)
        return paths[:limit]

    def find_paths_to_sinks(self, endpoint_id: str, cutoff: int = 5, limit: int = 25) -> List[List[str]]:
        """Find paths connecting an endpoint to any Sink node, capped at limit paths."""
        sink_nodes = [
            n_id
            for n_id, n in self.nodes_data.items()
            if n.node_type in (NodeType.SINK, NodeType.DATABASE, NodeType.EXTERNAL_SERVICE)
        ]

        result_paths = []
        for sink_id in sink_nodes:
            if len(result_paths) >= limit:
                break
            try:
                if nx.has_path(self.graph, endpoint_id, sink_id):
                    for path in nx.all_simple_paths(self.graph, endpoint_id, sink_id, cutoff=cutoff):
                        result_paths.append(path)
                        if len(result_paths) >= limit:
                            break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        return result_paths[:limit]

    def choke_points(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Rank nodes by betweenness centrality: fixing these covers the
        most endpoint-to-sink reachability (choke-point prioritization)."""
        if self.graph.number_of_nodes() == 0:
            return []
        try:
            node_count = self.graph.number_of_nodes()
            if node_count > _EXACT_BETWEENNESS_MAX_NODES:
                # Exact Brandes is O(V*E) and dominates runtime on large
                # real-world graphs; sample a seeded set of sources instead.
                # Deterministic and preserves the top rankings.
                centrality = nx.betweenness_centrality(
                    self.graph,
                    k=min(node_count, _BETWEENNESS_SAMPLE_SOURCES),
                    seed=42,
                )
            else:
                centrality = nx.betweenness_centrality(self.graph)
        except Exception:
            return []
        ranked = sorted(centrality.items(), key=lambda kv: kv[1], reverse=True)
        points = []
        for node_id, score in ranked:
            if score <= 0:
                break
            node = self.nodes_data.get(node_id)
            points.append(
                {
                    "node": node_id,
                    "label": node.label if node else node_id,
                    "type": node.node_type.value if node else "UNKNOWN",
                    "betweenness": round(float(score), 4),
                }
            )
            if len(points) >= limit:
                break
        return points

    def minimum_cut_size(self) -> Optional[int]:
        """Global minimum edge cut size (number of edges whose removal
        disconnects the graph most cheaply). None when not computable."""
        try:
            cut = nx.minimum_edge_cut(self.graph)
            return len(cut)
        except Exception:
            return None

    def mitigation_plan(self, limit: int = 5) -> Dict[str, Any]:
        """Which single fixes remove the most endpoint-to-sink attack paths."""
        from trace_engine.apm.mitigation import mitigation_plan

        return mitigation_plan(self, limit=limit)

    def summary(self) -> Dict[str, Any]:
        """Return a statistical overview of the graph."""
        type_counts: Dict[str, int] = {}
        for node in self.nodes_data.values():
            type_counts[node.node_type.value] = type_counts.get(node.node_type.value, 0) + 1

        edge_counts: Dict[str, int] = {}
        for edge in self.edges_data:
            edge_counts[edge.edge_type.value] = edge_counts.get(edge.edge_type.value, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "nodes_by_type": type_counts,
            "edges_by_type": edge_counts,
        }
