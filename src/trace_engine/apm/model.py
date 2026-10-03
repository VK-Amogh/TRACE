"""Attack-Path Model (APM) graph representation using NetworkX."""

import networkx as nx
from typing import List, Dict, Any, Optional, Set
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType


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

    def find_paths_from_endpoint(self, endpoint_id: str, max_depth: int = 4) -> List[List[str]]:
        """Find all downstream paths originating from an endpoint up to max_depth."""
        if endpoint_id not in self.graph:
            return []

        paths: List[List[str]] = []
        visited = set()

        def dfs(curr: str, current_path: List[str], depth: int):
            if depth > max_depth or curr in visited:
                return
            current_path.append(curr)
            visited.add(curr)

            successors = list(self.graph.successors(curr))
            if not successors:
                paths.append(list(current_path))
            else:
                for succ in successors:
                    dfs(succ, current_path, depth + 1)

            visited.remove(curr)
            current_path.pop()

        dfs(endpoint_id, [], 0)
        return paths

    def find_paths_to_sinks(self, endpoint_id: str) -> List[List[str]]:
        """Find paths connecting an endpoint to any Sink node."""
        sink_nodes = [
            n_id
            for n_id, n in self.nodes_data.items()
            if n.node_type in (NodeType.SINK, NodeType.DATABASE, NodeType.EXTERNAL_SERVICE)
        ]
        
        result_paths = []
        for sink_id in sink_nodes:
            if nx.has_path(self.graph, endpoint_id, sink_id):
                for path in nx.all_simple_paths(self.graph, endpoint_id, sink_id, cutoff=5):
                    result_paths.append(path)
        return result_paths

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
