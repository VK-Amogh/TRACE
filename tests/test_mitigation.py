"""Mitigation simulation: shared nodes rank first and the min cut is exact."""

from trace_engine.apm.edges import APMEdge, EdgeType
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.nodes import APMNode, NodeType


def build():
    apm = AttackPathModel("t")

    def node(i, kind, label=None):
        apm.add_node(APMNode(id=i, node_type=kind, label=label or i))

    def edge(a, b, kind=EdgeType.CALLS):
        apm.add_edge(APMEdge(source_id=a, target_id=b, edge_type=kind))

    for e in ("ep1", "ep2", "ep3"):
        node(e, NodeType.ENDPOINT)
    node("repo", NodeType.REPOSITORY)
    node("shared_repo_fn", NodeType.FUNCTION, "UserRepository.find")
    node("h1", NodeType.FUNCTION)
    node("h2", NodeType.FUNCTION)
    node("h3", NodeType.FUNCTION)
    node("db", NodeType.DATABASE, "users table")
    node("ext", NodeType.EXTERNAL_SERVICE, "payments api")
    edge("repo", "ep1", EdgeType.CONTAINS)  # structural edges are not attack flow
    for ep, h in (("ep1", "h1"), ("ep2", "h2"), ("ep3", "h3")):
        edge(ep, h, EdgeType.ROUTES_TO)
    edge("h1", "shared_repo_fn")
    edge("h2", "shared_repo_fn")
    edge("shared_repo_fn", "db", EdgeType.ACCESSES)
    edge("h3", "ext", EdgeType.CONNECTS_TO)
    return apm


def test_shared_node_removes_the_most_paths():
    plan = build().mitigation_plan(limit=3)
    assert plan["total_paths"] == 3 and not plan["truncated"]
    top = plan["fixes"][0]
    assert top["label"] == "UserRepository.find"
    assert top["paths_removed"] == 2 and top["coverage"] == round(2 / 3, 4)
    assert top["endpoints_fully_protected"] == 2
    assert {f["node"] for f in plan["fixes"]} <= {"shared_repo_fn", "h1", "h2", "h3"}


def test_min_cut_is_exact():
    plan = build().mitigation_plan()
    assert plan["min_cut"] == sorted(["UserRepository.find", "h3"])


def test_empty_and_unreachable_graphs_are_safe():
    assert AttackPathModel("e").mitigation_plan()["fixes"] == []
    apm = AttackPathModel("x")
    apm.add_node(APMNode(id="ep", node_type=NodeType.ENDPOINT, label="ep"))
    apm.add_node(APMNode(id="db", node_type=NodeType.DATABASE, label="db"))
    assert apm.mitigation_plan() == {"total_paths": 0, "truncated": False, "fixes": [], "min_cut": []}


def test_direct_endpoint_to_sink_hardens_the_endpoint():
    apm = AttackPathModel("d")
    apm.add_node(APMNode(id="ep", node_type=NodeType.ENDPOINT, label="GET /x"))
    apm.add_node(APMNode(id="db", node_type=NodeType.DATABASE, label="db"))
    apm.add_edge(APMEdge(source_id="ep", target_id="db", edge_type=EdgeType.ACCESSES))
    plan = apm.mitigation_plan()
    assert plan["fixes"][0]["label"] == "GET /x" and plan["fixes"][0]["paths_removed"] == 1
