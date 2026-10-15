"""Unit tests for engine building blocks: ingest helpers, parsing symbols,
APM nodes/edges/serialization, runtime target, security signals, constants,
tools registry, and config loader."""

from pathlib import Path

from trace_engine.ingest.files import detect_language, EXTENSION_LANGUAGE_MAP
from trace_engine.ingest.hashing import hash_content
from trace_engine.ingest.ignore import IgnoreFilter, DEFAULT_IGNORE_DIRS
from trace_engine.parsing.symbols import FunctionSymbol, ClassSymbol
from trace_engine.parsing.locations import SourceLocation
from trace_engine.parsing.calls import CallSymbol
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.serialization import save_apm_sqlite
from trace_engine.runtime.target import Target
from trace_engine.security.signals import SecuritySignal, SignalType
from trace_engine import constants
from trace_engine.tools.registry import default_tool_registry
from trace_engine.config.loader import init_trace_dir, load_config


def test_detect_language_covers_common_extensions():
    assert detect_language(Path("a.py")) == "python"
    assert detect_language(Path("a.ts")) == "typescript"
    assert detect_language(Path("a.go")) == "go"
    assert ".py" in EXTENSION_LANGUAGE_MAP


def test_hash_content_stable():
    assert hash_content("hello") == hash_content("hello")
    assert hash_content("hello") != hash_content("world")


def test_ignore_filter_skips_defaults(tmp_path):
    filt = IgnoreFilter(repo_root=tmp_path)
    assert filt.should_ignore(tmp_path / "node_modules" / "x.js")
    assert not filt.should_ignore(tmp_path / "src" / "app.py")
    assert ".git" in DEFAULT_IGNORE_DIRS


def test_parsing_symbols_construct():
    loc = SourceLocation(file="a.py", line_start=1, line_end=5)
    fn = FunctionSymbol(name="get_order", qualified_name="api.get_order", location=loc)
    assert fn.name == "get_order"
    cls = ClassSymbol(name="OrderController", qualified_name="api.OrderController", location=loc)
    assert cls.name == "OrderController"
    call = CallSymbol(caller_name="a", callee_name="b", location=loc)
    assert call.callee_name == "b"


def test_apm_node_edge_types():
    node = APMNode(id="n1", node_type=NodeType.ENDPOINT, label="/api/x")
    assert node.node_type == NodeType.ENDPOINT
    edge = APMEdge(source_id="n1", target_id="n2", edge_type=EdgeType.CONTAINS)
    assert edge.edge_type == EdgeType.CONTAINS


def test_apm_sqlite_roundtrip(tmp_path):
    apm = AttackPathModel(name="t")
    apm.add_node(APMNode(id="n1", node_type=NodeType.ENDPOINT, label="/api/x"))
    db = tmp_path / "graph.db"
    save_apm_sqlite(apm, db)
    assert db.exists() and db.stat().st_size > 0


def test_runtime_target_from_url():
    t = Target.from_url("http://127.0.0.1:18080/api")
    assert t.host in ("127.0.0.1",)
    assert t.port == 18080


def test_security_signal_model():
    sig = SecuritySignal(
        id="SIG-001",
        signal_type=SignalType.MISSING_AUTH,
        endpoint_id="ep_1",
        title="missing auth",
        description="no auth middleware",
        severity_potential="HIGH",
        source=SourceLocation(file="a.py", line_start=1, line_end=2),
    )
    assert sig.signal_type == SignalType.MISSING_AUTH


def test_constants_sane():
    assert constants.DEFAULT_TARGET_URL.startswith("http://127.0.0.1:")
    assert constants.DEFAULT_MCP_PORT == 8765
    assert set(constants.DEFAULT_TEST_TOKENS) == {"user-a", "user-b", "admin"}
    assert constants.VERIFY_HTTP_TIMEOUT > 0


def test_tool_registry_lists_adapters():
    tools = default_tool_registry.list_all() if hasattr(default_tool_registry, "list_all") else default_tool_registry.get_all_info()
    assert len(tools) > 0


def test_config_loader_roundtrip(tmp_path):
    trace_dir = init_trace_dir(tmp_path, project_name="t")
    assert trace_dir.exists()
    cfg = load_config(tmp_path)
    assert cfg is not None
