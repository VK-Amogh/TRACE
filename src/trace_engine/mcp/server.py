"""TRACE Model Context Protocol (MCP) stdio server implementation."""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

from trace_engine.findings.store import FindingStore
from trace_engine.verify import VerificationEngine
from trace_engine.ingest.repository import RepositoryScanner
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework import get_adapters
from trace_engine.apm.builder import APMBuilder
from trace_engine.apm.model import AttackPathModel
from trace_engine.security.hypotheses import HypothesisEngine
from trace_engine.policy.scope import ScopeGuard
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.testpacks.registry import default_registry
from trace_engine.testpacks.base import TestContext
from trace_engine.findings.correlate import EvidenceCorrelator
from trace_engine.config.loader import load_config, get_trace_dir

logger = logging.getLogger("trace_mcp")

# MCP Specification Tool Definitions
TRACE_TOOLS = [
    {
        "name": "trace_scan",
        "description": "Run complete TRACE static + runtime security audit on repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "default": ".", "description": "Path to target repository"},
                "target": {"type": "string", "default": "http://127.0.0.1:18080", "description": "Target HTTP runtime URL"},
                "profile": {"type": "string", "default": "standard", "enum": ["quick", "standard", "deep"]},
            },
            "required": ["repository"],
        },
    },
    {
        "name": "trace_status",
        "description": "Get current status and statistics of TRACE engine in repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "default": "."},
            },
        },
    },
    {
        "name": "trace_findings",
        "description": "Retrieve all correlated vulnerability findings for repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "default": "."},
                "severity": {"type": "string", "description": "Filter by minimum severity"},
            },
        },
    },
    {
        "name": "trace_explain",
        "description": "Retrieve root cause explanation, attack path, and evidence for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding identifier (e.g. TR-BOLA-001)"},
                "repository": {"type": "string", "default": "."},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "trace_attack_path",
        "description": "Inspect Attack-Path Model hops connecting an endpoint to dangerous sinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Endpoint path (e.g. /api/orders/{id})"},
                "repository": {"type": "string", "default": "."},
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "trace_verify",
        "description": "Verify whether a code modification by a coding agent resolved a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding identifier to verify"},
                "repository": {"type": "string", "default": "."},
                "target": {"type": "string", "default": "http://127.0.0.1:18080"},
            },
            "required": ["finding_id"],
        },
    },
]


class TraceMCPServer:
    """Stdio JSON-RPC 2.0 MCP server for coding agent handoff."""

    def __init__(self):
        self.running = True

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "trace-security-mcp",
                        "version": "2.0.0",
                    },
                    "capabilities": {"tools": {}},
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TRACE_TOOLS},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                res_content = self.execute_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(res_content, indent=2)}
                        ]
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method {method} not found"},
        }

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        repo_path = Path(args.get("repository", ".")).resolve()
        target_url = args.get("target", "http://127.0.0.1:18080")

        if name == "trace_status":
            trace_dir = repo_path / ".trace"
            store = FindingStore(trace_dir)
            findings = store.load_findings()
            return {
                "repository": str(repo_path),
                "initialized": trace_dir.exists(),
                "total_findings": len(findings),
                "confirmed": sum(1 for f in findings if f.confidence.value == "CONFIRMED"),
            }

        elif name == "trace_findings":
            store = FindingStore(repo_path / ".trace")
            findings = store.load_findings()
            return [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "endpoint": f.endpoint,
                    "remediation": f.remediation,
                    "source": str(f.source_location) if f.source_location else None,
                }
                for f in findings
            ]

        elif name == "trace_explain":
            finding_id = args.get("finding_id", "")
            store = FindingStore(repo_path / ".trace")
            finding = store.get_finding_by_id(finding_id)
            if not finding:
                return {"error": f"Finding {finding_id} not found."}
            return {
                "id": finding.id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "endpoint": finding.endpoint,
                "source": str(finding.source_location),
                "attack_path": finding.attack_path,
                "static_evidence": finding.static_evidence,
                "runtime_evidence": finding.runtime_evidence,
                "correlation_notes": finding.correlation_notes,
                "reproduction_steps": finding.reproduction_steps,
                "remediation": finding.remediation,
            }

        elif name == "trace_verify":
            finding_id = args.get("finding_id", "")
            engine = VerificationEngine(repo_path=repo_path, target_url=target_url)
            res = engine.verify(finding_id)
            return res.model_dump()

        elif name == "trace_scan":
            # Execute scan programmatic flow
            scanner = RepositoryScanner(repo_path)
            source_files = scanner.scan()
            parser = CodeParser()
            adapters = get_adapters()

            parsed_files = []
            discovered_endpoints = []
            for sf in source_files:
                content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
                pf = parser.parse(sf.path, content, sf.language)
                parsed_files.append(pf)
                for adapter in adapters:
                    if adapter.can_handle(pf):
                        discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

            builder = APMBuilder(project_name=repo_path.name)
            apm = builder.build(repo_path, source_files, parsed_files, discovered_endpoints)

            engine = HypothesisEngine()
            hypotheses = engine.derive_hypotheses(apm, discovered_endpoints)

            scope_guard = ScopeGuard()
            client = ScopedHttpClient(scope_guard=scope_guard)
            context = TestContext(
                target_base_url=target_url,
                active_tokens={"user-a": "user-a", "user-b": "user-b", "admin": "admin"},
            )

            correlator = EvidenceCorrelator()
            findings = []
            for hyp in hypotheses:
                pack = default_registry.get(hyp.recommended_test_pack)
                test_res = None
                if pack:
                    try:
                        test_res = pack.execute(hyp, client, context)
                    except Exception:
                        test_res = None
                f = correlator.correlate(hyp, test_res, apm)
                if f:
                    findings.append(f)

            store = FindingStore(repo_path / ".trace")
            store.save_findings(findings)

            return {
                "status": "completed",
                "total_findings": len(findings),
                "confirmed": sum(1 for f in findings if f.confidence.value == "CONFIRMED"),
                "endpoints_audited": len(discovered_endpoints),
            }

        elif name == "trace_attack_path":
            endpoint_str = args.get("endpoint", "")
            store = FindingStore(repo_path / ".trace")
            for f in store.load_findings():
                if endpoint_str.lower() in f.endpoint.lower():
                    return {"endpoint": f.endpoint, "attack_path": f.attack_path}
            return {"endpoint": endpoint_str, "attack_path": []}

        return {"error": f"Unknown tool: {name}"}

    def run_stdio(self):
        """Run the stdio JSON-RPC loop."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
