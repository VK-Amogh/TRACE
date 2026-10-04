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
    {
        "name": "trace_harness_task",
        "description": "Retrieve benchmark task specification (SWE-bench format) for a security finding to guide an autonomous agent harness.",
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
        "name": "trace_eval_patch",
        "description": "Evaluate an agent's proposed patch or diff against the TRACE verification oracle and exploit tests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding identifier"},
                "patch_content": {"type": "string", "description": "Full new content for the target file"},
                "target_file": {"type": "string", "description": "Relative path to target file in repository"},
                "repository": {"type": "string", "default": "."},
                "target": {"type": "string", "default": "http://127.0.0.1:18080"},
                "rollback_after": {"type": "boolean", "default": False, "description": "Whether to rollback the patch after evaluation"},
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
                pf = parser.parse(sf.path, content, sf.language, absolute_path=sf.absolute_path)
                parsed_files.append(pf)
                for adapter in adapters:
                    if adapter.can_handle(pf):
                        discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

            builder = APMBuilder(project_name=repo_path.name)
            apm = builder.build(repo_path, source_files, parsed_files, discovered_endpoints)

            engine = HypothesisEngine()
            hypotheses = engine.derive_hypotheses(apm, discovered_endpoints)

            scope_guard = ScopeGuard()
            scope_guard.allow_target(target_url)
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

        elif name == "trace_harness_task":
            finding_id = args.get("finding_id", "")
            from trace_engine.plugin import TraceHarnessPlugin
            plugin = TraceHarnessPlugin(repo_path=repo_path, target_url=target_url)
            task = plugin.get_task(finding_id)
            if not task:
                return {"error": f"Harness task for finding '{finding_id}' not found."}
            return task.model_dump()

        elif name == "trace_eval_patch":
            finding_id = args.get("finding_id", "")
            patch_content = args.get("patch_content")
            target_file = args.get("target_file")
            rollback = args.get("rollback_after", False)
            from trace_engine.plugin import TraceHarnessPlugin
            plugin = TraceHarnessPlugin(repo_path=repo_path, target_url=target_url)
            eval_res = plugin.evaluate_patch(
                finding_id=finding_id,
                patch_content=patch_content,
                target_file=target_file,
                rollback_after=rollback,
            )
            return eval_res.model_dump()

        return {"error": f"Unknown tool: {name}"}

    def run_stdio(self):
        """Run the stdio JSON-RPC loop supporting both line-delimited JSON and Content-Length headers."""
        while self.running:
            line = sys.stdin.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue

            # Support Content-Length framing if sent by client
            if line_str.lower().startswith("content-length:"):
                try:
                    content_length = int(line_str.split(":", 1)[1].strip())
                    while True:
                        hdr = sys.stdin.readline()
                        if not hdr or hdr.strip() == "":
                            break
                    body = sys.stdin.read(content_length)
                    req = json.loads(body)
                except Exception as e:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {e}"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue
            else:
                try:
                    req = json.loads(line_str)
                except Exception as e:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {e}"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue

            try:
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req.get("id") if isinstance(req, dict) else None,
                    "error": {"code": -32603, "message": f"Internal error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

    def run_sse_server(self, host: str = "127.0.0.1", port: int = 8765):
        """Run an MCP HTTP/SSE transport server for Claude Code and local AI coding agents."""
        import uuid
        import queue
        import urllib.parse
        from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

        sessions: Dict[str, queue.Queue] = {}
        server_instance = self

        class MCPHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress request clutter in terminal

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.end_headers()

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/sse":
                    session_id = uuid.uuid4().hex
                    msg_queue: queue.Queue = queue.Queue()
                    sessions[session_id] = msg_queue

                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()

                    # Emit endpoint event as defined in MCP SSE transport specification
                    endpoint_msg = f"event: endpoint\r\ndata: /message?sessionId={session_id}\r\n\r\n"
                    self.wfile.write(endpoint_msg.encode("utf-8"))
                    self.wfile.flush()

                    try:
                        while server_instance.running:
                            try:
                                msg = msg_queue.get(timeout=1.0)
                                if msg is None:
                                    break
                                event_str = f"event: message\r\ndata: {json.dumps(msg)}\r\n\r\n"
                                self.wfile.write(event_str.encode("utf-8"))
                                self.wfile.flush()
                            except queue.Empty:
                                self.wfile.write(b": keepalive\r\n\r\n")
                                self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        sessions.pop(session_id, None)

                elif parsed.path in ("/health", "/status"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    status_info = {
                        "status": "online",
                        "server": "TRACE MCP Server v2.1",
                        "transport": "sse",
                        "sse_url": f"http://{host}:{port}/sse",
                        "active_sessions": len(sessions),
                        "tools": [t["name"] for t in TRACE_TOOLS],
                    }
                    self.wfile.write(json.dumps(status_info, indent=2).encode("utf-8"))

                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>TRACE Local MCP Server</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f17; color: #f8fafc; padding: 40px; margin: 0; }}
    .container {{ max-width: 680px; margin: 0 auto; background: #131b2e; border: 1px solid #10b981; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    h1 {{ color: #10b981; margin-top: 0; display: flex; align-items: center; gap: 10px; font-size: 24px; }}
    .badge {{ background: #10b981; color: #0b0f17; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    p {{ color: #94a3b8; font-size: 14px; line-height: 1.6; }}
    .cmd-box {{ background: #070a12; border: 1px solid #1e293b; border-radius: 6px; padding: 12px 16px; margin: 12px 0; font-family: monospace; color: #38bdf8; font-size: 13px; word-break: break-all; }}
    .section-title {{ color: #ffffff; font-size: 14px; font-weight: bold; margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>TRACE MCP Server <span class="badge">ONLINE</span></h1>
    <p>Local Model Context Protocol (MCP) server listening for Claude Code and AI coding agents.</p>
    
    <div class="section-title">Local MCP Endpoint Link:</div>
    <div class="cmd-box">http://{host}:{port}/sse</div>

    <div class="section-title">Connect via Claude Code CLI:</div>
    <div class="cmd-box">claude mcp add --transport sse trace http://{host}:{port}/sse</div>

    <div class="section-title">Connect in Claude Chat:</div>
    <p>Paste the local MCP link into your Claude chat to grant autonomous AST scanning and verification powers:</p>
    <div class="cmd-box">http://{host}:{port}/sse</div>
  </div>
</body>
</html>"""
                    self.wfile.write(html.encode("utf-8"))

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path.startswith("/message"):
                    query = urllib.parse.parse_qs(parsed.query)
                    session_id = query.get("sessionId", [None])[0]

                    content_len = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(content_len).decode("utf-8")
                    try:
                        req = json.loads(body)
                        resp = server_instance.handle_request(req)
                    except Exception as e:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32603, "message": str(e)},
                        }

                    if session_id and session_id in sessions and resp:
                        sessions[session_id].put(resp)

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps(resp or {"jsonrpc": "2.0", "result": None}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

        GREEN = "\033[38;2;16;185;129m"
        CYAN = "\033[38;2;56;189;248m"
        ORANGE = "\033[38;2;255;158;59m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"

        print(f"\n  {GREEN}┌{'─' * 74}┐{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}TRACE Local MCP Server (Model Context Protocol){RESET}                     {GREEN}│{RESET}")
        print(f"  {GREEN}├{'─' * 74}┤{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}Local MCP Link   :{RESET} {CYAN}http://{host}:{port}/sse{RESET}{' ' * max(0, 39 - len(f'http://{host}:{port}/sse'))}{GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}Web Dashboard    :{RESET} {CYAN}http://{host}:{port}/{RESET}{' ' * max(0, 42 - len(f'http://{host}:{port}/'))}{GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}Status           :{RESET} {GREEN}ONLINE{RESET} (Listening for Claude Code & AI Coding Agents)  {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}                                                                          {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}Connect in Claude Code CLI:{RESET}                                             {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}   {ORANGE}›{RESET} {BOLD}claude mcp add --transport sse trace http://{host}:{port}/sse{RESET}          {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}                                                                          {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}  {BOLD}Or paste this link directly in your Claude Code chat:{RESET}                   {GREEN}│{RESET}")
        print(f"  {GREEN}│{RESET}   {CYAN}http://{host}:{port}/sse{RESET}{' ' * max(0, 49 - len(f'http://{host}:{port}/sse'))}{GREEN}│{RESET}")
        print(f"  {GREEN}└{'─' * 74}┘{RESET}\n")
        print(f"  {DIM}Press Ctrl+C to terminate the local MCP server.{RESET}\n")

        httpd = ThreadingHTTPServer((host, port), MCPHandler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n  {ORANGE}[TRACE] MCP Server stopped.{RESET}\n")
        finally:
            httpd.server_close()
