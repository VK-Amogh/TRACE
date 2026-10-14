"""TRACE Model Context Protocol (MCP) stdio server implementation."""

import sys
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from trace_engine.findings.store import FindingStore
from trace_engine.constants import (
    DEFAULT_TARGET_URL,
    DEFAULT_MCP_HOST,
    DEFAULT_MCP_PORT,
    DEFAULT_TEST_TOKENS,
    VERIFY_HTTP_TIMEOUT,
    SCAN_HTTP_TIMEOUT,
)

logger = logging.getLogger("trace_mcp")

MAX_SESSIONS = 16
SESSION_TTL_SECONDS = 600
MAX_REQUEST_BYTES = 1024 * 1024
FINDINGS_DEFAULT_LIMIT = 20
FINDINGS_MAX_LIMIT = 100
EVIDENCE_PREVIEW = 10
SCAN_MAX_FILE_BYTES = 512 * 1024
MCP_PROTOCOL_VERSION = "2024-11-05"


def _server_version() -> str:
    try:
        from trace_engine import __version__

        return __version__
    except Exception:
        return "0.0.0"

# MCP Specification Tool Definitions
TRACE_TOOLS = [
    {
        "name": "trace_scan",
        "description": "Run complete TRACE static + runtime security audit on repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "default": ".", "description": "Path to target repository"},
                "target": {"type": "string", "default": DEFAULT_TARGET_URL, "description": "Target HTTP runtime URL"},
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
        "description": "Retrieve correlated vulnerability findings for repository (paginated).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "default": "."},
                "severity": {"type": "string", "description": "Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL"},
                "limit": {"type": "integer", "default": FINDINGS_DEFAULT_LIMIT, "description": "Max findings to return (1-100)"},
                "offset": {"type": "integer", "default": 0, "description": "Skip first N findings"},
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
                "target": {"type": "string", "default": DEFAULT_TARGET_URL},
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
                "target": {"type": "string", "default": DEFAULT_TARGET_URL},
                "rollback_after": {"type": "boolean", "default": False, "description": "Whether to rollback the patch after evaluation"},
            },
            "required": ["finding_id", "target_file", "patch_content"],
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
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "trace-security-mcp",
                        "version": _server_version(),
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
            except ValueError as e:
                logger.warning("MCP bad tool call %s: %s", tool_name, e)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": str(e)},
                }
            except Exception as e:
                logger.exception("MCP tool %s failed", tool_name)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": "tool execution failed"},
                }

        elif method == "ping":
            if msg_id is None:
                return None
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if msg_id is None:
            # JSON-RPC notification: no response allowed.
            return None
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method {method} not found"},
        }

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        repo_path = Path(args.get("repository", ".")).resolve()
        target_url = args.get("target", DEFAULT_TARGET_URL)

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
            severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            store = FindingStore(repo_path / ".trace")
            findings = store.load_findings()
            min_sev = str(args.get("severity", "") or "").upper()
            if min_sev in severity_order:
                cutoff = severity_order.index(min_sev)
                findings = [
                    f for f in findings
                    if f.severity.value in severity_order[cutoff:]
                ]
            try:
                limit = max(1, min(int(args.get("limit", FINDINGS_DEFAULT_LIMIT)), FINDINGS_MAX_LIMIT))
            except (TypeError, ValueError):
                limit = FINDINGS_DEFAULT_LIMIT
            try:
                offset = max(0, int(args.get("offset", 0)))
            except (TypeError, ValueError):
                offset = 0
            page = findings[offset:offset + limit]
            return {
                "total": len(findings),
                "limit": limit,
                "offset": offset,
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "category": f.category,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "endpoint": f.endpoint,
                        "short_action": f.short_action,
                        "source": str(f.source_location) if f.source_location else None,
                    }
                    for f in page
                ],
            }

        elif name == "trace_explain":
            finding_id = args.get("finding_id", "")
            if not finding_id:
                raise ValueError("trace_explain requires 'finding_id'")
            store = FindingStore(repo_path / ".trace")
            finding = store.get_finding_by_id(finding_id)
            if not finding:
                return {"error": f"Finding {finding_id} not found."}

            def _preview(items: Any) -> Any:
                if isinstance(items, list) and len(items) > EVIDENCE_PREVIEW:
                    return {
                        "shown": items[:EVIDENCE_PREVIEW],
                        "truncated": len(items) - EVIDENCE_PREVIEW,
                        "total": len(items),
                    }
                return items

            return {
                "id": finding.id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "endpoint": finding.endpoint,
                "source": str(finding.source_location),
                "attack_path": finding.attack_path,
                "root_cause": finding.root_cause,
                "short_action": finding.short_action,
                "static_evidence": _preview(finding.static_evidence),
                "runtime_evidence": _preview(finding.runtime_evidence),
                "correlation_notes": finding.correlation_notes,
                "reproduction_steps": _preview(finding.reproduction_steps),
                "remediation": finding.remediation,
            }

        elif name == "trace_verify":
            finding_id = args.get("finding_id", "")
            if not finding_id:
                raise ValueError("trace_verify requires 'finding_id'")
            from trace_engine.verify import VerificationEngine

            engine = VerificationEngine(
                repo_path=repo_path, target_url=target_url, timeout_seconds=VERIFY_HTTP_TIMEOUT
            )
            res = engine.verify(finding_id)
            return res.model_dump()

        elif name == "trace_scan":
            from trace_engine.ingest.repository import RepositoryScanner
            from trace_engine.parsing.parser import CodeParser
            from trace_engine.framework import get_adapters
            from trace_engine.apm.builder import APMBuilder
            from trace_engine.security.hypotheses import HypothesisEngine
            from trace_engine.policy.scope import ScopeGuard
            from trace_engine.runtime.client import ScopedHttpClient
            from trace_engine.testpacks.registry import default_registry
            from trace_engine.testpacks.base import TestContext
            from trace_engine.findings.correlate import EvidenceCorrelator

            # Execute scan programmatic flow
            profile = str(args.get("profile", "standard") or "standard").lower()
            run_probes = profile in ("standard", "deep")
            scanner = RepositoryScanner(repo_path)
            source_files = scanner.scan()
            parser = CodeParser()
            adapters = get_adapters()

            parsed_files = []
            discovered_endpoints = []
            skipped_large = 0
            for sf in source_files:
                if (sf.size_bytes or 0) > SCAN_MAX_FILE_BYTES:
                    skipped_large += 1
                    continue
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
            client = ScopedHttpClient(scope_guard=scope_guard, timeout_seconds=SCAN_HTTP_TIMEOUT)
            context = TestContext(
                target_base_url=target_url,
                active_tokens=dict(DEFAULT_TEST_TOKENS),
            )

            correlator = EvidenceCorrelator()
            findings = []
            for hyp in hypotheses:
                pack = default_registry.get(hyp.recommended_test_pack)
                test_res = None
                if pack and run_probes:
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
                "profile": profile,
                "total_findings": len(findings),
                "confirmed": sum(1 for f in findings if f.confidence.value == "CONFIRMED"),
                "endpoints_audited": len(discovered_endpoints),
                "files_skipped_large": skipped_large,
            }

        elif name == "trace_attack_path":
            endpoint_str = str(args.get("endpoint", "") or "")
            if not endpoint_str:
                raise ValueError("trace_attack_path requires 'endpoint'")
            store = FindingStore(repo_path / ".trace")
            matches = []
            for f in store.load_findings():
                if f.endpoint.lower() == endpoint_str.lower():
                    return {"endpoint": f.endpoint, "attack_path": f.attack_path}
                if endpoint_str.lower() in f.endpoint.lower():
                    matches.append({"endpoint": f.endpoint, "attack_path": f.attack_path})
                    if len(matches) >= 10:
                        break
            if len(matches) == 1:
                return matches[0]
            if matches:
                return {"endpoint": endpoint_str, "candidates": matches}
            return {"endpoint": endpoint_str, "attack_path": []}

        elif name == "trace_harness_task":
            finding_id = args.get("finding_id", "")
            if not finding_id:
                raise ValueError("trace_harness_task requires 'finding_id'")
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
            if not finding_id:
                raise ValueError("trace_eval_patch requires 'finding_id'")
            if not target_file:
                raise ValueError("trace_eval_patch requires 'target_file'")
            if patch_content is None:
                raise ValueError("trace_eval_patch requires 'patch_content'")
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

        raise ValueError(f"Unknown tool: {name}")

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
                except Exception:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue
            else:
                try:
                    req = json.loads(line_str)
                except Exception:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue

            try:
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception:
                logger.exception("MCP stdio request failed")
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req.get("id") if isinstance(req, dict) else None,
                    "error": {"code": -32603, "message": "Internal error"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

    def run_sse_server(self, host: str = DEFAULT_MCP_HOST, port: int = DEFAULT_MCP_PORT, allow_remote: bool = False):
        """Run an MCP HTTP/SSE transport server for Claude Code and local AI coding agents."""
        import uuid
        import queue
        import urllib.parse
        from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

        if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
            raise ValueError(
                f"Refusing to bind MCP server to non-loopback host '{host}' without allow_remote=True: "
                "trace_scan/trace_eval_patch can overwrite files and issue HTTP requests."
            )

        # session_id -> (queue, last_seen_monotonic)
        sessions: Dict[str, Any] = {}
        server_instance = self

        def _evict_sessions() -> None:
            now = time.monotonic()
            expired = [sid for sid, (_, seen) in sessions.items() if now - seen > SESSION_TTL_SECONDS]
            for sid in expired:
                _, q = sessions.pop(sid, (None, None))
                try:
                    if q is not None:
                        q.put(None)
                except Exception:
                    pass
            while len(sessions) >= MAX_SESSIONS:
                oldest = min(sessions, key=lambda sid: sessions[sid][1])
                _, q = sessions.pop(oldest, (None, None))
                try:
                    if q is not None:
                        q.put(None)
                except Exception:
                    break

        class MCPHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress request clutter in terminal

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/sse":
                    _evict_sessions()
                    session_id = uuid.uuid4().hex
                    msg_queue: queue.Queue = queue.Queue()
                    sessions[session_id] = (msg_queue, time.monotonic())

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
                                if session_id in sessions:
                                    sessions[session_id] = (msg_queue, time.monotonic())
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
                        "server": f"TRACE MCP Server v{_server_version()}",
                        "transport": "sse",
                        "sse_url": f"http://{host}:{port}/sse",
                        "active_sessions": len(sessions),
                        "tools": [t["name"] for t in TRACE_TOOLS],
                    }
                    self.wfile.write(json.dumps(status_info, indent=2).encode("utf-8"))

                elif parsed.path == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>TRACE Local MCP Server</title>
</head>
<body>
  <h1>TRACE MCP Server ONLINE</h1>
  <p>Local Model Context Protocol (MCP) server listening for Claude Code and AI coding agents.</p>
  <p>SSE endpoint: <code>http://{host}:{port}/sse</code></p>
  <p>Health: <code>http://{host}:{port}/health</code></p>
</body>
</html>"""
                    self.wfile.write(html.encode("utf-8"))

                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "not found"}).encode("utf-8"))

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path.startswith("/message"):
                    query = urllib.parse.parse_qs(parsed.query)
                    session_id = query.get("sessionId", [None])[0]

                    content_len = int(self.headers.get("Content-Length", 0) or 0)
                    if content_len > MAX_REQUEST_BYTES:
                        self.send_response(413)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "request too large"}).encode("utf-8"))
                        return
                    try:
                        body = self.rfile.read(content_len).decode("utf-8")
                    except Exception:
                        body = ""
                    try:
                        req = json.loads(body) if body else None
                        resp = server_instance.handle_request(req) if req else None
                    except Exception:
                        logger.exception("MCP SSE request failed")
                        resp = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32603, "message": "Internal error"},
                        }

                    entry = sessions.get(session_id) if session_id else None
                    if entry is not None and resp is not None:
                        msg_queue, _ = entry
                        try:
                            msg_queue.put(resp)
                        except Exception:
                            pass
                        sessions[session_id] = (msg_queue, time.monotonic())

                    # SSE spec: acknowledge receipt; the response travels on the event stream.
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps({"accepted": True}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "not found"}).encode("utf-8"))

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
