"""Model Context Protocol (MCP) server for coding agent integration."""

from trace_engine.mcp.server import TraceMCPServer, TRACE_TOOLS
from trace_engine.mcp.config import generate_mcp_json

__all__ = ["TraceMCPServer", "TRACE_TOOLS", "generate_mcp_json"]
