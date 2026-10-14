"""Shared runtime defaults for TRACE (single source; env-overridable where noted).

Import from here instead of hardcoding hosts, ports, timeouts, or tokens.
"""

import os

DEFAULT_TARGET_URL = os.environ.get("TRACE_TARGET_URL", "http://127.0.0.1:18080")
DEFAULT_MCP_HOST = os.environ.get("TRACE_MCP_HOST", "127.0.0.1")
DEFAULT_MCP_PORT = int(os.environ.get("TRACE_MCP_PORT", "8765"))

# Synthetic probe identities (test traffic only, never real credentials).
DEFAULT_TEST_TOKENS = {
    "user-a": "user-a",
    "user-b": "user-b",
    "admin": "admin",
}

# HTTP timeouts (seconds).
SCAN_HTTP_TIMEOUT = float(os.environ.get("TRACE_HTTP_TIMEOUT", "8.0"))
VERIFY_HTTP_TIMEOUT = float(os.environ.get("TRACE_VERIFY_TIMEOUT", "4.0"))
