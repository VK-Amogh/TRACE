"""Project-local MCP configuration generator (Section 64)."""

import json
import sys
from pathlib import Path
from typing import Optional


def generate_mcp_json(project_dir: Path, trace_cmd_path: Optional[str] = None) -> Path:
    """Generate .mcp.json in the repository directory, preserving other servers."""
    project_dir = project_dir.resolve()
    if not project_dir.is_dir():
        raise ValueError(f"Project directory does not exist: {project_dir}")
    mcp_file = project_dir / ".mcp.json"

    if trace_cmd_path:
        cmd = trace_cmd_path
        args = ["mcp"]
    else:
        # Deterministic: prefer the current interpreter over PATH shims.
        cmd = sys.executable
        args = ["-m", "trace_engine.cli", "mcp"]

    existing: dict = {}
    if mcp_file.exists():
        try:
            existing = json.loads(mcp_file.read_text(encoding="utf-8"))
        except Exception:
            backup = mcp_file.with_suffix(".json.bak")
            mcp_file.rename(backup)
            existing = {}
    servers = existing.get("mcpServers", {}) if isinstance(existing, dict) else {}

    config_data = {
        "mcpServers": {
            **servers,
            "trace": {
                "command": cmd,
                "args": args,
                "env": {"PYTHONUNBUFFERED": "1"},
            },
        }
    }

    with open(mcp_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    return mcp_file
