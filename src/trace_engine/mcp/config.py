"""Project-local MCP configuration generator (Section 64)."""

import json
import sys
from pathlib import Path
from typing import Optional


def generate_mcp_json(project_dir: Path, trace_cmd_path: Optional[str] = None) -> Path:
    """Generate .mcp.json in the repository directory."""
    project_dir = project_dir.resolve()
    mcp_file = project_dir / ".mcp.json"

    # Command to run trace mcp
    cmd = trace_cmd_path or (
        str((Path(__file__).parent.parent.parent.parent / "trace.cmd").resolve())
        if sys.platform == "win32"
        else "trace"
    )

    config_data = {
        "mcpServers": {
            "trace": {
                "command": cmd,
                "args": ["mcp"],
            }
        }
    }

    with open(mcp_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    return mcp_file
