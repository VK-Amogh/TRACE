"""Environment diagnostics and system readiness check (trace doctor)."""

import sys
import sqlite3
import shutil
from typing import List, Dict, Any
from pydantic import BaseModel

from trace_engine.tools.registry import default_tool_registry
from trace_engine.ai.ollama import OllamaProvider


class CheckItem(BaseModel):
    name: str
    status: bool  # True for pass, False for fail/missing
    category: str
    details: str
    critical: bool = False


class DoctorReport(BaseModel):
    items: List[CheckItem]
    all_critical_passed: bool


def run_doctor() -> DoctorReport:
    """Runs system diagnostics across runtime, AI, tools, and dependencies."""
    items: List[CheckItem] = []

    # 1. Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    items.append(
        CheckItem(
            name=f"Python {py_ver}",
            status=py_ok,
            category="Core Runtime",
            details="Requires Python >= 3.11",
            critical=True,
        )
    )

    # 2. SQLite
    try:
        conn = sqlite3.connect(":memory:")
        conn.close()
        items.append(
            CheckItem(
                name="SQLite 3",
                status=True,
                category="Core Runtime",
                details=f"SQLite version {sqlite3.sqlite_version}",
                critical=True,
            )
        )
    except Exception as e:
        items.append(
            CheckItem(
                name="SQLite 3",
                status=False,
                category="Core Runtime",
                details=str(e),
                critical=True,
            )
        )

    # 3. Tree-sitter
    try:
        import tree_sitter_language_pack
        items.append(
            CheckItem(
                name="Tree-sitter Language Pack",
                status=True,
                category="Code Analysis",
                details="Multi-language AST parsing enabled",
                critical=True,
            )
        )
    except Exception as e:
        items.append(
            CheckItem(
                name="Tree-sitter",
                status=False,
                category="Code Analysis",
                details="Fallback AST mode active",
                critical=False,
            )
        )

    # 4. NetworkX
    try:
        import networkx as nx
        items.append(
            CheckItem(
                name="NetworkX",
                status=True,
                category="Attack-Path Model",
                details=f"Graph engine v{nx.__version__}",
                critical=True,
            )
        )
    except Exception as e:
        items.append(
            CheckItem(
                name="NetworkX",
                status=False,
                category="Attack-Path Model",
                details=str(e),
                critical=True,
            )
        )

    # 5. HTTPX
    try:
        import httpx
        items.append(
            CheckItem(
                name="HTTPX Scoped Client",
                status=True,
                category="Runtime Testing",
                details=f"HTTP engine v{httpx.__version__}",
                critical=True,
            )
        )
    except Exception as e:
        items.append(
            CheckItem(
                name="HTTPX",
                status=False,
                category="Runtime Testing",
                details=str(e),
                critical=True,
            )
        )

    # 6. Local AI (Ollama)
    ollama = OllamaProvider()
    ollama_ok = ollama.is_available()
    items.append(
        CheckItem(
            name="Ollama Local LLM",
            status=ollama_ok,
            category="AI Inference",
            details="Connected at http://127.0.0.1:11434" if ollama_ok else "Not reachable (using deterministic planner)",
            critical=False,
        )
    )

    # 7. External Tools
    for tool_info in default_tool_registry.get_all_info():
        items.append(
            CheckItem(
                name=tool_info.name,
                status=tool_info.installed,
                category="Security Tool Adapters",
                details=tool_info.version or f"Executable '{tool_info.command}' not found in PATH",
                critical=False,
            )
        )

    # 8. Docker
    docker_installed = shutil.which("docker") is not None
    items.append(
        CheckItem(
            name="Docker Desktop / CLI",
            status=docker_installed,
            category="Lab Isolation",
            details="Available for isolated container labs" if docker_installed else "Not found (local process labs enabled)",
            critical=False,
        )
    )

    all_crit = all(item.status for item in items if item.critical)
    return DoctorReport(items=items, all_critical_passed=all_crit)
