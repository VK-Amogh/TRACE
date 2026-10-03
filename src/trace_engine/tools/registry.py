"""Registry of external security tool adapters."""

from typing import List, Dict, Optional
from trace_engine.tools.base import ToolAdapter, ToolInfo
from trace_engine.tools.adapters import (
    SchemathesisAdapter,
    NucleiAdapter,
    ZapAdapter,
    TruffleHogAdapter,
    SqlmapAdapter,
    FfufAdapter,
)


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolAdapter] = {
            "schemathesis": SchemathesisAdapter(),
            "nuclei": NucleiAdapter(),
            "zap": ZapAdapter(),
            "trufflehog": TruffleHogAdapter(),
            "sqlmap": SqlmapAdapter(),
            "ffuf": FfufAdapter(),
        }

    def list_all(self) -> List[ToolAdapter]:
        return list(self._tools.values())

    def get(self, name: str) -> Optional[ToolAdapter]:
        return self._tools.get(name.lower())

    def get_all_info(self) -> List[ToolInfo]:
        return [t.get_info() for t in self._tools.values()]


default_tool_registry = ToolRegistry()
