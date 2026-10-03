"""TRACE Agent Harness package for autonomous security auditing, benchmarking, and self-healing."""

from trace_engine.harness.context import (
    AgentRemediationPackage,
    PatchResult,
    HarnessExecutionReport,
)
from trace_engine.harness.patcher import SafePatcher
from trace_engine.harness.remediators import AutonomousRemediator
from trace_engine.harness.engine import AgentHarness

__all__ = [
    "AgentHarness",
    "AgentRemediationPackage",
    "PatchResult",
    "HarnessExecutionReport",
    "SafePatcher",
    "AutonomousRemediator",
]
