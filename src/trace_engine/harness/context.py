"""Agent remediation context and task models for the TRACE Agent Harness."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AgentRemediationPackage(BaseModel):
    """Self-contained remediation context payload delivered to an autonomous coding agent."""
    finding_id: str
    title: str
    category: str
    severity: str
    priority_rank: int
    endpoint: str
    source_file: str
    line_start: int
    line_end: int
    code_snippet: str
    attack_path_hops: List[str] = Field(default_factory=list)
    runtime_exploit_proof: List[str] = Field(default_factory=list)
    remediation_guidance: str
    reproduction_steps: List[str] = Field(default_factory=list)
    verification_criteria: str
    raw_observation: Optional[Dict[str, Any]] = None


class PatchResult(BaseModel):
    """Result of applying a code modification via the Agent Harness."""
    finding_id: str
    target_file: str
    success: bool
    backup_file: Optional[str] = None
    diff: Optional[str] = None
    error: Optional[str] = None


class HarnessExecutionReport(BaseModel):
    """Outcome of a complete Agent Harness remediation or benchmark run."""
    project_name: str
    baseline_score: int
    final_score: int
    score_delta: int
    total_findings: int
    fixed_findings: int
    remaining_findings: int
    fix_rate_percent: float
    verified_patches: List[Dict[str, Any]] = Field(default_factory=list)
    unresolved_findings: List[str] = Field(default_factory=list)
    execution_time_seconds: float
