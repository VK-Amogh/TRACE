"""Task and benchmark specifications for the TRACE Agent Harness Plugin."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class HarnessTaskSpec(BaseModel):
    """Standardized task instance specification for AI coding agent harnesses.
    
    Compatible with SWE-bench, OpenHands, and Antigravity task schemas.
    """
    instance_id: str
    finding_id: str
    title: str
    category: str
    severity: str
    repo_name: str
    endpoint: str
    source_file: str
    line_start: int
    line_end: int
    code_snippet: str
    problem_statement: str
    hints_text: str
    attack_path_hops: List[str] = Field(default_factory=list)
    runtime_exploit_proof: List[str] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    fail_to_pass: List[str] = Field(default_factory=list)
    pass_to_pass: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_swebench_dict(self) -> Dict[str, Any]:
        """Convert this task instance into a standard SWE-bench JSON object."""
        return {
            "instance_id": self.instance_id,
            "repo": self.repo_name,
            "base_commit": self.metadata.get("base_commit", "HEAD"),
            "problem_statement": self.problem_statement,
            "hints_text": self.hints_text,
            "created_at": self.metadata.get("created_at", "2026-10-03T00:00:00Z"),
            "version": "1.0",
            "FAIL_TO_PASS": self.fail_to_pass,
            "PASS_TO_PASS": self.pass_to_pass,
            "environment_setup_commit": self.metadata.get("environment_setup_commit", "HEAD"),
            "target_endpoint": self.endpoint,
            "source_location": f"{self.source_file}:{self.line_start}-{self.line_end}",
            "vulnerability_category": self.category,
        }
