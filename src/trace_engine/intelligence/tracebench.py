"""TRACEBench dataset generation and recording for training/benchmarking."""

import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from trace_engine.findings.model import Finding
from trace_engine.apm.model import AttackPathModel
from trace_engine.testpacks.base import TestExecutionResult


class TRACEBenchRecord(BaseModel):
    """Ground truth record matching Section 19 of TRACE Specification."""
    timestamp: float = Field(default_factory=time.time)
    repository: str
    endpoint: str
    attack_path: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    candidate_tests: List[str] = Field(default_factory=list)
    executed_tests: List[Dict[str, Any]] = Field(default_factory=list)
    ground_truth: str  # "confirmed", "safe", "inconclusive"


class TRACEBenchRecorder:
    """Records real security analysis and runtime test trajectories into TRACEBench."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("training/datasets")
        self.output_file = self.output_dir / "tracebench.jsonl"

    def record_run(
        self,
        repository_name: str,
        finding: Finding,
        apm: AttackPathModel,
    ) -> TRACEBenchRecord:
        """Saves a confirmed or evaluated finding as a TRACEBench dataset record."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        record = TRACEBenchRecord(
            repository=repository_name,
            endpoint=finding.endpoint,
            attack_path=finding.attack_path,
            signals=finding.static_evidence,
            candidate_tests=[finding.category.lower()],
            executed_tests=[
                {
                    "test": finding.category.lower(),
                    "summary": finding.correlation_notes,
                    "status": "confirmed" if finding.confidence.value == "CONFIRMED" else "potential",
                }
            ],
            ground_truth="confirmed" if finding.confidence.value == "CONFIRMED" else "safe",
        )

        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.model_dump()) + "\n")

        return record
