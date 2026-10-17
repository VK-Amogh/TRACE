"""Baseline diff and the CI exit gate.

``diff_findings`` classifies a scan against a previous one by fingerprint
(stable across line drift and ID renumbering). ``gate`` decides whether a run
should fail a pipeline.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from trace_engine.findings.model import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    Finding,
)


class BaselineDiff(BaseModel):
    new: List[Finding] = Field(default_factory=list)
    persisted: List[Finding] = Field(default_factory=list)
    resolved: List[Finding] = Field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        return {"new": len(self.new), "persisted": len(self.persisted), "resolved": len(self.resolved)}


def load_baseline(path: Path) -> List[Finding]:
    """Load findings from a JSON file (a list, or an object with ``findings``)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings", [])
    return [Finding.model_validate(item) for item in data]


def diff_findings(current: List[Finding], baseline: List[Finding]) -> BaselineDiff:
    base = {f.fingerprint: f for f in baseline}
    cur = {f.fingerprint: f for f in current}
    return BaselineDiff(
        new=[f for f in current if f.fingerprint not in base],
        persisted=[f for f in current if f.fingerprint in base],
        resolved=[f for f in baseline if f.fingerprint not in cur],
    )


def _rank(order: List[str], value) -> int:
    key = str(getattr(value, "value", value)).upper()
    return order.index(key) if key in order else -1


def blocking_findings(
    findings: List[Finding],
    fail_on: Optional[str],
    *,
    min_confidence: str = "MEDIUM",
    include_fixtures: bool = False,
) -> List[Finding]:
    """Findings at/above ``fail_on`` severity and ``min_confidence`` confidence."""
    if not fail_on:
        return []
    floor = _rank(SEVERITY_ORDER, fail_on)
    if floor < 0:
        raise ValueError(f"unknown severity '{fail_on}' (choose: {', '.join(SEVERITY_ORDER)})")
    conf_floor = _rank(CONFIDENCE_ORDER, min_confidence)
    if conf_floor < 0:
        raise ValueError(f"unknown confidence '{min_confidence}' (choose: {', '.join(CONFIDENCE_ORDER)})")
    return [
        f
        for f in findings
        if _rank(SEVERITY_ORDER, f.severity) >= floor
        and _rank(CONFIDENCE_ORDER, f.confidence) >= conf_floor
        and (include_fixtures or not f.is_fixture)
    ]
