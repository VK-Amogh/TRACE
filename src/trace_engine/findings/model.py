"""Correlated security finding schema."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator
from trace_engine.parsing.locations import SourceLocation
from trace_engine.runtime.observations import RuntimeObservation


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    POTENTIAL = "POTENTIAL"


SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["POTENTIAL", "MEDIUM", "HIGH", "CONFIRMED"]


class Finding(BaseModel):
    """Correlated vulnerability finding supported by both static AST and runtime proof."""
    id: str
    title: str
    category: str
    severity: Severity
    confidence: FindingConfidence
    endpoint: str
    source_location: Optional[SourceLocation] = None
    attack_path: List[str] = Field(default_factory=list)
    static_evidence: List[str] = Field(default_factory=list)
    runtime_evidence: List[str] = Field(default_factory=list)
    correlation_notes: str
    remediation: str
    reproduction_steps: List[str] = Field(default_factory=list)
    observations: List[RuntimeObservation] = Field(default_factory=list)
    root_cause: Optional[str] = None
    short_action: Optional[str] = None
    provenance: str = "application"
    is_fixture: bool = False
    # Derived identity and ranking (filled automatically when left empty).
    fingerprint: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    priority_score: int = 0
    priority_tier: str = ""
    score_factors: Dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _derive_fields(self) -> "Finding":
        from trace_engine.findings.fingerprint import compute_fingerprint
        from trace_engine.findings.scoring import score_finding
        from trace_engine.findings.taxonomy import lookup

        if not self.fingerprint:
            file = self.source_location.file if self.source_location else ""
            self.fingerprint = compute_fingerprint(self.category, self.endpoint, file, self.title)
        if not self.cwe or not self.owasp:
            cwe, owasp = lookup(self.category, self.title)
            self.cwe = self.cwe or cwe
            self.owasp = self.owasp or owasp
        if not self.score_factors:
            score, factors, tier = score_finding(
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                title=self.title,
                attack_path=self.attack_path,
                static_evidence=self.static_evidence,
                runtime_evidence=self.runtime_evidence,
                is_fixture=self.is_fixture,
            )
            self.priority_score, self.score_factors, self.priority_tier = score, factors, tier
        return self
