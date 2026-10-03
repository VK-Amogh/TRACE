"""Correlated security finding schema."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
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
