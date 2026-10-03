"""Deterministic security signal models and static detectors."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from trace_engine.parsing.locations import SourceLocation


class SignalType(str, Enum):
    MISSING_AUTH = "MISSING_AUTH"
    UNTRUSTED_OBJECT_LOOKUP = "UNTRUSTED_OBJECT_LOOKUP"
    PRIVILEGE_MISMATCH = "PRIVILEGE_MISMATCH"
    USER_URL_OUTBOUND = "USER_URL_OUTBOUND"
    DYNAMIC_QUERY_CONSTRUCTION = "DYNAMIC_QUERY_CONSTRUCTION"
    MASS_ASSIGNMENT_SURFACE = "MASS_ASSIGNMENT_SURFACE"


class SecuritySignal(BaseModel):
    """A deterministic indicator of a potential vulnerability path in source code."""
    id: str
    signal_type: SignalType
    endpoint_id: str
    title: str
    description: str
    severity_potential: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    source: SourceLocation
    evidence_snippet: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
