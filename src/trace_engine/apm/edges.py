"""Edge definitions for the Attack-Path Model (APM)."""

from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    EXPOSES = "EXPOSES"
    RECEIVES = "RECEIVES"
    ROUTES_TO = "ROUTES_TO"
    CALLS = "CALLS"
    PROTECTS = "PROTECTS"
    ACCESSES = "ACCESSES"
    SINKS_TO = "SINKS_TO"
    CONNECTS_TO = "CONNECTS_TO"


class APMEdge(BaseModel):
    """Directed edge between two APM nodes."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: Dict[str, Any] = Field(default_factory=dict)
