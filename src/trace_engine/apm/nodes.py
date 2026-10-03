"""Node definitions for the Attack-Path Model (APM)."""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from trace_engine.parsing.locations import SourceLocation


class NodeType(str, Enum):
    REPOSITORY = "Repository"
    FILE = "File"
    ENDPOINT = "Endpoint"
    FUNCTION = "Function"
    PARAMETER = "Parameter"
    AUTH_CHECK = "AuthCheck"
    DATABASE = "Database"
    SINK = "Sink"
    EXTERNAL_SERVICE = "ExternalService"


class APMNode(BaseModel):
    """Base node in the Attack-Path Model graph."""
    id: str
    node_type: NodeType
    label: str
    location: Optional[SourceLocation] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
