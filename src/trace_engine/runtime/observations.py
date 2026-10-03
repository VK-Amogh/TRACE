"""Runtime test observations and HTTP exchange records."""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class RuntimeObservation(BaseModel):
    """Detailed observation from executing a test request against a target."""
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    latency_ms: float = 0.0
    is_anomaly: bool = False
    observation_notes: List[str] = Field(default_factory=list)
