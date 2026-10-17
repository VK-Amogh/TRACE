"""Normalized API endpoint models and framework adapter base class."""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from trace_engine.parsing.locations import SourceLocation
from trace_engine.parsing.parser import ParsedFile


class EndpointParameter(BaseModel):
    name: str
    location: str = "query"  # "path", "query", "body", "header"
    param_type: Optional[str] = "string"
    required: bool = True
    user_controlled: bool = True


class Endpoint(BaseModel):
    """Normalized API endpoint representation according to TRACE specification."""
    id: str
    method: str
    path: str
    handler_name: str
    auth_required: bool = False
    roles: List[str] = Field(default_factory=list)
    parameters: List[EndpointParameter] = Field(default_factory=list)
    database_access: bool = False
    object_identifier: bool = False
    state_changing: bool = False
    external_network: bool = False
    sensitive_data: bool = False
    source: SourceLocation
    # Route-establishment confidence. ``registered=True`` means the endpoint
    # comes from an actual route registration (decorator, URL pattern, router
    # call). ``registered=False`` marks inferred/low-confidence inventory
    # (e.g. a decorated function with no route registration) that must not
    # produce vulnerability findings on its own.
    registered: bool = True
    confidence: str = "high"  # "high" | "medium" | "low"

    def display_name(self) -> str:
        return f"{self.method.upper()} {self.path}"


class FrameworkAdapter(ABC):
    """Abstract adapter for extracting endpoints from parsed ASTs."""

    @abstractmethod
    def can_handle(self, parsed_file: ParsedFile) -> bool:
        """Determines if this adapter applies to the given file."""
        pass

    @abstractmethod
    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        """Extracts normalized endpoints from the file."""
        pass
