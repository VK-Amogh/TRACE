"""Call graph edge representation extracted from AST."""

from typing import List, Optional
from pydantic import BaseModel, Field
from trace_engine.parsing.locations import SourceLocation


class CallSymbol(BaseModel):
    """Represents a function call within a function body."""
    caller_name: str
    callee_name: str
    arguments: List[str] = Field(default_factory=list)
    location: SourceLocation
    is_await: bool = False
