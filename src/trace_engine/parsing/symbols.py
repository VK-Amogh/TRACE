"""Symbol definitions extracted from AST parsing."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from trace_engine.parsing.locations import SourceLocation


class ParameterSymbol(BaseModel):
    name: str
    type_annotation: Optional[str] = None
    default_value: Optional[str] = None
    location: SourceLocation


class DecoratorSymbol(BaseModel):
    name: str
    arguments: List[str] = Field(default_factory=list)
    raw_text: str
    location: SourceLocation


class FunctionSymbol(BaseModel):
    name: str
    qualified_name: str
    parameters: List[ParameterSymbol] = Field(default_factory=list)
    decorators: List[DecoratorSymbol] = Field(default_factory=list)
    docstring: Optional[str] = None
    is_async: bool = False
    return_type: Optional[str] = None
    location: SourceLocation
    body_text: Optional[str] = None


class ClassSymbol(BaseModel):
    name: str
    base_classes: List[str] = Field(default_factory=list)
    methods: List[FunctionSymbol] = Field(default_factory=list)
    location: SourceLocation


class ImportSymbol(BaseModel):
    module: str
    imported_names: List[str] = Field(default_factory=list)
    alias: Optional[str] = None
    location: SourceLocation
