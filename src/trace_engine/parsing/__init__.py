"""Code parsing and symbol extraction module."""

from trace_engine.parsing.locations import SourceLocation
from trace_engine.parsing.symbols import (
    ParameterSymbol,
    DecoratorSymbol,
    FunctionSymbol,
    ClassSymbol,
    ImportSymbol,
)
from trace_engine.parsing.calls import CallSymbol
from trace_engine.parsing.parser import ParsedFile, CodeParser
from trace_engine.parsing.language import get_tree_sitter_parser

__all__ = [
    "SourceLocation",
    "ParameterSymbol",
    "DecoratorSymbol",
    "FunctionSymbol",
    "ClassSymbol",
    "ImportSymbol",
    "CallSymbol",
    "ParsedFile",
    "CodeParser",
    "get_tree_sitter_parser",
]
