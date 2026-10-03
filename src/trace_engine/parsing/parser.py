"""Unified code parser for Python, JavaScript, and TypeScript."""

import ast
import re
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from trace_engine.parsing.locations import SourceLocation
from trace_engine.parsing.symbols import (
    FunctionSymbol,
    ClassSymbol,
    ImportSymbol,
    ParameterSymbol,
    DecoratorSymbol,
)
from trace_engine.parsing.calls import CallSymbol
from trace_engine.parsing.language import get_tree_sitter_parser


class ParsedFile(BaseModel):
    """Result of parsing a source file."""
    file_path: str
    language: str
    imports: List[ImportSymbol] = Field(default_factory=list)
    classes: List[ClassSymbol] = Field(default_factory=list)
    functions: List[FunctionSymbol] = Field(default_factory=list)
    calls: List[CallSymbol] = Field(default_factory=list)


class CodeParser:
    """Parses source files into structured AST symbols and calls."""

    def parse(self, file_path: str, content: str, language: str) -> ParsedFile:
        if language == "python":
            return self._parse_python(file_path, content)
        elif language in ("javascript", "typescript"):
            return self._parse_js_ts(file_path, content, language)
        else:
            return ParsedFile(file_path=file_path, language=language)

    def _parse_python(self, file_path: str, content: str) -> ParsedFile:
        parsed = ParsedFile(file_path=file_path, language="python")
        try:
            tree = ast.parse(content, filename=file_path)
        except Exception:
            return parsed

        lines = content.splitlines()

        for node in ast.walk(tree):
            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parsed.imports.append(
                        ImportSymbol(
                            module=alias.name,
                            alias=alias.asname,
                            location=SourceLocation(
                                file=file_path,
                                line_start=node.lineno,
                                line_end=node.end_lineno or node.lineno,
                            ),
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = [alias.name for alias in node.names]
                parsed.imports.append(
                    ImportSymbol(
                        module=module,
                        imported_names=names,
                        location=SourceLocation(
                            file=file_path,
                            line_start=node.lineno,
                            line_end=node.end_lineno or node.lineno,
                        ),
                    )
                )

        # Classes and Top-level/Class Functions
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                cls_symbol = self._extract_python_class(node, file_path, lines)
                parsed.classes.append(cls_symbol)
                for method in cls_symbol.methods:
                    parsed.functions.append(method)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_symbol = self._extract_python_function(node, file_path, lines)
                parsed.functions.append(fn_symbol)

        # Extract calls inside functions
        for fn in parsed.functions:
            fn_calls = self._extract_python_calls_from_text(fn, lines, file_path)
            parsed.calls.extend(fn_calls)

        return parsed

    def _extract_python_class(
        self, node: ast.ClassDef, file_path: str, lines: List[str]
    ) -> ClassSymbol:
        bases = []
        for b in node.bases:
            if isinstance(b, ast.Name):
                bases.append(b.id)
            elif isinstance(b, ast.Attribute):
                bases.append(f"{ast.unparse(b)}")

        methods: List[FunctionSymbol] = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(
                    self._extract_python_function(
                        item, file_path, lines, parent_class=node.name
                    )
                )

        return ClassSymbol(
            name=node.name,
            base_classes=bases,
            methods=methods,
            location=SourceLocation(
                file=file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
            ),
        )

    def _extract_python_function(
        self,
        node: ast.AST,
        file_path: str,
        lines: List[str],
        parent_class: Optional[str] = None,
    ) -> FunctionSymbol:
        is_async = isinstance(node, ast.AsyncFunctionDef)
        name = getattr(node, "name", "unknown")
        qualified_name = f"{parent_class}.{name}" if parent_class else name

        # Parameters
        params: List[ParameterSymbol] = []
        args_node = getattr(node, "args", None)
        if args_node:
            for arg in args_node.args:
                type_ann = ast.unparse(arg.annotation) if arg.annotation else None
                params.append(
                    ParameterSymbol(
                        name=arg.arg,
                        type_annotation=type_ann,
                        location=SourceLocation(
                            file=file_path,
                            line_start=arg.lineno,
                            line_end=arg.end_lineno or arg.lineno,
                        ),
                    )
                )

        # Decorators
        decorators: List[DecoratorSymbol] = []
        for dec in getattr(node, "decorator_list", []):
            try:
                dec_text = ast.unparse(dec)
            except Exception:
                dec_text = ""
            dec_name = dec_text.split("(")[0].strip()
            args = []
            if isinstance(dec, ast.Call):
                args = [ast.unparse(a) for a in dec.args]
            decorators.append(
                DecoratorSymbol(
                    name=dec_name,
                    arguments=args,
                    raw_text=dec_text,
                    location=SourceLocation(
                        file=file_path,
                        line_start=dec.lineno,
                        line_end=dec.end_lineno or dec.lineno,
                    ),
                )
            )

        # Body snippet
        line_start = node.lineno
        line_end = node.end_lineno or line_start
        body_lines = lines[line_start - 1 : line_end]
        body_text = "\n".join(body_lines)

        return FunctionSymbol(
            name=name,
            qualified_name=qualified_name,
            parameters=params,
            decorators=decorators,
            is_async=is_async,
            location=SourceLocation(
                file=file_path,
                line_start=line_start,
                line_end=line_end,
            ),
            body_text=body_text,
        )

    def _extract_python_calls_from_text(
        self, fn: FunctionSymbol, lines: List[str], file_path: str
    ) -> List[CallSymbol]:
        calls: List[CallSymbol] = []
        if not fn.body_text:
            return calls

        # Match function calls e.g. db.query(...), requests.get(...), auth.check(...)
        pattern = re.compile(r"([a-zA-Z0-9_\.]+)\s*\((.*?)\)", re.DOTALL)
        for match in pattern.finditer(fn.body_text):
            callee = match.group(1)
            # Filter language keywords
            if callee in ("def", "class", "if", "for", "while", "return", "print"):
                continue
            args = [a.strip() for a in match.group(2).split(",") if a.strip()]
            calls.append(
                CallSymbol(
                    caller_name=fn.qualified_name,
                    callee_name=callee,
                    arguments=args[:5],  # store first 5 args
                    location=fn.location,
                )
            )
        return calls

    def _parse_js_ts(self, file_path: str, content: str, language: str) -> ParsedFile:
        parsed = ParsedFile(file_path=file_path, language=language)
        lines = content.splitlines()

        # Extract Imports: import ... from '...'; or require('...')
        import_pat = re.compile(
            r"""(?:import\s+.*?from\s+['"](.*?)['"]|require\s*\(\s*['"](.*?)['"]\s*\))"""
        )
        for idx, line in enumerate(lines, 1):
            for match in import_pat.finditer(line):
                mod = match.group(1) or match.group(2)
                if mod:
                    parsed.imports.append(
                        ImportSymbol(
                            module=mod,
                            location=SourceLocation(
                                file=file_path, line_start=idx, line_end=idx
                            ),
                        )
                    )

        # Extract Functions & Express routes
        # e.g. function name(...) or const name = (...) => or router.get('/path', ...)
        fn_pat = re.compile(
            r"""(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\((.*?)\)"""
        )
        for idx, line in enumerate(lines, 1):
            for match in fn_pat.finditer(line):
                name = match.group(1)
                args = [a.strip() for a in match.group(2).split(",") if a.strip()]
                params = [
                    ParameterSymbol(
                        name=arg,
                        location=SourceLocation(
                            file=file_path, line_start=idx, line_end=idx
                        ),
                    )
                    for arg in args
                ]
                parsed.functions.append(
                    FunctionSymbol(
                        name=name,
                        qualified_name=name,
                        parameters=params,
                        location=SourceLocation(
                            file=file_path, line_start=idx, line_end=idx
                        ),
                    )
                )

        return parsed
