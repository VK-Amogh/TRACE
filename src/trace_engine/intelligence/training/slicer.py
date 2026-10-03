"""AST & Dataflow-Aware Code Slicer with Canonical Identifier Renaming."""

import ast
import re
from typing import List, Dict, Tuple, Optional, Set


class CanonicalRenamer(ast.NodeTransformer):
    """AST transformer that normalizes variable and function names into canonical tokens (VAR_1, FUNC_1)."""

    def __init__(self, preserve_builtins: bool = True):
        super().__init__()
        self.var_map: Dict[str, str] = {}
        self.func_map: Dict[str, str] = {}
        self.var_idx = 1
        self.func_idx = 1
        self.preserve_builtins = preserve_builtins
        self.builtins = {
            "open", "print", "len", "range", "str", "int", "float", "list", "dict",
            "set", "tuple", "min", "max", "sum", "abs", "round", "input", "eval", "exec"
        }

    def visit_Name(self, node: ast.Name) -> ast.Name:
        name = node.id
        if self.preserve_builtins and name in self.builtins:
            return node
        if name.startswith(("request", "req", "db", "cursor", "session", "user", "auth", "token")):
            # Preserve critical security semantic identifiers
            return node

        if isinstance(node.ctx, (ast.Store, ast.Param)):
            if name not in self.var_map:
                self.var_map[name] = f"VAR_{self.var_idx}"
                self.var_idx += 1
        if name in self.var_map:
            node.id = self.var_map[name]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if not node.name.startswith("__"):
            if node.name not in self.func_map:
                self.func_map[node.name] = f"FUNC_{self.func_idx}"
                self.func_idx += 1
            node.name = self.func_map[node.name]
        self.generic_visit(node)
        return node


class DataflowSliceExtractor:
    """Extracts normalized dataflow traces: [SOURCE: ...] -> [FLOW: ...] -> [SINK: ...]"""

    SOURCE_PATTERNS = [
        r"\brequest\.(args|params|query|body|json|headers|form|get_json)",
        r"\breq\.(params|query|body|headers)",
        r"\b(user_input|client_data|query_val|target_url|filename)\b",
    ]

    SINK_PATTERNS = [
        r"\b(cursor|db|connection|session)\.(execute|raw|query)\b",
        r"\b(os\.system|subprocess\.\w+|\beval\b|\bexec\b|\bpopen\b)",
        r"\b(open|readfile|sendfile|send_file|writefile)\b",
        r"\b(render_template_string|nunjucks\.renderString|Environment\.from_string)\b",
        r"\b(pickle\.loads|yaml\.load|unserialize)\b",
        r"\b(httpx\.(get|post)|requests\.(get|post)|fetch|axios\.\w+)\b",
    ]

    def extract_trace(self, code_snippet: str) -> str:
        """Parses snippet and generates high-signal dataflow trace."""
        lines = code_snippet.strip().splitlines()
        sources: List[str] = []
        flows: List[str] = []
        sinks: List[str] = []

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith(("#", "//", "/*", "*", "def ", "function ", "class ", "import ", "from ")):
                continue

            # Check for source
            if any(re.search(pat, line_str, re.IGNORECASE) for pat in self.SOURCE_PATTERNS):
                sources.append(line_str)
            # Check for sink
            elif any(re.search(pat, line_str, re.IGNORECASE) for pat in self.SINK_PATTERNS):
                sinks.append(line_str)
            # Intermediate assignment / data manipulation
            elif "=" in line_str:
                flows.append(line_str)

        trace_elements: List[str] = []
        for s in sources[:2]:
            trace_elements.append(f"[SOURCE: {s}]")
        for f in flows[:3]:
            trace_elements.append(f"[FLOW: {f}]")
        for k in sinks[:2]:
            trace_elements.append(f"[SINK: {k}]")

        if trace_elements:
            return " -> ".join(trace_elements)

        # Fallback to canonical AST normalization
        return self.canonicalize_code(code_snippet)

    def canonicalize_code(self, code_snippet: str) -> str:
        """Parses code into AST, renames identifiers to VAR_n/FUNC_n, and unparses to string."""
        try:
            tree = ast.parse(code_snippet)
            renamer = CanonicalRenamer()
            transformed = renamer.visit(tree)
            ast.fix_missing_locations(transformed)
            return ast.unparse(transformed)
        except Exception:
            # If snippet is not a complete Python AST (e.g. JS/Kotlin), apply regex canonicalization
            normalized = code_snippet
            var_candidates = re.findall(r"\b([a-z_][a-zA-Z0-9_]{3,})\b", normalized)
            preserved = {"request", "params", "query", "body", "return", "const", "function", "class", "async", "await", "import", "from"}
            idx = 1
            for var in set(var_candidates):
                if var not in preserved:
                    normalized = re.sub(rf"\b{var}\b", f"VAR_{idx}", normalized)
                    idx += 1
            return normalized


default_slicer = DataflowSliceExtractor()


def slice_and_canonicalize(code_snippet: str) -> str:
    """Convenience helper to extract dataflow trace and canonicalize code."""
    return default_slicer.extract_trace(code_snippet)
