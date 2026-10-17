"""Intra-procedural taint analysis for request handlers.

Answers one question per dangerous call: does request-controlled data reach
the dangerous *argument* of this sink inside the same function, without a
sanitizer or validating guard on the way?

Scope and limits (precision first; findings are evidence, not proof):

- Python is analyzed with the ``ast`` module; JavaScript/TypeScript with a
  brace-aware, line-oriented tracker. Other languages are not analyzed.
- Taint follows assignments, f-strings, concatenation, ``%`` and ``.format``
  inside one function. It does not follow values into helper functions: a
  helper's own parameters are *unknown*, never assumed attacker-controlled.
- Only the dangerous argument counts (the query, not the bound parameters; the
  URL, not the JSON body). A URL whose literal prefix pins scheme and host is
  not SSRF.
- Branches are not distinguished. A guard (``if not x.isdigit(): abort()``)
  cleans the variable afterwards, and a positive guard cleans it inside.
"""

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class TaintFlow(BaseModel):
    function: str
    kind: str  # sql | command | code | ssrf | path | deserialization | ssti | redirect
    sink: str
    sink_line: int
    source_line: int
    source: str
    trail: List[str] = Field(default_factory=list)
    region_start: int = 0
    region_end: int = 0


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_REQUEST_ROOTS = {"request", "req"}
_REQUEST_ATTRS = {
    "args", "form", "json", "values", "cookies", "headers", "data", "files", "GET", "POST",
    "body", "query_params", "path_params", "COOKIES", "META", "query", "params",
}
_REQUEST_CALLS = {"get_json", "json", "body", "form", "stream", "get_data"}
_IGNORED_PARAMS = {
    "self", "cls", "request", "req", "response", "res", "db", "session", "conn", "connection",
    "cursor", "user", "current_user", "background_tasks", "background", "settings", "config",
    "logger", "ctx", "context", "next", "args", "kwargs",
}
_SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "uuid.UUID", "UUID", "secure_filename",
    "shlex.quote", "quote", "escape", "html.escape", "markupsafe.escape", "os.path.basename",
    "basename", "bleach.clean", "ipaddress.ip_address", "Decimal", "datetime.fromisoformat",
}
_VALIDATED_TYPES = {"int", "float", "bool", "UUID", "Decimal", "date", "datetime"}
_GUARD_METHODS = {"isdigit", "isalnum", "isnumeric", "isidentifier", "isalpha", "isdecimal"}
_GUARD_FUNCS = {"fullmatch", "match", "isinstance", "ip_address", "UUID", "is_valid", "validate"}
_PATH_GUARDS = ("is_relative_to(", "commonpath(", "realpath(", ".relative_to(", "secure_filename(")

_SQL_METHODS = {"execute", "executemany", "executescript", "raw", "exec_driver_sql"}
_SQL_FUNCS = {"text"}
_COMMAND_FUNCS = {"os.system", "os.popen", "commands.getoutput"}
_SUBPROCESS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
}
_CODE_FUNCS = {"eval", "exec"}
_SSRF_FUNCS = {
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.head",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch", "httpx.head",
    "urllib.request.urlopen", "urlopen", "urllib2.urlopen",
}
_SSRF_ARG1 = {"requests.request", "httpx.request"}
_PATH_FUNCS = {"open", "send_file", "FileResponse", "os.remove", "os.unlink", "shutil.copy", "shutil.rmtree"}
_PATH_ARG1 = {"send_from_directory"}
_DESER_FUNCS = {"pickle.loads", "pickle.load", "marshal.loads", "jsonpickle.decode", "dill.loads", "shelve.open"}
_SSTI_FUNCS = {"render_template_string", "Template", "jinja2.Template", "Environment.from_string"}
_REDIRECT_FUNCS = {"redirect", "RedirectResponse", "HttpResponseRedirect", "flask.redirect"}


def _dotted(node: ast.AST) -> str:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        return (inner + "()." + ".".join(reversed(parts))) if parts else inner + "()"
    return ".".join(reversed(parts))


class _Taint:
    __slots__ = ("line", "desc", "trail")

    def __init__(self, line: int, desc: str, trail: Tuple[str, ...] = ()):
        self.line, self.desc, self.trail = line, desc, trail

    def via(self, name: str) -> "_Taint":
        return _Taint(self.line, self.desc, self.trail + (name,))


class _PyFunction:
    """Taint state and sink search for one function body."""

    def __init__(self, fn: ast.AST, source_lines: List[str], params_tainted: bool, is_method_handler: bool):
        self.fn = fn
        self.name = getattr(fn, "name", "<lambda>")
        self.tainted: Dict[str, _Taint] = {}
        self.clean_guard: Set[str] = set()
        self.flows: List[TaintFlow] = []
        end = getattr(fn, "end_lineno", None) or getattr(fn, "lineno", 0)
        body_text = "\n".join(source_lines[getattr(fn, "lineno", 1) - 1 : end])
        self.has_path_guard = any(g in body_text for g in _PATH_GUARDS)
        if params_tainted:
            args = fn.args  # type: ignore[attr-defined]
            names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
            defaults = {}
            pos = args.posonlyargs + args.args
            for a, d in zip(reversed(pos), reversed(args.defaults)):
                defaults[a.arg] = d
            for a, d in zip(args.kwonlyargs, args.kw_defaults):
                if d is not None:
                    defaults[a.arg] = d
            annotations = {a.arg: a.annotation for a in pos + args.kwonlyargs}
            for name in names:
                if name in _IGNORED_PARAMS or name.startswith("_"):
                    continue
                ann = annotations.get(name)
                if isinstance(ann, ast.Name) and ann.id in _VALIDATED_TYPES:
                    continue
                d = defaults.get(name)
                if d is not None and isinstance(d, ast.Call) and _dotted(d.func).endswith("Depends"):
                    continue
                self.tainted[name] = _Taint(fn.lineno, f"parameter '{name}'", ())  # type: ignore[attr-defined]

    # -- expression taint -------------------------------------------------
    def expr_taint(self, node: Optional[ast.AST]) -> Optional[_Taint]:
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            if node.id in self.clean_guard:
                return None
            t = self.tainted.get(node.id)
            return t.via(node.id) if t else None
        src = self._request_source(node)
        if src:
            return src
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in _SANITIZERS or name.split(".")[-1] in {"secure_filename", "basename", "quote", "escape"}:
                return None
            # method call on a tainted receiver propagates (x.strip(), x.format(..))
            if isinstance(node.func, ast.Attribute):
                t = self.expr_taint(node.func.value)
                if t:
                    return t
            for a in list(node.args) + [k.value for k in node.keywords]:
                t = self.expr_taint(a)
                if t:
                    return t
            return None
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self.expr_taint(v.value)
                    if t:
                        return t
            return None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.expr_context, ast.operator, ast.cmpop, ast.boolop, ast.unaryop)):
                continue
            t = self.expr_taint(child)
            if t:
                return t
        return None

    def _request_source(self, node: ast.AST) -> Optional[_Taint]:
        """``request.args.get('q')``, ``request.json['x']``, ``await request.json()``."""
        cur = node
        if isinstance(cur, ast.Await):
            cur = cur.value
        chain: List[str] = []
        while True:
            if isinstance(cur, ast.Call):
                cur = cur.func
            elif isinstance(cur, ast.Subscript):
                cur = cur.value
            elif isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            else:
                break
        if isinstance(cur, ast.Name) and cur.id in _REQUEST_ROOTS and chain:
            first = chain[-1]
            if first in _REQUEST_ATTRS or first in _REQUEST_CALLS:
                return _Taint(getattr(node, "lineno", 0), f"{cur.id}.{'.'.join(reversed(chain))}", ())
        return None

    # -- guards -------------------------------------------------------------
    def _guard_names(self, test: ast.AST) -> Tuple[Set[str], bool]:
        """Names validated by ``test`` and whether the test is the *negative* form."""
        names: Set[str] = set()
        negative = False
        node = test
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            negative, node = True, node.operand
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fname = _dotted(sub.func)
                last = fname.split(".")[-1]
                if last in _GUARD_METHODS and isinstance(sub.func, ast.Attribute):
                    if isinstance(sub.func.value, ast.Name):
                        names.add(sub.func.value.id)
                elif last in _GUARD_FUNCS:
                    for a in sub.args:
                        if isinstance(a, ast.Name):
                            names.add(a.id)
            elif isinstance(sub, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops):
                if isinstance(sub.left, ast.Name):
                    names.add(sub.left.id)
                    if any(isinstance(op, ast.NotIn) for op in sub.ops):
                        negative = True
        return names, negative

    @staticmethod
    def _terminates(body: List[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            return _dotted(last.value.func).split(".")[-1] in {"abort", "exit", "fail"}
        return False

    # -- statements ---------------------------------------------------------
    def run(self) -> List[TaintFlow]:
        self._block(self.fn.body)  # type: ignore[attr-defined]
        return self.flows

    def _assign(self, target: ast.AST, taint: Optional[_Taint]) -> None:
        if isinstance(target, ast.Name):
            if taint:
                self.tainted[target.id] = taint
                self.clean_guard.discard(target.id)
            else:
                self.tainted.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, taint)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, taint)

    def _block(self, stmts: List[ast.stmt]) -> None:
        for stmt in stmts:
            self._stmt(stmt)

    def _stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # nested scopes are analyzed on their own
        if isinstance(stmt, ast.Assign):
            self._scan_calls(stmt.value)
            t = self.expr_taint(stmt.value)
            for target in stmt.targets:
                self._assign(target, t)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._scan_calls(stmt.value)
                self._assign(stmt.target, self.expr_taint(stmt.value))
        elif isinstance(stmt, ast.AugAssign):
            self._scan_calls(stmt.value)
            t = self.expr_taint(stmt.value) or (self.expr_taint(stmt.target) if isinstance(stmt.target, ast.Name) else None)
            if t:
                self._assign(stmt.target, t)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._scan_calls(stmt.iter)
            self._assign(stmt.target, self.expr_taint(stmt.iter))
            self._block(stmt.body)
            self._block(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self._scan_calls(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, self.expr_taint(item.context_expr))
            self._block(stmt.body)
        elif isinstance(stmt, ast.If):
            self._scan_calls(stmt.test)
            names, negative = self._guard_names(stmt.test)
            if names and negative and self._terminates(stmt.body):
                self._block(stmt.body)
                self.clean_guard |= names
                self._block(stmt.orelse)
            elif names and not negative:
                before = set(self.clean_guard)
                self.clean_guard |= names
                self._block(stmt.body)
                self.clean_guard = before
                self._block(stmt.orelse)
            else:
                self._block(stmt.body)
                self._block(stmt.orelse)
        elif isinstance(stmt, ast.Try):
            self._block(stmt.body)
            for handler in stmt.handlers:
                self._block(handler.body)
            self._block(stmt.orelse)
            self._block(stmt.finalbody)
        elif isinstance(stmt, (ast.While,)):
            self._scan_calls(stmt.test)
            self._block(stmt.body)
            self._block(stmt.orelse)
        elif isinstance(stmt, (ast.Return, ast.Expr)) and getattr(stmt, "value", None) is not None:
            self._scan_calls(stmt.value)  # type: ignore[arg-type]

    # -- sinks ----------------------------------------------------------------
    def _scan_calls(self, expr: ast.AST) -> None:
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                self._check_sink(node)

    def _pinned_host(self, arg: ast.AST) -> bool:
        """Literal prefix pins scheme+host: ``f"https://api.example.com/{id}"``."""
        head: Optional[str] = None
        if isinstance(arg, ast.JoinedStr) and arg.values and isinstance(arg.values[0], ast.Constant):
            head = str(arg.values[0].value)
        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            left = arg.left
            while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
                left = left.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                head = left.value
        return bool(head and re.match(r"^https?://[A-Za-z0-9.-]+(?::\d+)?/", head))

    def _check_sink(self, call: ast.Call) -> None:
        name = _dotted(call.func)
        last = name.split(".")[-1]
        kind: Optional[str] = None
        arg_index = 0
        if last in _SQL_METHODS and isinstance(call.func, ast.Attribute):
            kind = "sql"
        elif name in _SQL_FUNCS and call.args:
            kind = "sql"
        elif name in _COMMAND_FUNCS:
            kind = "command"
        elif name in _SUBPROCESS:
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords)
            if shell:
                kind = "command"
        elif name in _CODE_FUNCS:
            kind = "code"
        elif name in _SSRF_FUNCS:
            kind = "ssrf"
        elif name in _SSRF_ARG1:
            kind, arg_index = "ssrf", 1
        elif name in _PATH_FUNCS:
            kind = "path"
        elif name in _PATH_ARG1:
            kind, arg_index = "path", 1
        elif name in _DESER_FUNCS:
            kind = "deserialization"
        elif name == "yaml.load":
            loader = next((k.value for k in call.keywords if k.arg == "Loader"), None)
            if loader is None or "Safe" not in _dotted(loader):
                kind = "deserialization"
        elif name in _SSTI_FUNCS or last == "render_template_string":
            kind = "ssti"
        elif name in _REDIRECT_FUNCS or last == "redirect":
            kind = "redirect"
        if kind is None or len(call.args) <= arg_index:
            return
        arg = call.args[arg_index]
        if kind == "path" and self.has_path_guard:
            return
        if kind == "ssrf" and self._pinned_host(arg):
            return
        taint = self.expr_taint(arg)
        if not taint:
            return
        self.flows.append(
            TaintFlow(
                function=self.name,
                kind=kind,
                sink=name or last,
                sink_line=getattr(call, "lineno", 0),
                source_line=taint.line,
                source=taint.desc,
                trail=list(taint.trail),
                region_start=getattr(self.fn, "lineno", 0),
                region_end=getattr(self.fn, "end_lineno", 0) or 0,
            )
        )


def _is_handler(fn: ast.AST, in_class: bool) -> bool:
    args = fn.args  # type: ignore[attr-defined]
    first = (args.posonlyargs + args.args)[:2]
    names = [a.arg for a in first]
    if getattr(fn, "decorator_list", None):
        return True
    if names[:1] in (["request"], ["req"]):
        return True
    if in_class and names[:1] == ["self"] and names[1:2] in (["request"], ["req"]):
        return True
    return False


def analyze_python(source: str) -> List[TaintFlow]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    lines = source.splitlines()
    flows: List[TaintFlow] = []

    def visit(node: ast.AST, in_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                handler = _is_handler(child, in_class)
                flows.extend(_PyFunction(child, lines, handler, in_class).run())
                visit(child, False)
            elif isinstance(child, ast.ClassDef):
                visit(child, True)
            else:
                visit(child, in_class)

    visit(tree, False)
    # de-duplicate (same sink line/kind reached via several walks)
    seen: Set[Tuple[str, int, str]] = set()
    unique: List[TaintFlow] = []
    for f in flows:
        key = (f.function, f.sink_line, f.kind)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# JavaScript / TypeScript (brace-aware, line-oriented)
# ---------------------------------------------------------------------------

_JS_HANDLER_RE = re.compile(
    r"\(\s*(?:async\s+)?\(?\s*(?:req|request)\b[^)]*\)\s*(?:=>\s*)?\{|"
    r"\b(?:req|request)\s*,\s*(?:res|reply|response)\b[^)]*\)\s*(?::\s*\w+\s*)?(?:=>\s*)?\{"
)
_JS_SOURCE_RE = re.compile(r"\b(?:req|request)\.(?:query|params|body|headers|cookies)\b")
_JS_DESTRUCT_RE = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)")
_JS_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)")
_JS_REASSIGN_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*\+?=\s*(.+)")
_JS_SANITIZER_RE = re.compile(
    r"^\s*(?:Number|parseInt|parseFloat|Boolean|encodeURIComponent|path\.basename|escape|String\(Number)\("
)
_JS_SINKS = [
    ("sql", re.compile(r"\.(?:query|execute|raw|queryRawUnsafe|\$queryRawUnsafe|\$executeRawUnsafe)\(")),
    ("command", re.compile(r"\b(?:exec|execSync)\(")),
    ("code", re.compile(r"\beval\(|new\s+Function\(")),
    ("ssrf", re.compile(r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|http\.get|https\.get)\(")),
    ("path", re.compile(r"\b(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink)|res\.sendFile|res\.download)\(")),
    ("redirect", re.compile(r"\bres\.redirect\(")),
]


def _strip_comments(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comments but keep string contents (URLs contain ``//``)."""
    out: List[str] = []
    i, n = 0, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = ""
            i += 1
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _match_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _first_arg(text: str, open_paren: int) -> str:
    depth, i, n = 0, open_paren + 1, len(text)
    start = i
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        i += 1
    return text[start:i]


def analyze_js(source: str) -> List[TaintFlow]:
    """Heuristic tracker for Express/Fastify/Next-style handlers."""
    flows: List[TaintFlow] = []
    clean = _strip_comments(source)

    def lines_before(idx: int) -> int:
        return clean.count("\n", 0, idx) + 1

    for m in _JS_HANDLER_RE.finditer(clean):
        open_idx = m.end() - 1
        close_idx = _match_brace(clean, open_idx)
        body = clean[open_idx + 1 : close_idx]
        base_line = lines_before(open_idx + 1)
        region = (lines_before(m.start()), lines_before(close_idx))
        tainted: Dict[str, Tuple[int, str]] = {}

        def is_tainted(expr: str) -> Optional[Tuple[int, str, str]]:
            if _JS_SANITIZER_RE.match(expr):
                return None
            src = _JS_SOURCE_RE.search(expr)
            if src:
                return (0, src.group(0), "")
            for name, (line, desc) in tainted.items():
                if re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", expr):
                    return (line, desc, name)
            return None

        offset = 0
        for rel_line, text in enumerate(body.split("\n")):
            line_no = base_line + rel_line
            stmt_start = open_idx + 1 + offset
            offset += len(text) + 1
            d = _JS_DESTRUCT_RE.search(text)
            if d and is_tainted(d.group(2)):
                t = is_tainted(d.group(2))
                for part in d.group(1).split(","):
                    name = part.split(":")[-1].split("=")[0].strip()
                    if re.match(r"^[A-Za-z_$][\w$]*$", name):
                        tainted[name] = (line_no, t[1])  # type: ignore[index]
            else:
                a = _JS_ASSIGN_RE.search(text) or _JS_REASSIGN_RE.match(text)
                if a:
                    t = is_tainted(a.group(2))
                    if t:
                        tainted[a.group(1)] = (line_no, t[1])
                    elif a.group(1) in tainted and not text.lstrip().startswith(("const", "let", "var")):
                        pass  # reassignment from clean data keeps prior taint (flow-insensitive)
                    else:
                        tainted.pop(a.group(1), None)
            for kind, rx in _JS_SINKS:
                for sm in rx.finditer(text):
                    abs_idx = stmt_start + sm.end() - 1
                    arg = _first_arg(clean, abs_idx)
                    if not arg.strip():
                        continue
                    if kind == "ssrf" and re.match(r"^\s*[`'\"]https?://[A-Za-z0-9.-]+(?::\d+)?/", arg):
                        continue
                    t = is_tainted(arg)
                    if not t:
                        continue
                    flows.append(
                        TaintFlow(
                            function=f"handler@{region[0]}",
                            kind=kind,
                            sink=sm.group(0).rstrip("("),
                            sink_line=line_no,
                            source_line=t[0] or line_no,
                            source=t[1],
                            trail=[t[2]] if t[2] else [],
                            region_start=region[0],
                            region_end=region[1],
                        )
                    )
    seen: Set[Tuple[int, str]] = set()
    unique: List[TaintFlow] = []
    for f in flows:
        key = (f.sink_line, f.kind)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze_source(source: str, language: str) -> List[TaintFlow]:
    """Taint flows for ``source`` (``python``, ``javascript`` or ``typescript``)."""
    if language == "python":
        return analyze_python(source)
    if language in ("javascript", "typescript"):
        return analyze_js(source)
    return []


LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyi": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
}
