"""OpenAPI / Swagger ingestion.

A machine-readable API description gives TRACE routes that code adapters
cannot see (unsupported frameworks, generated routers), real parameter
schemas, declared security requirements, and valid request bodies for
stateful probes. It also enables an inventory check: documented routes missing
from code, and routes in code missing from the documentation.

JSON is always supported; YAML needs PyYAML (``pip install pyyaml``).
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation

SPEC_NAMES = (
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
)
_SPEC_DIRS = ("", "docs", "doc", "api", "spec", "specs", "openapi", "swagger")
_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_URL_PARAM_WORDS = ("url", "uri", "callback", "webhook", "redirect", "endpoint", "target")
_SENSITIVE_WORDS = ("user", "account", "profile", "payment", "billing", "order", "admin", "credential", "token", "secret")


class SpecError(Exception):
    """The API description could not be read or parsed."""


class SpecInfo(BaseModel):
    path: str
    title: str = ""
    endpoints: List[Endpoint] = Field(default_factory=list)
    hints: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)


def find_spec(repo: Path) -> Optional[Path]:
    """First API description in the repository root or a common docs folder."""
    for sub in _SPEC_DIRS:
        base = Path(repo) / sub if sub else Path(repo)
        for name in SPEC_NAMES:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


def load_document(path: Path) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    suffix = Path(path).suffix.lower()
    try:
        if suffix == ".json":
            doc = json.loads(text)
        else:
            try:
                import yaml  # type: ignore
            except ImportError as e:  # pragma: no cover - depends on environment
                raise SpecError(
                    f"{path.name} is YAML but PyYAML is not installed (pip install pyyaml), or supply a JSON spec"
                ) from e
            doc = yaml.safe_load(text)
    except SpecError:
        raise
    except Exception as e:  # noqa: BLE001
        raise SpecError(f"could not parse {path.name}: {e}") from e
    if not isinstance(doc, dict) or not ("paths" in doc or "openapi" in doc or "swagger" in doc):
        raise SpecError(f"{path.name} does not look like an OpenAPI/Swagger document")
    return doc


def _resolve(doc: Dict[str, Any], node: Any, seen: Optional[set] = None) -> Any:
    """Follow local ``$ref`` pointers (cycle-safe)."""
    seen = seen or set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return {}
        seen.add(ref)
        cur: Any = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict) or part not in cur:
                return {}
            cur = cur[part]
        node = cur
    return node


def sample_from_schema(doc: Dict[str, Any], schema: Any, depth: int = 0) -> Any:
    """A schema-valid example value, so probes pass input validation."""
    schema = _resolve(doc, schema)
    if not isinstance(schema, dict) or depth > 5:
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    for key in ("oneOf", "anyOf"):
        if schema.get(key):
            return sample_from_schema(doc, schema[key][0], depth + 1)
    if schema.get("allOf"):
        merged: Dict[str, Any] = {}
        for part in schema["allOf"]:
            value = sample_from_schema(doc, part, depth + 1)
            if isinstance(value, dict):
                merged.update(value)
        return merged
    kind = schema.get("type")
    if kind is None and "properties" in schema:
        kind = "object"
    if kind == "object":
        props = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        names = [n for n in props if n in required] or list(props)[:20]
        return {n: sample_from_schema(doc, props[n], depth + 1) for n in names}
    if kind == "array":
        item = sample_from_schema(doc, schema.get("items", {}), depth + 1)
        return [] if item is None else [item]
    if kind == "integer":
        return int(schema.get("minimum", 1))
    if kind == "number":
        return float(schema.get("minimum", 1))
    if kind == "boolean":
        return True
    if kind == "string":
        fmt = schema.get("format", "")
        by_format = {
            "uuid": "00000000-0000-4000-8000-000000000000",
            "email": "trace@example.com",
            "date": "2026-01-01",
            "date-time": "2026-01-01T00:00:00Z",
            "uri": "http://127.0.0.1/",
            "url": "http://127.0.0.1/",
            "password": "TraceP@ssw0rd!",
        }
        if fmt in by_format:
            return by_format[fmt]
        value = "trace"
        return value.ljust(int(schema.get("minLength", 0)), "x")[: int(schema.get("maxLength", 10_000))]
    return None


def _server_prefix(doc: Dict[str, Any]) -> str:
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        path = urlparse(url).path if "://" in url else url
        if path and path != "/" and "{" not in path:
            return "/" + path.strip("/")
    base = doc.get("basePath")  # Swagger 2
    if isinstance(base, str) and base not in ("", "/"):
        return "/" + base.strip("/")
    return ""


def _requires_auth(doc: Dict[str, Any], operation: Dict[str, Any]) -> bool:
    security = operation.get("security", doc.get("security"))
    if not security:
        return False
    # An empty requirement object ({}) makes authentication optional.
    return all(bool(req) for req in security if isinstance(req, dict))


def _make_id(method: str, path: str) -> str:
    return "ep_openapi_" + re.sub(r"[^A-Za-z0-9]+", "_", f"{method}_{path}").strip("_")


def parse_spec(spec_path: Path, repo_root: Optional[Path] = None) -> SpecInfo:
    doc = load_document(spec_path)
    try:
        rel = str(Path(spec_path).resolve().relative_to(Path(repo_root).resolve())) if repo_root else str(spec_path)
    except ValueError:
        rel = str(spec_path)
    rel = rel.replace("\\", "/")
    info = SpecInfo(path=rel, title=str((doc.get("info") or {}).get("title", "")))
    prefix = _server_prefix(doc)
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        raise SpecError("'paths' is not an object")

    for raw_path, item in paths.items():
        item = _resolve(doc, item)
        if not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            verb = method.upper()
            full_path = prefix + (raw_path if raw_path.startswith("/") else "/" + raw_path)
            params: List[EndpointParameter] = []
            for raw in list(item.get("parameters", []) or []) + list(op.get("parameters", []) or []):
                p = _resolve(doc, raw)
                if not isinstance(p, dict) or "name" not in p:
                    continue
                schema = _resolve(doc, p.get("schema", {})) or {}
                params.append(
                    EndpointParameter(
                        name=str(p["name"]),
                        location=str(p.get("in", "query")),
                        param_type=str(schema.get("type") or p.get("type") or "string"),
                        required=bool(p.get("required", p.get("in") == "path")),
                    )
                )
            body_sample = None
            body = _resolve(doc, op.get("requestBody", {}))
            if isinstance(body, dict):
                content = body.get("content", {}) or {}
                media = content.get("application/json") or next(iter(content.values()), {})
                schema = _resolve(doc, (media or {}).get("schema", {}))
                if isinstance(schema, dict) and schema:
                    body_sample = sample_from_schema(doc, schema)
                    for name, prop in (schema.get("properties", {}) or {}).items():
                        prop = _resolve(doc, prop) or {}
                        params.append(
                            EndpointParameter(
                                name=str(name), location="body",
                                param_type=str(prop.get("type") or "string"),
                                required=name in (schema.get("required") or []),
                            )
                        )
            if body_sample is None:
                for q in op.get("parameters", []) or []:  # Swagger 2 body parameter
                    q = _resolve(doc, q)
                    if isinstance(q, dict) and q.get("in") == "body":
                        body_sample = sample_from_schema(doc, q.get("schema", {}))

            path_params = [p for p in params if p.location == "path"]
            low = full_path.lower()
            info.endpoints.append(
                Endpoint(
                    id=_make_id(verb, full_path),
                    method=verb,
                    path=full_path,
                    handler_name=str(op.get("operationId", "")),
                    auth_required=_requires_auth(doc, op),
                    parameters=params,
                    database_access=bool(path_params),
                    object_identifier=bool(path_params),
                    state_changing=verb in _STATE_CHANGING,
                    external_network=any(w in p.name.lower() for p in params for w in _URL_PARAM_WORDS),
                    sensitive_data=any(w in low for w in _SENSITIVE_WORDS),
                    source=SourceLocation(file=rel, line_start=1, line_end=1),
                    registered=True,
                    confidence="medium",
                    origin="spec",
                )
            )
            hint: Dict[str, Any] = {"exists": True}
            if body_sample is not None:
                hint["body"] = body_sample
            info.hints[f"{verb} {full_path}"] = hint
    if not info.endpoints:
        info.warnings.append(f"{rel}: no operations found")
    return info


def _norm(path: str) -> str:
    return re.sub(r"\{[^}/]*\}|<[^>/]*>|:[A-Za-z_]\w*", "{}", path).lower().rstrip("/") or "/"


def _same_route(a: Endpoint, b: Endpoint) -> bool:
    if a.method.upper() != b.method.upper() and "ALL" not in (a.method.upper(), b.method.upper()):
        return False
    pa, pb = _norm(a.path), _norm(b.path)
    return pa == pb or pa.endswith(pb) or pb.endswith(pa)


def merge_with_code(
    code: List[Endpoint], spec: List[Endpoint]
) -> Tuple[List[Endpoint], Dict[str, List[str]]]:
    """Add spec-only routes to ``code`` and report the inventory differences."""
    documented_only: List[Endpoint] = []
    matched = 0
    mismatch: List[str] = []
    for s in spec:
        twin = next((c for c in code if _same_route(c, s)), None)
        if twin is None:
            documented_only.append(s)
            continue
        matched += 1
        if s.auth_required and not twin.auth_required:
            mismatch.append(f"{s.method} {s.path}: spec requires auth, code shows none")
    code_only = [c for c in code if c.registered and not any(_same_route(c, s) for s in spec)]
    inventory = {
        "matched": [str(matched)],
        "documented_not_in_code": [f"{e.method} {e.path}" for e in documented_only],
        "in_code_not_documented": [f"{e.method} {e.path}" for e in code_only],
        "auth_mismatch": mismatch,
    }
    return list(code) + documented_only, inventory
