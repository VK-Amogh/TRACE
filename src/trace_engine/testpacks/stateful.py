"""Helpers for owner discovery and (opt-in) test-data creation in BOLA probes."""

import json
import re
from typing import Any, List, Optional

_LIST_KEYS = ("data", "items", "results", "records", "content", "rows", "list", "objects")
_PARAM_RE = re.compile(r"\{([A-Za-z0-9_]+)\}\s*$")


def collection_path(path: str) -> Optional[str]:
    """``/api/items/{id}`` -> ``/api/items`` (None when no trailing param)."""
    stripped = path.rstrip("/")
    if not _PARAM_RE.search(stripped):
        return None
    head = stripped.rsplit("/", 1)[0]
    return head or None


def trailing_param(path: str) -> Optional[str]:
    m = _PARAM_RE.search(path.rstrip("/"))
    return m.group(1) if m else None


def _records(doc: Any) -> List[dict]:
    if isinstance(doc, list):
        return [d for d in doc if isinstance(d, dict)]
    if isinstance(doc, dict):
        for key in _LIST_KEYS:
            if isinstance(doc.get(key), list):
                return [d for d in doc[key] if isinstance(d, dict)]
        for value in doc.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


def _id_of(record: dict, param: Optional[str]) -> Optional[str]:
    keys = [k for k in (param, "id", "_id", "uuid") if k]
    keys += [k for k in record if k.lower().endswith("id") and k not in keys]
    for key in keys:
        value = record.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
            return str(value)
    return None


def extract_ids(body: str, param: Optional[str] = None, limit: int = 3) -> List[str]:
    """Object IDs found in a list-style JSON response."""
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return []
    out: List[str] = []
    for record in _records(doc):
        ident = _id_of(record, param)
        if ident and ident not in out:
            out.append(ident)
        if len(out) >= limit:
            break
    return out


def extract_created_id(body: str, param: Optional[str] = None) -> Optional[str]:
    """ID of a freshly created object from a create-response body."""
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(doc, dict):
        direct = _id_of(doc, param)
        if direct:
            return direct
        for key in ("data", "result", "item", "record"):
            if isinstance(doc.get(key), dict):
                nested = _id_of(doc[key], param)
                if nested:
                    return nested
    return None
