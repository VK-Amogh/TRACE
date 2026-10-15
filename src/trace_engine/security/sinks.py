"""Declarative sink catalog: match handler bodies against data, not code.

The catalog lives in ``sinks.toml`` next to this module. ``tomllib`` is
stdlib on Python 3.11+, so lite installs need no new dependency. A hit is
suppressed when a sanitizer for the same sink kind appears in the body.
"""

import re
import tomllib
from pathlib import Path
from typing import Dict, List
from pydantic import BaseModel, Field


class SinkEntry(BaseModel):
    """One catalogued dangerous operation."""

    id: str
    category: str
    langs: List[str] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    cwe: str = ""
    testpack: str = ""


class SinkHit(BaseModel):
    """A catalog match inside a handler body."""

    sink_id: str
    category: str
    cwe: str
    testpack: str
    pattern: str


_catalog: List[SinkEntry] = []
_compiled: Dict[str, List[re.Pattern]] = {}
_compiled_sanitizers: Dict[str, List[re.Pattern]] = {}


def _load_catalog() -> List[SinkEntry]:
    global _catalog, _compiled, _compiled_sanitizers
    if _catalog:
        return _catalog
    toml_path = Path(__file__).resolve().parent / "sinks.toml"
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)
    for raw in data.get("sink", []):
        entry = SinkEntry(**raw)
        _catalog.append(entry)
        _compiled[entry.id] = [re.compile(p, re.IGNORECASE) for p in entry.patterns]
        _compiled_sanitizers[entry.id] = [re.compile(p, re.IGNORECASE) for p in entry.sanitizers]
    return _catalog


def reset_catalog() -> None:
    """Clear cached catalog (tests only)."""
    global _catalog, _compiled, _compiled_sanitizers
    _catalog = []
    _compiled = {}
    _compiled_sanitizers = {}


def match_sinks(body: str, language: str) -> List[SinkHit]:
    """Return catalog hits for a handler body, minus sanitized kinds."""
    text = body or ""
    hits: List[SinkHit] = []
    for entry in _load_catalog():
        if entry.langs and language not in entry.langs:
            continue
        matched = [rx.pattern for rx in _compiled[entry.id] if rx.search(text)]
        if not matched:
            continue
        if any(rx.search(text) for rx in _compiled_sanitizers[entry.id]):
            continue
        hits.append(
            SinkHit(
                sink_id=entry.id,
                category=entry.category,
                cwe=entry.cwe,
                testpack=entry.testpack,
                pattern=matched[0],
            )
        )
    return hits


def has_sink_kind(body: str, language: str, *kinds: str) -> bool:
    """True when any hit's id starts with one of the given kind prefixes."""
    return any(
        hit.sink_id.startswith(kind)
        for hit in match_sinks(body, language)
        for kind in kinds
    )
