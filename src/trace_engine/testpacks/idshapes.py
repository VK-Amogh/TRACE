"""Identifier shape catalog and neighbour mutations for BOLA probes."""

import base64
import binascii
import re
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, List, Optional

from pydantic import BaseModel


class IdShape(BaseModel):
    name: str
    kind: str  # "enumerable" (guessable) or "opaque" (random)
    regex: str
    mutation: str


@lru_cache(maxsize=1)
def load_shapes() -> List[IdShape]:
    path = Path(__file__).resolve().parent / "id_patterns.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [IdShape(**item) for item in data.get("pattern", [])]


def classify(value: str) -> Optional[IdShape]:
    """First catalog shape matching ``value``."""
    text = str(value)
    for shape in load_shapes():
        if re.match(shape.regex, text):
            return shape
    return None


def _increment(value: str) -> List[str]:
    n = int(value)
    return [str(n + 1)] + ([str(n - 1)] if n > 0 else [])


def _increment_suffix(value: str) -> List[str]:
    m = re.match(r"^(.*?)(\d+)$", value)
    if not m:
        return []
    head, digits = m.groups()
    n = int(digits)
    pad = len(digits)
    out = [f"{head}{n + 1:0{pad}d}"]
    if n > 0:
        out.append(f"{head}{n - 1:0{pad}d}")
    return out


def _flip_last_nibble(value: str) -> List[str]:
    last = value[-1].lower()
    if last not in "0123456789abcdef":
        return []
    flipped = "0123456789abcdef"[(int(last, 16) + 1) % 16]
    return [value[:-1] + flipped]


def _base64_increment(value: str) -> List[str]:
    try:
        raw = base64.b64decode(value, validate=True).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return []
    if not raw.isdigit():
        return []
    return [base64.b64encode(str(int(raw) + 1).encode("ascii")).decode("ascii")]


def _slug_neighbor(value: str) -> List[str]:
    if re.search(r"\d+$", value):
        return _increment_suffix(value)
    return [f"{value}-1"]


MUTATIONS: Dict[str, Callable[[str], List[str]]] = {
    "increment": _increment,
    "increment_suffix": _increment_suffix,
    "flip_last_nibble": _flip_last_nibble,
    "base64_increment": _base64_increment,
    "slug_neighbor": _slug_neighbor,
}


def mutations(value: str, limit: int = 4) -> List[str]:
    """Neighbouring IDs of ``value`` according to its shape (never ``value`` itself)."""
    shape = classify(value)
    if shape is None:
        return []
    fn = MUTATIONS.get(shape.mutation)
    if fn is None:
        return []
    try:
        out = [m for m in fn(str(value)) if m != str(value)]
    except (ValueError, OverflowError):
        return []
    return out[:limit]
