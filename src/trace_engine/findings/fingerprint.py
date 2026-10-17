"""Stable finding identity.

Finding IDs (``TR-BOLA-001``) are positional and change whenever a scan runs
over modified code. A fingerprint identifies the *same flaw* across scans, so
suppression files and baseline diffs keep working when line numbers drift or
unrelated findings appear and disappear.
"""

import hashlib
import re
from typing import Optional

_PARAM_RE = re.compile(r"\{[^}/]*\}|<[^>/]*>|:[A-Za-z_][A-Za-z0-9_]*")
_DIGITS_RE = re.compile(r"\d+")
_SPACE_RE = re.compile(r"\s+")


def normalize_endpoint(endpoint: str) -> str:
    """``get /Users/{user_id}/`` -> ``GET /users/{}``."""
    text = (endpoint or "").strip()
    method = ""
    if " " in text:
        head, _, rest = text.partition(" ")
        if head.isalpha() and head.isupper() or head.upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL", "ANY",
        }:
            method, text = head.upper(), rest.strip()
    text = _PARAM_RE.sub("{}", text).lower().rstrip("/")
    return f"{method} {text}".strip()


def normalize_path(path: Optional[str]) -> str:
    """Last two path segments, lowercased, so absolute paths differ by machine."""
    if not path:
        return ""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    return "/".join(parts[-2:]).lower()


def normalize_title(title: str) -> str:
    return _SPACE_RE.sub(" ", _DIGITS_RE.sub("", (title or "").lower())).strip()


def compute_fingerprint(
    category: str, endpoint: str, file: Optional[str], title: str = ""
) -> str:
    """16-hex-char identity of a flaw: category + endpoint + file + rule title."""
    key = "|".join(
        [
            (category or "").upper(),
            normalize_endpoint(endpoint),
            normalize_path(file),
            normalize_title(title),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
