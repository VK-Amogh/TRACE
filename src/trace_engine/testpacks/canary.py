"""Canary oracles: prove data flow with unique markers instead of matching
generic keywords like ``status`` or ``ok``.

A canary is a unique token this engine generated. A finding is only
confirmed when the canary (or owner-baseline marker) comes back in a
response where it should never appear.
"""

import secrets
from typing import Dict, List, Optional


def new_canary(prefix: str = "trc") -> str:
    """Generate a unique marker token, e.g. ``trc-9f2ac41b``."""
    return f"{prefix}-{secrets.token_hex(4)}"


def contains_canary(body: str, canary: str) -> bool:
    """True when the exact canary echo is present (case-sensitive)."""
    if not body or not canary:
        return False
    return canary in body


def owner_markers(owner_body: str, min_len: int = 4) -> List[str]:
    """Extract candidate owner-specific markers from a baseline response.

    Heuristic: quoted string/number literals that are specific enough to
    re-identify (emails, uuids, long tokens, distinctive names).
    """
    import re

    candidates = set()
    for m in re.finditer(r'"([A-Za-z0-9@._\-]{%d,})"' % min_len, owner_body or ""):
        candidates.add(m.group(1))
    for m in re.finditer(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", owner_body or ""):
        candidates.add(m.group(1))
    generic = {"status", "message", "data", "result", "error", "success", "true", "false", "null"}
    return sorted(c for c in candidates if c.lower() not in generic)


def attacker_sees_owner_markers(owner_body: str, attacker_body: str, required: int = 1) -> Dict[str, object]:
    """Ground-truth differential: does the attacker response leak owner markers?

    Returns ``{"leaked": [...], "confirmed": bool}``. This is the BOLA
    oracle: fetch as owner, refetch as attacker, require owner-specific
    markers — never generic keywords.
    """
    markers = owner_markers(owner_body)
    leaked = [m for m in markers if m and m in (attacker_body or "")]
    return {"leaked": leaked, "confirmed": len(leaked) >= required}
