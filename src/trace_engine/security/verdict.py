"""Weighted multi-signal verdict engine for cross-identity response comparison.

Scores whether a prober (attacker) response exposes data from an owner
baseline using five independent signals. Thresholds: CONFIRMED >= 0.75,
LIKELY >= 0.50, otherwise CLEAR.
"""

from typing import Any, Dict, List, Set
from pydantic import BaseModel, Field

W_STATUS = 0.30
W_STRUCTURE = 0.35
W_OVERLAP = 0.20
W_SIZE = 0.05
DENIAL_PENALTY = 0.10

THRESHOLD_CONFIRMED = 0.75
THRESHOLD_LIKELY = 0.50

DENIAL_KEYWORDS = (
    "forbidden",
    "unauthorized",
    "access denied",
    "access-denied",
    "not permitted",
    "permission denied",
)


class PairVerdict(BaseModel):
    """Verdict for one owner/prober response pair."""

    score: float = Field(ge=0.0, le=1.0)
    verdict: str
    breakdown: Dict[str, float] = Field(default_factory=dict)


def _parse_json(body: str) -> Any:
    import json

    try:
        return json.loads(body)
    except Exception:
        return None


def _key_paths(obj: Any, prefix: str = "") -> Set[str]:
    paths: Set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            paths.add(key)
            paths.update(_key_paths(v, key))
    elif isinstance(obj, list):
        for item in obj[:5]:
            paths.update(_key_paths(item, prefix + "[]"))
    return paths


def _leaf_values(obj: Any) -> List[str]:
    if obj is None or isinstance(obj, bool):
        return []
    if isinstance(obj, (int, float)):
        return [str(obj)]
    if isinstance(obj, str):
        return [obj] if len(obj) >= 3 else []
    if isinstance(obj, dict):
        out: List[str] = []
        for v in obj.values():
            out.extend(_leaf_values(v))
        return out
    if isinstance(obj, list):
        out = []
        for v in obj[:20]:
            out.extend(_leaf_values(v))
        return out
    return []


def score_response_pair(
    owner_status: int,
    owner_body: str,
    prober_status: int,
    prober_body: str,
) -> PairVerdict:
    """Score whether the prober response leaks the owner baseline."""
    breakdown: Dict[str, float] = {}

    s_status = W_STATUS if (owner_status == 200 and prober_status == 200) else 0.0
    breakdown["status"] = round(s_status, 4)

    owner_doc = _parse_json(owner_body or "")
    prober_doc = _parse_json(prober_body or "")
    if owner_doc is not None and prober_doc is not None:
        ok, pk = _key_paths(owner_doc), _key_paths(prober_doc)
        union = ok | pk
        jaccard = len(ok & pk) / len(union) if union else 0.0
        s_struct = W_STRUCTURE * jaccard
        owner_leaves = set(_leaf_values(owner_doc))
        prober_leaves = set(_leaf_values(prober_doc))
        overlap = len(owner_leaves & prober_leaves) / len(owner_leaves) if owner_leaves else 0.0
        s_overlap = W_OVERLAP * overlap
    else:
        s_struct = 0.0
        s_overlap = W_OVERLAP if (owner_body and owner_body == prober_body) else 0.0
    breakdown["structure"] = round(s_struct, 4)
    breakdown["overlap"] = round(s_overlap, 4)

    la, lb = len(owner_body or ""), len(prober_body or "")
    s_size = W_SIZE * max(0.0, 1.0 - abs(la - lb) / max(la, lb, 1))
    breakdown["size"] = round(s_size, 4)

    lowered = (prober_body or "").lower()
    penalty = DENIAL_PENALTY if any(k in lowered for k in DENIAL_KEYWORDS) else 0.0
    breakdown["denial_penalty"] = round(penalty, 4)

    total = max(0.0, min(1.0, s_status + s_struct + s_overlap + s_size - penalty))
    if total >= THRESHOLD_CONFIRMED:
        verdict = "CONFIRMED"
    elif total >= THRESHOLD_LIKELY:
        verdict = "LIKELY"
    else:
        verdict = "CLEAR"
    return PairVerdict(score=round(total, 4), verdict=verdict, breakdown=breakdown)
