"""Explainable 0-100 priority score for findings.

Deterministic: the same finding always scores the same, and every point is
attributable to a named factor, so a reviewer (or an agent) can see why one
finding outranks another. This is a *fix-order* aid, not a CVSS replacement.
"""

from typing import Dict, Iterable, Tuple

CATEGORY_BASE = {
    "INJECTION": 35, "DESERIALIZATION": 35, "SSTI": 30, "BOLA": 28, "BFLA": 28,
    "SECRETS": 30, "AUTHENTICATION": 25, "SSRF": 25, "JWT": 25, "PATH_TRAVERSAL": 22,
    "DEPENDENCY": 20, "MASS_ASSIGNMENT": 18, "OPEN_REDIRECT": 12, "RATE_LIMIT": 12,
    "MISCONFIG": 12, "CORS": 10,
}
CONFIDENCE_POINTS = {"CONFIRMED": 25, "HIGH": 15, "MEDIUM": 8, "POTENTIAL": 2}
SEVERITY_POINTS = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SENSITIVE_WORDS = (
    "password", "credential", "token", "secret", "payment", "card", "ssn",
    "private key", "api key", "billing", "medical", "pii",
)
UNAUTH_MARKERS = (
    "auth required: false", "no auth", "unauthenticated", "without authentication",
    "lacks authentication", "missing authentication",
)

TIERS = ((75, "P0"), (55, "P1"), (35, "P2"), (0, "P3"))


def tier_for(score: int) -> str:
    for floor, name in TIERS:
        if score >= floor:
            return name
    return "P3"


def _enum_value(value) -> str:
    return str(getattr(value, "value", value)).upper()


def score_finding(
    *,
    category: str,
    severity,
    confidence,
    title: str = "",
    attack_path: Iterable[str] = (),
    static_evidence: Iterable[str] = (),
    runtime_evidence: Iterable[str] = (),
    is_fixture: bool = False,
) -> Tuple[int, Dict[str, int], str]:
    """Return ``(score, factors, tier)``."""
    factors: Dict[str, int] = {}
    cat = (category or "").upper()
    factors["category_impact"] = CATEGORY_BASE.get(cat, 15)
    factors["confidence"] = CONFIDENCE_POINTS.get(_enum_value(confidence), 0)
    factors["severity"] = SEVERITY_POINTS.get(_enum_value(severity), 0)

    text = " ".join(list(static_evidence) + list(runtime_evidence) + [title or ""]).lower()
    if any(m in text for m in UNAUTH_MARKERS):
        factors["unauthenticated"] = 15
    if any(w in text for w in SENSITIVE_WORDS):
        factors["sensitive_data"] = 8
    hops = len(list(attack_path))
    if 0 < hops <= 3:
        factors["short_attack_path"] = 5
    if (title or "").lower().startswith("chained"):
        factors["chained_escalation"] = 10
    if is_fixture:
        factors["fixture_or_test_code"] = -30

    score = max(0, min(100, sum(factors.values())))
    return score, factors, tier_for(score)
