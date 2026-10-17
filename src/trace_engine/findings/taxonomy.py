"""CWE and OWASP taxonomy for every finding category TRACE can emit."""

from typing import Dict, Optional, Tuple

# category -> (primary CWE, OWASP reference)
CATEGORY_TAXONOMY: Dict[str, Tuple[Optional[str], Optional[str]]] = {
    "BOLA": ("CWE-639", "API1:2023"),
    "AUTHENTICATION": ("CWE-306", "API2:2023"),
    "MASS_ASSIGNMENT": ("CWE-915", "API3:2023"),
    "RATE_LIMIT": ("CWE-770", "API4:2023"),
    "BFLA": ("CWE-285", "API5:2023"),
    "SSRF": ("CWE-918", "API7:2023"),
    "CORS": ("CWE-942", "API8:2023"),
    "INJECTION": ("CWE-89", "A03:2021"),
    "SSTI": ("CWE-1336", "A03:2021"),
    "PATH_TRAVERSAL": ("CWE-22", "A01:2021"),
    "DESERIALIZATION": ("CWE-502", "A08:2021"),
    "JWT": ("CWE-347", "API2:2023"),
    "OPEN_REDIRECT": ("CWE-601", "A01:2021"),
    "SECRETS": ("CWE-798", "A07:2021"),
    "DEPENDENCY": ("CWE-1395", "A06:2021"),
    "MISCONFIG": ("CWE-16", "A05:2021"),
}


def lookup(category: str, title: str = "") -> Tuple[Optional[str], Optional[str]]:
    """Return ``(cwe, owasp)`` for a category; refines injection by title."""
    cat = (category or "").upper().replace(" ", "_")
    cwe, owasp = CATEGORY_TAXONOMY.get(cat, (None, None))
    if cat == "INJECTION":
        low = (title or "").lower()
        if "command" in low or "shell" in low:
            cwe = "CWE-78"
    return cwe, owasp
