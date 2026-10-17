"""Redaction of credentials from persisted runtime evidence.

Observations are written to ``.trace/findings.json`` and the evidence log, and
may be shared. When real identities are configured, their tokens must never be
persisted, so headers and token-shaped text are masked at the source.
"""

import re
from typing import Dict

from trace_engine.runtime.observations import RuntimeObservation

SENSITIVE_HEADERS = frozenset(
    {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
        "api-key", "apikey", "x-auth-token", "x-access-token", "x-csrf-token",
        "x-xsrf-token", "x-amz-security-token",
    }
)
REDACTED = "<redacted>"

_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r'(?i)("(?:access_|refresh_|id_|api_|auth_)?(?:token|secret|password|key)"\s*:\s*")([^"]{6,})(")'
    ),
]


def redact_text(text: str) -> str:
    if not text:
        return text
    out = _PATTERNS[0].sub(REDACTED, text)
    out = _PATTERNS[1].sub("Bearer " + REDACTED, out)
    out = _PATTERNS[2].sub(lambda m: m.group(1) + REDACTED + m.group(3), out)
    return out


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    cleaned: Dict[str, str] = {}
    for name, value in (headers or {}).items():
        low = name.lower()
        if low in SENSITIVE_HEADERS:
            scheme = str(value).split(" ", 1)[0] if low == "authorization" and " " in str(value) else ""
            cleaned[name] = f"{scheme} {REDACTED}".strip()
        else:
            cleaned[name] = value
    return cleaned


def redact_observation(obs: RuntimeObservation) -> RuntimeObservation:
    """Copy of ``obs`` that is safe to persist or share."""
    return obs.model_copy(
        update={
            "request_headers": redact_headers(obs.request_headers),
            "response_headers": redact_headers(obs.response_headers),
            "request_body": redact_text(obs.request_body) if obs.request_body else obs.request_body,
            "response_body": redact_text(obs.response_body),
        }
    )
