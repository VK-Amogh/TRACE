"""Build probe identities from configuration.

With no ``[identities.*]`` tables TRACE falls back to synthetic bearer tokens
(``user-a``, ``user-b``, ``admin``). Configured identities replace them
entirely, so a scan never mixes real and synthetic credentials.
"""

import base64
import os
import re
from typing import Dict, List, Tuple

from trace_engine.config.settings import IdentityConfig, TraceConfig
from trace_engine.constants import DEFAULT_TEST_TOKENS
from trace_engine.testpacks.base import TestContext

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve(value: str, name: str, warnings: List[str]) -> str:
    """Expand ``${VAR}``; an unset variable yields an empty string and a warning."""
    def sub(match: "re.Match[str]") -> str:
        var = match.group(1)
        if var not in os.environ:
            warnings.append(f"identity '{name}': environment variable {var} is not set")
            return ""
        return os.environ[var]

    return _ENV_RE.sub(sub, value or "")


def headers_for_identity(name: str, cfg: IdentityConfig, warnings: List[str]) -> Tuple[Dict[str, str], str]:
    """Return ``(headers, bare_token)`` for one identity ({} when unusable)."""
    kind = (cfg.kind or "bearer").lower()
    token = _resolve(cfg.token or "", name, warnings)
    if kind == "basic":
        user = _resolve(cfg.username or "", name, warnings)
        pw = _resolve(cfg.password or "", name, warnings)
        if not user:
            warnings.append(f"identity '{name}': basic auth needs a username")
            return {}, ""
        raw = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {raw}"}, raw
    if not token:
        warnings.append(f"identity '{name}': no usable token; skipped")
        return {}, ""
    if kind == "bearer":
        return {"Authorization": f"Bearer {token}"}, token
    if kind in ("api_key", "header"):
        return {cfg.header or "X-API-Key": token}, token
    if kind == "cookie":
        return {"Cookie": f"{cfg.cookie or 'session'}={token}"}, token
    warnings.append(f"identity '{name}': unknown kind '{cfg.kind}'; skipped")
    return {}, ""


def build_context(target_url: str, config: TraceConfig) -> Tuple[TestContext, List[str]]:
    """Create the probe context for ``target_url`` from ``config``."""
    warnings: List[str] = []
    if not config.identities:
        return TestContext(target_base_url=target_url, active_tokens=dict(DEFAULT_TEST_TOKENS)), warnings
    tokens: Dict[str, str] = {}
    auth: Dict[str, Dict[str, str]] = {}
    for name, cfg in config.identities.items():
        headers, token = headers_for_identity(name, cfg, warnings)
        if headers:
            auth[name] = headers
            tokens[name] = token
    return TestContext(target_base_url=target_url, active_tokens=tokens, auth_headers=auth), warnings
