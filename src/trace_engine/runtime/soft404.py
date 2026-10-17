"""Catch-all ("soft 404") detection.

Single-page apps, reverse proxies and some gateways answer 2xx for paths that
do not exist. Any probe that treats "got a 2xx" as proof then reports fiction.
TRACE asks the target what an unknown path looks like once, then refuses to
confirm a finding whose only evidence matches that page.
"""

import difflib
import hashlib
import json
import re
import secrets
from typing import List, Optional

from pydantic import BaseModel, Field

from trace_engine.runtime.observations import RuntimeObservation

_VOLATILE_RE = re.compile(r"[0-9a-fA-F]{8,}|\d+")


class CatchAllBaseline(BaseModel):
    status: int
    body_hash: str
    sample: str
    keys: List[str] = Field(default_factory=list)


def _normalize(body: str) -> str:
    return _VOLATILE_RE.sub("#", (body or "").strip())[:2000]


def _key_paths(obj, prefix: str = "") -> List[str]:
    keys: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            keys.append(path)
            keys.extend(_key_paths(v, path))
    elif isinstance(obj, list) and obj:
        keys.extend(_key_paths(obj[0], prefix + "[]"))
    return keys


def _json_keys(body: str) -> Optional[List[str]]:
    try:
        return sorted(set(_key_paths(json.loads(body))))
    except (ValueError, TypeError):
        return None


def baseline_from_observation(obs: RuntimeObservation) -> Optional[CatchAllBaseline]:
    if not 200 <= obs.response_status < 300:
        return None
    norm = _normalize(obs.response_body)
    return CatchAllBaseline(
        status=obs.response_status,
        body_hash=hashlib.sha256(norm.encode("utf-8")).hexdigest(),
        sample=norm,
        keys=_json_keys(obs.response_body) or [],
    )


def probe_catch_all(client, base_url: str) -> Optional[CatchAllBaseline]:
    """Request a random unknown path; return a baseline when it answers 2xx."""
    url = f"{base_url.rstrip('/')}/trace-{secrets.token_hex(6)}/{secrets.token_hex(4)}"
    return baseline_from_observation(client.execute(method="GET", url=url, headers={}))


def looks_like_catch_all(baseline: Optional[CatchAllBaseline], obs: RuntimeObservation) -> bool:
    """True when ``obs`` is indistinguishable from the target's unknown-path page."""
    if baseline is None or not 200 <= obs.response_status < 300:
        return False
    norm = _normalize(obs.response_body)
    if hashlib.sha256(norm.encode("utf-8")).hexdigest() == baseline.body_hash:
        return True
    keys = _json_keys(obs.response_body)
    if keys is not None and baseline.keys:
        union = set(keys) | set(baseline.keys)
        if union and len(set(keys) & set(baseline.keys)) / len(union) >= 0.9:
            return True
    if keys is None and not baseline.keys and baseline.sample and norm:
        return difflib.SequenceMatcher(None, baseline.sample, norm).ratio() >= 0.97
    return False


def only_catch_all_evidence(baseline: Optional[CatchAllBaseline], observations: List[RuntimeObservation]) -> bool:
    """True when every 2xx observation matches the catch-all page (and one exists)."""
    ok = [o for o in observations if 200 <= o.response_status < 300]
    return bool(ok) and all(looks_like_catch_all(baseline, o) for o in ok)
