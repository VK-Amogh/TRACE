"""Chain-mode escalation: turn isolated leaks into attack chains.

After the main scan, values leaked in one finding's observations (user ids,
emails, tokens) are harvested and re-injected as ID parameters into *other*
endpoints. A hit proves data from finding A unlocks finding B — an attack
chain, not an isolated flaw. Design inspired by chain-mode API scanners;
reimplemented for TRACE testpacks.
"""

import re
from typing import Dict, List, Tuple

from trace_engine.testpacks.canary import attacker_sees_owner_markers

MAX_CHAIN_PROBES = 10

_ID_PATTERNS = (
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",  # email
    r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b",  # uuid
    r'"id"\s*:\s*"([A-Za-z0-9_.\-]{3,64})"',  # "id": "value"
    r"\b(user|order|patient|tenant|vault)[-_]?([0-9]{1,9})\b",  # prefixed ints
)


def harvest_markers(texts: List[str], limit: int = 20) -> List[str]:
    """Extract distinctive leaked values from response bodies/evidence."""
    found: List[str] = []
    seen = set()
    for text in texts:
        for pattern in _ID_PATTERNS:
            for m in re.finditer(pattern, text or ""):
                value = m.group(1) if m.lastindex else m.group(0)
                if value and value not in seen and len(value) >= 3:
                    seen.add(value)
                    found.append(value)
                    if len(found) >= limit:
                        return found
    return found


def finding_texts(finding) -> List[str]:
    """Collect harvestable text from a finding's evidence and observations."""
    texts: List[str] = list(finding.runtime_evidence or [])
    for obs in finding.observations or []:
        texts.append(getattr(obs, "response_body", "") or "")
    return texts


def substitute_param(path: str, value: str) -> str:
    """Replace the first {param} or :param placeholder with a value."""
    import urllib.parse

    replaced, count = re.subn(r"\{[a-zA-Z0-9_]+\}", urllib.parse.quote(value, safe=""), path, count=1)
    if count == 0:
        replaced, count = re.subn(r":[a-zA-Z0-9_]+", urllib.parse.quote(value, safe=""), path, count=1)
    return replaced


def escalate_chains(
    routes: List[Tuple[str, str]],
    findings: List,
    client,
    context,
    limit: int = MAX_CHAIN_PROBES,
) -> List[Dict[str, object]]:
    """Probe other routes with harvested leak values.

    `routes` are (method, path) pairs. Returns chain hits:
    ``{"from_finding": id, "marker": value, "method":, "path":,
    "leaked": [...]}``. Bounded by `limit` total probes. Never raises:
    transport errors end the pass quietly.
    """
    markers: List[str] = []
    marker_source: Dict[str, str] = {}
    for finding in findings:
        for marker in harvest_markers(finding_texts(finding)):
            if marker not in marker_source:
                marker_source[marker] = finding.id
                markers.append(marker)

    hits: List[Dict[str, object]] = []
    probes = 0
    token = (context.active_tokens or {}).get("user-b", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    for method, path in routes:
        # Only routes with an injectable path parameter can chain.
        if "{" not in path and not re.search(r"/:[a-zA-Z0-9_]+", path):
            continue
        for marker in markers:
            if probes >= limit:
                return hits
            probes += 1
            try:
                obs = client.execute(
                    method=method, url=f"{context.target_base_url.rstrip('/')}{substitute_param(path, marker)}",
                    headers=headers,
                )
                observations = [obs]
            except Exception:
                continue
            if obs.response_status == 200:
                diff = attacker_sees_owner_markers(marker, obs.response_body)
                leaked = diff["leaked"] or ([marker] if marker in (obs.response_body or "") else [])
                if leaked:
                    hits.append(
                        {
                            "from_finding": marker_source[marker],
                            "marker": marker,
                            "method": method,
                            "path": path,
                            "leaked": leaked,
                        }
                    )
    return hits
