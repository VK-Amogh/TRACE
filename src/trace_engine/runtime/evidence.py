"""Replayable evidence log for every probe TRACE sends.

Each request/response is appended to ``.trace/evidence/<run>.jsonl`` (headers
and tokens redacted) so a finding can be verified independently of TRACE, for
example by re-running the printed ``curl`` command or loading the log in a
proxy tool.
"""

import json
import shlex
import time
from pathlib import Path
from typing import Dict, List, Optional

from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.runtime.redact import redact_observation


class EvidenceLog:
    """Append-only JSONL log of runtime observations."""

    def __init__(self, directory: Path, run_id: Optional[str] = None):
        self.directory = Path(directory)
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%S")
        self.path = self.directory / f"{self.run_id}.jsonl"
        self.count = 0

    def record(self, obs: RuntimeObservation) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        safe = redact_observation(obs)
        row = {
            "ts": round(time.time(), 3),
            "method": safe.request_method,
            "url": safe.request_url,
            "request_headers": safe.request_headers,
            "request_body": safe.request_body,
            "status": safe.response_status,
            "response_headers": safe.response_headers,
            "response_body": safe.response_body[:2000],
            "latency_ms": safe.latency_ms,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        self.count += 1


def to_curl(obs: RuntimeObservation) -> str:
    """A ``curl`` command reproducing ``obs`` with credentials masked."""
    safe = redact_observation(obs)
    parts: List[str] = ["curl", "-i", "-X", safe.request_method, shlex.quote(safe.request_url)]
    for name, value in safe.request_headers.items():
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    if safe.request_body:
        parts += ["--data", shlex.quote(safe.request_body)]
    return " ".join(parts)


def curl_commands(observations: List[RuntimeObservation], limit: int = 6) -> List[str]:
    """Distinct curl commands for the observations that reached the target."""
    seen: Dict[str, None] = {}
    for obs in observations:
        if obs.response_status == 0:
            continue
        seen.setdefault(to_curl(obs), None)
        if len(seen) >= limit:
            break
    return list(seen)
