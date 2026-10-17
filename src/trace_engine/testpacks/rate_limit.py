"""Rate-limit test pack: does a sensitive endpoint throttle a burst of requests?

Bounded and conservative: a fixed small burst against credential/one-time-code
style routes, never a flood. A target that answers every request in the burst
without a 429, 503 or rate-limit headers is reported as unthrottled.
"""

import re
from typing import List

from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.testpacks.base import TestContext, TestExecutionResult, TestPack

BURST = 20
_LIMIT_HEADERS = ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit", "ratelimit-remaining")
_SAFE_METHODS_FOR_BURST = ("GET", "POST")


class RateLimitTestPack(TestPack):
    @property
    def name(self) -> str:
        return "rate_limit"

    @property
    def description(self) -> str:
        return "Sends a small bounded burst to credential and one-time-code routes and checks for throttling."

    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        base_url = context.target_base_url.rstrip("/")
        parts = hypothesis.endpoint_display.split(" ")
        method = (parts[0] if len(parts) > 1 else "POST").upper()
        raw_path = parts[1] if len(parts) > 1 else parts[0]
        url = base_url + re.sub(r"\{[a-zA-Z0-9_]+\}", "1", raw_path)

        if method not in _SAFE_METHODS_FOR_BURST:
            return TestExecutionResult(
                testpack_name=self.name, hypothesis_id=hypothesis.id, confirmed=False, confidence=0.0,
                summary=f"Rate-limit burst skipped for {method} (only GET/POST are probed).",
            )

        observations: List[RuntimeObservation] = []
        headers = context.headers_for("user-a")
        body = {} if method == "POST" else None
        for _ in range(BURST):
            obs = client.execute(method=method, url=url, headers=dict(headers), json_body=body)
            observations.append(obs)
            if obs.response_status in (0, 429, 503):
                break

        reached = [o for o in observations if o.response_status != 0]
        throttled = any(o.response_status in (429, 503) for o in reached) or any(
            h.lower() in _LIMIT_HEADERS for o in reached for h in o.response_headers
        )
        if not reached:
            return TestExecutionResult(
                testpack_name=self.name, hypothesis_id=hypothesis.id, confirmed=False, confidence=0.0,
                summary="Target unreachable. Rate-limit probe inconclusive.", observations=observations,
            )
        if throttled:
            return TestExecutionResult(
                testpack_name=self.name, hypothesis_id=hypothesis.id, confirmed=False, confidence=0.1,
                summary=f"Throttling observed after {len(observations)} request(s) (429/503 or rate-limit headers).",
                observations=observations,
            )
        confirmed = len(reached) >= BURST
        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.8 if confirmed else 0.2,
            summary=(
                f"Missing rate limiting (CWE-770): {len(reached)} rapid requests to {method} {raw_path} "
                f"were all served without HTTP 429/503 or rate-limit headers."
                if confirmed
                else f"Burst ended early after {len(reached)} request(s) without throttling signals."
            ),
            observations=observations,
            reproduction_steps=[
                f"Send {BURST} rapid {method} requests to {url}",
                "Observe that none is answered with HTTP 429 or carries rate-limit headers",
            ] if confirmed else [],
        )
