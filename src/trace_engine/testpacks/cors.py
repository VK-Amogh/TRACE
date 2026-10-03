"""CORS (Cross-Origin Resource Sharing) Misconfiguration test pack (CWE-942)."""

from typing import List, Dict, Any
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation

PROBE_ORIGINS = [
    "https://attacker.evil.com",
    "https://untrusted-cross-origin.net",
    "null",
]


class CorsTestPack(TestPack):
    @property
    def name(self) -> str:
        return "cors"

    @property
    def description(self) -> str:
        return "Validates whether arbitrary untrusted origins are reflected with credentials enabled."

    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        base_url = context.target_base_url.rstrip("/")
        parts = hypothesis.endpoint_display.split(" ")
        method = parts[0] if len(parts) > 1 else "GET"
        raw_path = parts[1] if len(parts) > 1 else parts[0]

        target_url = f"{base_url}{raw_path}"
        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No exploitable CORS misconfiguration detected."
        steps: List[str] = []

        for origin in PROBE_ORIGINS:
            headers = {"Origin": origin}
            obs = client.execute(method=method, url=target_url, headers=headers)
            observations.append(obs)

            resp_hdrs = {k.lower(): v for k, v in obs.response_headers.items()}
            allow_origin = resp_hdrs.get("access-control-allow-origin", "")
            allow_creds = resp_hdrs.get("access-control-allow-credentials", "").lower() == "true"

            # 1. Arbitrary origin reflection with credentials
            if allow_origin in (origin, "*") and allow_creds:
                confirmed = True
                summary = (
                    f"CORS Misconfiguration (CWE-942) CONFIRMED: Endpoint {raw_path} reflected untrusted origin "
                    f"'{origin}' with 'Access-Control-Allow-Credentials: true', enabling cross-origin authenticated data theft."
                )
                steps = [
                    f"Send {method} request to {target_url} with header Origin: {origin}",
                    f"Observe response headers containing Access-Control-Allow-Origin: {allow_origin} and Access-Control-Allow-Credentials: true",
                ]
                break

            # 2. 'null' origin reflection with credentials
            if origin == "null" and allow_origin == "null" and allow_creds:
                confirmed = True
                summary = (
                    f"CORS Misconfiguration (CWE-942) CONFIRMED: Endpoint {raw_path} trusts origin 'null' "
                    f"with credentials, exposing authenticated session to sandboxed iframe attacks."
                )
                steps = [
                    f"Send {method} request to {target_url} with header Origin: null",
                    "Observe response header Access-Control-Allow-Origin: null with credentials allowed",
                ]
                break

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.90 if confirmed else 0.1,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
