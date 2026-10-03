"""SSRF (Server-Side Request Forgery) test pack."""

import re
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class SsrfTestPack(TestPack):
    @property
    def name(self) -> str:
        return "ssrf"

    @property
    def description(self) -> str:
        return "Validates whether server endpoints can be coerced into arbitrary internal network fetches."

    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        base_url = context.target_base_url.rstrip("/")
        parts = hypothesis.endpoint_display.split(" ")
        method = parts[0] if len(parts) > 1 else "POST"
        raw_path = parts[1] if len(parts) > 1 else parts[0]

        clean_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "1", raw_path)
        target_url = f"{base_url}{clean_path}"
        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        # Safe internal loopback probe targeting local products list
        internal_probe = f"{base_url}/api/products"
        payload = {"url": internal_probe, "target": internal_probe}

        obs = client.execute(method=method, url=target_url, headers=headers, json_body=payload)
        observations = [obs]

        confirmed = False
        summary = "No SSRF behavior observed."
        steps = []

        if obs.response_status == 200:
            body_lower = obs.response_body.lower()
            # If the internal service content or products are echoed back
            if "status" in body_lower or "data" in body_lower or "product" in body_lower or "content" in body_lower:
                confirmed = True
                summary = (
                    f"SSRF confirmed: Endpoint {raw_path} executed internal network request "
                    f"to {internal_probe} and returned fetched data."
                )
                steps = [
                    f"Send {method} {target_url} with payload pointing to internal URL: {internal_probe}",
                    "Server fetched target and returned response payload",
                ]

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.96 if confirmed else 0.25,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
