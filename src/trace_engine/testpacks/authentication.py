"""Authentication bypass and missing authentication test pack."""

import re
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class AuthenticationTestPack(TestPack):
    @property
    def name(self) -> str:
        return "authentication"

    @property
    def description(self) -> str:
        return "Tests whether sensitive endpoints enforce authentication headers."

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

        # Replace any path param with dummy id
        probe_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "1", raw_path)
        target_url = f"{base_url}{probe_path}"

        # Send completely unauthenticated request
        obs = client.execute(method=method, url=target_url, headers={})
        observations = [obs]

        confirmed = False
        summary = "Authentication properly enforced (received 401/403)."
        steps = []

        if obs.response_status in (200, 201, 204):
            confirmed = True
            summary = (
                f"Missing Authentication confirmed: Sensitive endpoint {raw_path} responded "
                f"with {obs.response_status} to an unauthenticated request."
            )
            steps = [
                f"Send unauthenticated {method} request to {target_url}",
                f"Received HTTP {obs.response_status} rather than expected 401/403",
            ]

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.90 if confirmed else 0.15,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
