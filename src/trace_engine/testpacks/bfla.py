"""BFLA (Broken Function Level Authorization) test pack."""

import re
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class BflaTestPack(TestPack):
    @property
    def name(self) -> str:
        return "bfla"

    @property
    def description(self) -> str:
        return "Validates whether administrative and privileged endpoints enforce proper RBAC."

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

        target_url = f"{base_url}{raw_path}"
        token_user = context.active_tokens.get("user-a") or context.active_tokens.get("user-b", "")

        observations = []
        confirmed = False
        summary = "No BFLA behavior observed."
        steps = []

        headers = {}
        if token_user:
            headers["Authorization"] = f"Bearer {token_user}"

        # Probe with low-privileged token
        test_payload = {"order_id": "order-101", "amount": 50, "reason": "test"}
        obs = client.execute(
            method=method, url=target_url, headers=headers, json_body=test_payload if method != "GET" else None
        )
        observations.append(obs)

        # If HTTP 200 or 201 is returned rather than 403 Forbidden, privilege check is flawed
        if obs.response_status in (200, 201):
            confirmed = True
            summary = (
                f"BFLA confirmed: Privileged endpoint {raw_path} executed successfully "
                f"under standard user identity without 403 Forbidden check."
            )
            steps = [
                f"Authenticate as standard user 'user-a'",
                f"Invoke privileged endpoint {method} {target_url}",
                f"Received HTTP {obs.response_status} indicating unauthorized function execution",
            ]

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.92 if confirmed else 0.20,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
