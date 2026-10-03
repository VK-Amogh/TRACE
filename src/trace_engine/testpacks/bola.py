"""BOLA (Broken Object Level Authorization) test pack."""

import re
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class BolaTestPack(TestPack):
    @property
    def name(self) -> str:
        return "bola"

    @property
    def description(self) -> str:
        return "Validates whether object lookups enforce tenant and ownership boundaries."

    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        base_url = context.target_base_url.rstrip("/")
        # Path from endpoint display (e.g. "GET /api/orders/{id}")
        parts = hypothesis.endpoint_display.split(" ")
        method = parts[0] if len(parts) > 1 else "GET"
        raw_path = parts[1] if len(parts) > 1 else parts[0]

        # Candidate object IDs to probe
        test_ids = ["order-101", "101", "1", "order-102", "order-user-a"]
        observations = []
        confirmed = False
        summary = "No BOLA behavior observed."
        steps = []

        # Obtain tokens for user-a and user-b if available
        token_a = context.active_tokens.get("user-a", "")
        token_b = context.active_tokens.get("user-b", "")

        for test_id in test_ids:
            probe_path = re.sub(r"\{[a-zA-Z0-9_]+\}", test_id, raw_path)
            target_url = f"{base_url}{probe_path}"

            # Step 1: Request with user-b token (or no token if unauth test)
            headers = {}
            if token_b:
                headers["Authorization"] = f"Bearer {token_b}"

            obs = client.execute(method=method, url=target_url, headers=headers)
            observations.append(obs)

            if obs.response_status == 200:
                # Check if data belonged to user-a or contains sensitive order info
                body_lower = obs.response_body.lower()
                if "user-a" in body_lower or "total" in body_lower or "items" in body_lower or "product" in body_lower:
                    confirmed = True
                    summary = (
                        f"BOLA confirmed: User 'user-b' successfully accessed object '{test_id}' "
                        f"belonging to another identity on endpoint {raw_path} with status 200 OK."
                    )
                    steps = [
                        f"Send {method} {target_url} with user-b credentials",
                        f"Observe HTTP status 200 OK returning private data of user-a",
                    ]
                    break

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.95 if confirmed else 0.20,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
