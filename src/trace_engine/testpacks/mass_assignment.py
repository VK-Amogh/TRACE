"""Mass assignment test pack."""

import re
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class MassAssignmentTestPack(TestPack):
    @property
    def name(self) -> str:
        return "mass_assignment"

    @property
    def description(self) -> str:
        return "Validates whether object property updates accept privileged fields (e.g. is_admin, role)."

    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        base_url = context.target_base_url.rstrip("/")
        parts = hypothesis.endpoint_display.split(" ")
        method = parts[0] if len(parts) > 1 else "PATCH"
        raw_path = parts[1] if len(parts) > 1 else parts[0]

        probe_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "user-a", raw_path)
        target_url = f"{base_url}{probe_path}"

        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        # Inject privileged fields
        payload = {
            "name": "Updated User",
            "is_admin": True,
            "role": "admin",
        }

        obs = client.execute(method=method, url=target_url, headers=headers, json_body=payload)
        observations = [obs]

        confirmed = False
        summary = "No mass assignment vulnerability detected."
        steps = []

        if obs.response_status in (200, 201):
            body_lower = obs.response_body.lower()
            if "is_admin" in body_lower or "role" in body_lower or "admin" in body_lower:
                confirmed = True
                summary = (
                    f"Mass Assignment confirmed: Endpoint {raw_path} allowed binding of privileged "
                    f"attribute 'is_admin'/'role' into persisted entity."
                )
                steps = [
                    f"Send {method} {target_url} with payload: {{'is_admin': True, 'role': 'admin'}}",
                    f"Observed HTTP {obs.response_status} with updated administrative privilege in body",
                ]

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.91 if confirmed else 0.20,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
