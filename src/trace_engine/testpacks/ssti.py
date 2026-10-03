"""Server-Side Template Injection (SSTI) test pack (CWE-1336 / CWE-94)."""

import re
from typing import List, Dict, Any
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation

SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
]


class SstiTestPack(TestPack):
    @property
    def name(self) -> str:
        return "ssti"

    @property
    def description(self) -> str:
        return "Validates whether template engines dynamically evaluate user-supplied mathematical and script expressions."

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

        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No Server-Side Template Injection behavior observed."
        steps: List[str] = []

        for payload, expected in SSTI_PROBES:
            # 1. Query parameter probe
            target_url = f"{base_url}{raw_path}?template={payload}&name={payload}&msg={payload}"
            obs = client.execute(method="GET", url=target_url, headers=headers)
            observations.append(obs)

            if obs.response_status == 200:
                if expected in obs.response_body and payload not in obs.response_body:
                    confirmed = True
                    summary = (
                        f"SSTI (CWE-1336) CONFIRMED: Template payload '{payload}' dynamically executed "
                        f"and evaluated to '{expected}' in response on {raw_path}."
                    )
                    steps = [
                        f"Send GET {target_url} with template expression '{payload}'",
                        f"Observe mathematical execution result '{expected}' evaluated in response body",
                    ]
                    break

            # 2. JSON Body probe for mutating methods
            if method in ("POST", "PUT", "PATCH"):
                post_url = f"{base_url}{raw_path}"
                body_payload = {"template": payload, "name": payload, "format": payload}
                post_obs = client.execute(method=method, url=post_url, headers=headers, json_body=body_payload)
                observations.append(post_obs)

                if post_obs.response_status in (200, 201):
                    if expected in post_obs.response_body and payload not in post_obs.response_body:
                        confirmed = True
                        summary = (
                            f"SSTI (CWE-1336) CONFIRMED: JSON payload '{payload}' executed in template engine "
                            f"yielding '{expected}' on {raw_path}."
                        )
                        steps = [
                            f"Send {method} {post_url} with JSON payload containing '{payload}'",
                            f"Observe template evaluation output '{expected}'",
                        ]
                        break

            if confirmed:
                break

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.95 if confirmed else 0.1,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
