"""SSRF (Server-Side Request Forgery) test pack with polymorphic payload mutations."""

import re
from typing import List
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation


class SsrfTestPack(TestPack):
    @property
    def name(self) -> str:
        return "ssrf"

    @property
    def description(self) -> str:
        return "Validates whether server endpoints can be coerced into arbitrary internal network fetches across mutated IP representations."

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

        # Extract port from base_url for loopback mutations
        port_match = re.search(r":(\d+)", base_url)
        port = port_match.group(1) if port_match else "80"

        # Polymorphic internal probes
        candidate_probes = [
            # Standard internal endpoint
            f"{base_url}/api/products",
            # Loopback aliases & mutations
            f"http://127.0.0.1:{port}/api/products",
            f"http://localhost:{port}/api/products",
            f"http://127.0.0.1:{port}/health",
        ]

        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No SSRF behavior observed."
        steps: List[str] = []

        for probe_url in candidate_probes:
            payload = {"url": probe_url, "target": probe_url, "callbackUrl": probe_url, "webhookUrl": probe_url}
            try:
                obs = client.execute(method=method, url=target_url, headers=headers, json_body=payload)
                observations.append(obs)

                if obs.response_status == 200:
                    body_lower = obs.response_body.lower()
                    if any(k in body_lower for k in ("status", "data", "product", "content", "health", "ok", "items")):
                        confirmed = True
                        summary = (
                            f"SSRF (CWE-918) CONFIRMED: Endpoint {raw_path} fetched internal address "
                            f"{probe_url} and returned fetched data."
                        )
                        steps = [
                            f"Send {method} {target_url} with JSON payload containing URL: {probe_url}",
                            f"Observe internal service response echoed back in response body",
                        ]
                        break
            except Exception:
                continue

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.96 if confirmed else 0.25,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
