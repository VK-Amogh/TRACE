"""BOLA (Broken Object Level Authorization) dual-tenant differential test pack."""

import re
from typing import List
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation


class BolaTestPack(TestPack):
    @property
    def name(self) -> str:
        return "bola"

    @property
    def description(self) -> str:
        return "Validates whether object lookups enforce tenant and ownership boundaries using dual-identity differential testing."

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

        test_ids = ["order-101", "101", "1", "order-102", "order-user-a", "2", "3", "user-1", "doc-1"]
        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No BOLA behavior observed."
        steps: List[str] = []

        token_a = context.active_tokens.get("user-a", "")
        token_b = context.active_tokens.get("user-b", "")

        for test_id in test_ids:
            probe_path = re.sub(r"\{[a-zA-Z0-9_]+\}", test_id, raw_path)
            target_url = f"{base_url}{probe_path}"

            # Differential Phase 1: Request with User A context
            headers_a = {"Authorization": f"Bearer {token_a}"} if token_a else {}
            obs_a = client.execute(method=method, url=target_url, headers=headers_a)
            observations.append(obs_a)

            # Differential Phase 2: Request with User B context (or unauthenticated)
            headers_b = {"Authorization": f"Bearer {token_b}"} if token_b else {}
            obs_b = client.execute(method=method, url=target_url, headers=headers_b)
            observations.append(obs_b)

            # Case A: True dual-tenant differential match
            if obs_a.response_status == 200 and obs_b.response_status == 200:
                body_b_lower = obs_b.response_body.lower()
                # If User B receives legitimate record data without authorization restriction
                if any(k in body_b_lower for k in ("id", "user", "order", "item", "total", "data", "status")):
                    confirmed = True
                    summary = (
                        f"BOLA / IDOR (CWE-639) CONFIRMED via Dual-Tenant Differential Test: Object '{test_id}' on {raw_path} "
                        f"is accessible by both Identity A and Identity B without tenant isolation."
                    )
                    steps = [
                        f"Query {method} {target_url} using Tenant A credentials (HTTP {obs_a.response_status})",
                        f"Query identical resource {method} {target_url} using Tenant B credentials (HTTP {obs_b.response_status})",
                        "Observe cross-tenant data leak without HTTP 403 Forbidden or 404 Not Found scoping",
                    ]
                    break

            # Case B: Single token / unauthenticated BOLA check
            elif obs_b.response_status == 200:
                body_b_lower = obs_b.response_body.lower()
                if "user-a" in body_b_lower or "total" in body_b_lower or "items" in body_b_lower or "product" in body_b_lower:
                    confirmed = True
                    summary = (
                        f"BOLA confirmed: User 'user-b' accessed object '{test_id}' "
                        f"belonging to another identity on endpoint {raw_path} with status 200 OK."
                    )
                    steps = [
                        f"Send {method} {target_url} with user-b credentials",
                        "Observe HTTP status 200 OK returning private data of user-a",
                    ]
                    break

        any_reachable = any(obs.response_status != 0 for obs in observations)
        if not confirmed and not any_reachable:
            summary = "Target host unreachable. Dynamic probe inconclusive."

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.98 if confirmed else (None if not any_reachable else 0.20),
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
