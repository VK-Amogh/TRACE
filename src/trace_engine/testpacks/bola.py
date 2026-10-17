"""BOLA (Broken Object Level Authorization) dual-tenant differential test pack."""

import re
from typing import List
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.testpacks.canary import attacker_sees_owner_markers
from trace_engine.security.verdict import score_response_pair
from trace_engine.testpacks.idshapes import mutations
from trace_engine.testpacks.stateful import (
    collection_path,
    extract_created_id,
    extract_ids,
    trailing_param,
)


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

        guess_ids = ["order-101", "101", "1", "order-102", "order-user-a", "2", "3", "user-1", "doc-1"]
        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No BOLA behavior observed."
        steps: List[str] = []

        # Owner discovery: the identities' own objects beat guessed IDs. List the
        # parent collection as identity A (read-only) and, when the operator opted
        # into stateful testing, create a throwaway object if none exists.
        owner_ids: List[str] = []
        created_id = None
        collection = collection_path(raw_path)
        param = trailing_param(raw_path)
        if collection and context.headers_for("user-a"):
            list_obs = client.execute(
                method="GET", url=f"{base_url}{collection}", headers=context.headers_for("user-a")
            )
            observations.append(list_obs)
            if list_obs.response_status == 200:
                owner_ids = extract_ids(list_obs.response_body, param)
            hint = context.api_hints.get(f"POST {collection}")
            if not owner_ids and context.stateful and hint and hint.get("body") is not None:
                create_obs = client.execute(
                    method="POST", url=f"{base_url}{collection}",
                    headers=context.headers_for("user-a"), json_body=hint["body"],
                )
                observations.append(create_obs)
                if create_obs.response_status in (200, 201):
                    created_id = extract_created_id(create_obs.response_body, param)
                    if created_id:
                        owner_ids = [created_id]
        mutated: List[str] = []
        for oid in owner_ids[:1]:
            mutated.extend(mutations(oid))
        test_ids = list(dict.fromkeys(owner_ids + mutated + guess_ids))


        for test_id in test_ids:
            probe_path = re.sub(r"\{[a-zA-Z0-9_]+\}", lambda _: test_id, raw_path)
            target_url = f"{base_url}{probe_path}"

            # Differential Phase 1: Request with User A context
            headers_a = context.headers_for("user-a")
            obs_a = client.execute(method=method, url=target_url, headers=headers_a)
            observations.append(obs_a)

            # Differential Phase 2: Request with User B context (or unauthenticated)
            headers_b = context.headers_for("user-b")
            obs_b = client.execute(method=method, url=target_url, headers=headers_b)
            observations.append(obs_b)

            # Ground-truth differential: owner-baseline markers leaking to the
            # attacker prove cross-tenant access (canary oracle, not keywords).
            if obs_a.response_status == 200 and obs_b.response_status == 200:
                diff = attacker_sees_owner_markers(obs_a.response_body, obs_b.response_body)
                if diff["confirmed"]:
                    confirmed = True
                    summary = (
                        f"BOLA / IDOR (CWE-639) CONFIRMED via owner-marker leak: Object '{test_id}' on "
                        f"{raw_path} exposes identity-A markers ({', '.join(diff['leaked'][:3])}) to identity B."
                    )
                    steps = [
                        f"Query {method} {target_url} using Tenant A credentials (HTTP {obs_a.response_status})",
                        f"Query identical resource {method} {target_url} using Tenant B credentials (HTTP {obs_b.response_status})",
                        f"Observe Tenant A markers in Tenant B response: {', '.join(diff['leaked'][:3])}",
                    ]
                    break

            # Case A: True dual-tenant differential match
            if obs_a.response_status == 200 and obs_b.response_status == 200:
                body_b_lower = obs_b.response_body.lower()
                # If User B receives legitimate record data without authorization restriction
                if any(k in body_b_lower for k in ("id", "user", "order", "item", "total", "data", "status")):
                    # Multi-signal gate: a CLEAR verdict vetoes the keyword
                    # heuristic (kills {"status": "ok"} false positives).
                    gate = score_response_pair(
                        obs_a.response_status,
                        obs_a.response_body,
                        obs_b.response_status,
                        obs_b.response_body,
                    )
                    if gate.verdict == "CLEAR":
                        continue
                    confirmed = True
                    summary = (
                        f"BOLA / IDOR (CWE-639) CONFIRMED via Dual-Tenant Differential Test: Object '{test_id}' on {raw_path} "
                        f"is accessible by both Identity A and Identity B without tenant isolation "
                        f"(verdict {gate.verdict} {gate.score})."
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

        # Existence oracle: a denied-but-existing object that answers differently
        # from a missing one lets an attacker enumerate real identifiers.
        if not confirmed and owner_ids and context.headers_for("user-b"):
            real = re.sub(r"\{[a-zA-Z0-9_]+\}", lambda _: owner_ids[0], raw_path)
            fake = re.sub(r"\{[a-zA-Z0-9_]+\}", lambda _: "trace-nonexistent-000", raw_path)
            denied = client.execute(method=method, url=f"{base_url}{real}", headers=context.headers_for("user-b"))
            missing = client.execute(method=method, url=f"{base_url}{fake}", headers=context.headers_for("user-b"))
            observations.extend([denied, missing])
            if denied.response_status in (401, 403) and missing.response_status == 404:
                summary += (
                    f" Existence oracle: foreign object returns HTTP {denied.response_status} but "
                    f"a missing one returns 404, so valid identifiers can be enumerated."
                )

        # Teardown of any object this run created (stateful mode only).
        if created_id and context.headers_for("user-a") and f"DELETE {raw_path}" in context.api_hints:
            del_path = re.sub(r"\{[a-zA-Z0-9_]+\}", lambda _: created_id, raw_path)
            observations.append(
                client.execute(method="DELETE", url=f"{base_url}{del_path}", headers=context.headers_for("user-a"))
            )

        if not confirmed and not any_reachable:
            summary = "Target host unreachable. Dynamic probe inconclusive."

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.98 if confirmed else (0.0 if not any_reachable else 0.20),
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
