"""Insecure Deserialization test pack (CWE-502)."""

from typing import List, Dict, Any
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation

DESER_PROBES = [
    ("pickle_base64", "gASVBAAAAAAAAACMCXRyYWNlX2JveJSULg=="),
    ("yaml_object", "!!python/object/apply:builtins.str [\"trace_probe\"]"),
    ("java_serial", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlmeFAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeA=="),
]

DESER_ERROR_SIGNATURES = [
    "unpicklingerror",
    "pickle.unpicklingerror",
    "cannot deserialize",
    "invalidstreamheader",
    "java.io.invalidclassexception",
    "constructorerror",
    "yaml.constructor",
    "unsafe deserialization",
]


class DeserializationTestPack(TestPack):
    @property
    def name(self) -> str:
        return "deserialization"

    @property
    def description(self) -> str:
        return "Validates whether endpoints accept untrusted serialized byte-streams or object definitions without schema validation."

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
        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No Insecure Deserialization vulnerabilities detected."
        steps: List[str] = []

        for probe_type, payload in DESER_PROBES:
            json_payload = {"data": payload, "object": payload, "state": payload}
            obs = client.execute(method=method, url=target_url, headers=headers, json_body=json_payload)
            observations.append(obs)

            body_lower = obs.response_body.lower()
            for sig in DESER_ERROR_SIGNATURES:
                if sig in body_lower:
                    confirmed = True
                    summary = (
                        f"Insecure Deserialization (CWE-502) CONFIRMED: Endpoint {raw_path} attempted to deserialize "
                        f"untrusted object probe ({probe_type}) resulting in deserialization parser reaction: '{sig}'."
                    )
                    steps = [
                        f"Send {method} request to {target_url} containing serialized {probe_type} payload",
                        f"Observe deserialization runtime exception trace '{sig}' in server response",
                    ]
                    break

            if confirmed:
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
