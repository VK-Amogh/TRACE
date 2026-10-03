"""Injection indicator test pack."""

import urllib.parse
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient


class InjectionTestPack(TestPack):
    @property
    def name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Tests query and search parameters for dynamic SQL/command injection indicators."

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

        probes = ["' OR '1'='1", "''", "test'--"]
        observations = []
        confirmed = False
        summary = "No dynamic injection signatures observed."
        steps = []

        sql_error_patterns = [
            "syntax error",
            "sqlite3.operationalerror",
            "unrecognized token",
            "sql syntax",
            "database error",
        ]

        for probe in probes:
            encoded_probe = urllib.parse.quote(probe)
            sep = "&" if "?" in raw_path else "?"
            probe_url = f"{base_url}{raw_path}{sep}q={encoded_probe}&query={encoded_probe}&search={encoded_probe}"

            obs = client.execute(method=method, url=probe_url)
            observations.append(obs)

            body_lower = obs.response_body.lower()
            if any(pattern in body_lower for pattern in sql_error_patterns) or obs.response_status == 500:
                confirmed = True
                summary = (
                    f"Injection indicator confirmed: Probe '{probe}' on {raw_path} triggered "
                    f"unhandled database error signature or server crash."
                )
                steps = [
                    f"Send request with probe: {probe_url}",
                    "Server returned database syntax error or 500 internal server crash",
                ]
                break

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.88 if confirmed else 0.15,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
