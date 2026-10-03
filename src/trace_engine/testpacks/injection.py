"""Injection indicator test pack with polymorphic SQLi and Command Injection mutations."""

import re
import urllib.parse
from typing import List
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation

INJECTION_PROBES = [
    # Classic SQLi Boolean
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    # SQL Syntax breakers
    "'",
    "''",
    "test'--",
    "';--",
    # Stacked queries / Command delimiters
    "; cat /etc/passwd",
    "| whoami",
    "$(id)",
]

SQL_ERROR_PATTERNS = [
    "syntax error",
    "sqlite3.operationalerror",
    "unrecognized token",
    "sql syntax",
    "database error",
    "pg_query",
    "ora-01756",
    "mysql_fetch",
    "sqlstate",
    "odbc sql server driver",
    "pdoexception",
    "unterminated quotation mark",
    "unclosed quotation mark",
]


class InjectionTestPack(TestPack):
    @property
    def name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Tests query, path, and body parameters for dynamic SQL/command injection vulnerabilities across mutated probe varieties."

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

        clean_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "1", raw_path)
        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No dynamic injection signatures observed."
        steps: List[str] = []

        for probe in INJECTION_PROBES:
            encoded_probe = urllib.parse.quote(probe)
            sep = "&" if "?" in clean_path else "?"
            probe_url = f"{base_url}{clean_path}{sep}q={encoded_probe}&query={encoded_probe}&search={encoded_probe}&id={encoded_probe}"

            # 1. Query probe
            obs = client.execute(method=method, url=probe_url, headers=headers)
            observations.append(obs)

            body_lower = obs.response_body.lower()
            matched_error = next((pat for pat in SQL_ERROR_PATTERNS if pat in body_lower), None)

            if matched_error or (obs.response_status == 500 and "error" in body_lower):
                confirmed = True
                detail = f"database error signature '{matched_error}'" if matched_error else "unhandled 500 server crash"
                summary = (
                    f"Injection vulnerability confirmed: Probe '{probe}' on {raw_path} triggered "
                    f"{detail} indicating unparameterized query execution."
                )
                steps = [
                    f"Send request with probe: {probe_url}",
                    f"Observe server reaction: {detail}",
                ]
                break

            # 2. Body probe for mutating requests
            if method in ("POST", "PUT", "PATCH"):
                body_probe = {"q": probe, "query": probe, "search": probe, "name": probe}
                body_obs = client.execute(
                    method=method,
                    url=f"{base_url}{clean_path}",
                    headers=headers,
                    json_body=body_probe,
                )
                observations.append(body_obs)
                body_res_lower = body_obs.response_body.lower()
                matched_body_err = next((pat for pat in SQL_ERROR_PATTERNS if pat in body_res_lower), None)
                if matched_body_err or (body_obs.response_status == 500 and "error" in body_res_lower):
                    confirmed = True
                    detail = f"database error signature '{matched_body_err}'" if matched_body_err else "unhandled 500 server crash"
                    summary = (
                        f"Injection vulnerability confirmed in request body: Probe '{probe}' on {raw_path} triggered "
                        f"{detail}."
                    )
                    steps = [
                        f"Send {method} to {base_url}{clean_path} with JSON body payload containing '{probe}'",
                        f"Observe database reaction: {detail}",
                    ]
                    break

        return TestExecutionResult(
            testpack_name=self.name,
            hypothesis_id=hypothesis.id,
            confirmed=confirmed,
            confidence=0.92 if confirmed else 0.15,
            summary=summary,
            observations=observations,
            reproduction_steps=steps,
        )
