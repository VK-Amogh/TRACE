"""Path Traversal and Arbitrary File Access test pack (CWE-22 / CWE-73)."""

import re
from typing import List, Dict, Any
from trace_engine.testpacks.base import TestPack, TestContext, TestExecutionResult
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\Windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../etc/passwd%00.png",
]

SENSITIVE_SIGNATURES = [
    "root:x:",
    "daemon:x:",
    "[extensions]",
    "[fonts]",
    "[files]",
    "for 16-bit app support",
]

FS_ERROR_MARKERS = [
    "filenotfoundexception",
    "no such file or directory",
    "java.io.filenotfound",
    "enoent",
    "open_basedir restriction",
]


class PathTraversalTestPack(TestPack):
    @property
    def name(self) -> str:
        return "path_traversal"

    @property
    def description(self) -> str:
        return "Validates whether file/path parameters allow escaping directory boundaries to access arbitrary files."

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

        token = context.active_tokens.get("user-a", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        observations: List[RuntimeObservation] = []
        confirmed = False
        summary = "No path traversal vulnerability detected."
        steps: List[str] = []

        for payload in TRAVERSAL_PAYLOADS:
            # 1. Path parameter substitution if endpoint contains {id} or {path} or {file}
            if "{" in raw_path:
                probed_path = re.sub(r"\{[a-zA-Z0-9_]+\}", payload, raw_path)
                target_url = f"{base_url}{probed_path}"
                obs = client.execute(method=method, url=target_url, headers=headers)
                observations.append(obs)
            else:
                # 2. Query parameter probe
                target_url = f"{base_url}{raw_path}?file={payload}&path={payload}"
                obs = client.execute(method=method, url=target_url, headers=headers)
                observations.append(obs)

            if obs.response_status in (200, 500):
                body_lower = obs.response_body.lower()
                for sig in SENSITIVE_SIGNATURES:
                    if sig.lower() in body_lower:
                        confirmed = True
                        summary = (
                            f"Path Traversal (CWE-22) CONFIRMED: Endpoint {raw_path} returned contents of "
                            f"system file when supplied with traversal payload '{payload}'."
                        )
                        steps = [
                            f"Send {method} request to {target_url} with traversal sequence '{payload}'",
                            f"Observe leaked file system contents containing '{sig}'",
                        ]
                        break

                if not confirmed and obs.response_status == 500:
                    for marker in FS_ERROR_MARKERS:
                        if marker in body_lower:
                            confirmed = True
                            summary = (
                                f"Path Traversal Indicator: File system path error disclosure '{marker}' "
                                f"triggered on {raw_path} using traversal payload '{payload}'."
                            )
                            steps = [
                                f"Send {method} {target_url} with traversal probe '{payload}'",
                                f"Observe underlying file system path disclosure error '{marker}'",
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
