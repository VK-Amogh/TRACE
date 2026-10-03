"""Scoped runtime HTTP client for executing controlled security tests."""

import time
import httpx
from typing import Optional, Dict, Any
from trace_engine.policy.scope import ScopeGuard, ScopeViolationError
from trace_engine.runtime.observations import RuntimeObservation


class ScopedHttpClient:
    """HTTP client bound to ScopeGuard that captures comprehensive runtime observations."""

    def __init__(self, scope_guard: ScopeGuard, timeout_seconds: float = 8.0):
        self.scope_guard = scope_guard
        self.timeout = timeout_seconds

    def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> RuntimeObservation:
        """Executes request after scope validation and captures runtime observation."""
        self.scope_guard.validate_url(url)

        headers = headers or {}
        req_body_str = None
        if json_body is not None:
            import json
            req_body_str = json.dumps(json_body)
            headers["Content-Type"] = "application/json"

        start_time = time.perf_counter()
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,  # Intercept redirects for scope check
            ) as client:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    content=req_body_str,
                    data=data,
                )
                latency_ms = (time.perf_counter() - start_time) * 1000

                # Check if redirect is safe
                if resp.is_redirect and "location" in resp.headers:
                    redirect_target = resp.headers["location"]
                    # If absolute URL, validate with scope guard
                    if redirect_target.startswith("http://") or redirect_target.startswith("https://"):
                        self.scope_guard.validate_url(redirect_target)

                return RuntimeObservation(
                    request_method=method.upper(),
                    request_url=url,
                    request_headers=dict(headers),
                    request_body=req_body_str,
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:2000],  # preview up to 2KB
                    latency_ms=round(latency_ms, 2),
                )
        except ScopeViolationError:
            raise
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return RuntimeObservation(
                request_method=method.upper(),
                request_url=url,
                request_headers=dict(headers),
                request_body=req_body_str,
                response_status=0,
                response_headers={},
                response_body=f"Connection Error: {str(e)}",
                latency_ms=round(latency_ms, 2),
                observation_notes=[f"Execution exception: {e}"],
            )
