"""Scoped runtime HTTP client for executing controlled security tests."""

import time
import httpx
from typing import Callable, Optional, Dict, Any
from trace_engine.policy.scope import ScopeGuard, ScopeViolationError
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.runtime.redact import redact_headers


class RequestBudgetExceeded(Exception):
    """Raised when a scan has used its configured request budget."""


class ScopedHttpClient:
    """HTTP client bound to ScopeGuard that captures comprehensive runtime observations.

    ``max_requests`` caps the total requests this client will send (a hard
    ceiling on probe traffic); ``recorder`` receives every observation, for
    the evidence log. Persisted observations never carry credentials.
    """

    def __init__(
        self,
        scope_guard: ScopeGuard,
        timeout_seconds: float = 8.0,
        max_requests: Optional[int] = None,
        recorder: Optional[Callable[[RuntimeObservation], None]] = None,
    ):
        self.scope_guard = scope_guard
        self.timeout = timeout_seconds
        self.max_requests = max_requests
        self.recorder = recorder
        self.request_count = 0

    def _emit(self, obs: RuntimeObservation) -> RuntimeObservation:
        if self.recorder is not None:
            try:
                self.recorder(obs)
            except Exception:  # noqa: BLE001 - evidence logging must never break a scan
                pass
        return obs

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
        if self.max_requests is not None and self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"request budget of {self.max_requests} reached")
        self.request_count += 1

        headers = headers or {}
        req_body_str = None
        if json_body is not None:
            import json
            req_body_str = json.dumps(json_body)
            headers["Content-Type"] = "application/json"

        start_time = time.perf_counter()
        try:
            # httpx forbids content + data together: JSON body wins when present.
            request_kwargs: Dict[str, Any] = {
                "method": method.upper(),
                "url": url,
                "headers": headers,
            }
            if req_body_str is not None:
                request_kwargs["content"] = req_body_str
            elif data is not None:
                request_kwargs["data"] = data
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,  # Intercept redirects for scope check
            ) as client:
                resp = client.request(**request_kwargs)
                latency_ms = (time.perf_counter() - start_time) * 1000

                # Check if redirect is safe
                if resp.is_redirect and "location" in resp.headers:
                    redirect_target = resp.headers["location"]
                    import urllib.parse
                    resolved_redirect = urllib.parse.urljoin(url, redirect_target)
                    self.scope_guard.validate_url(resolved_redirect)

                return self._emit(RuntimeObservation(
                    request_method=method.upper(),
                    request_url=url,
                    request_headers=redact_headers(headers),
                    request_body=req_body_str,
                    response_status=resp.status_code,
                    response_headers=redact_headers(dict(resp.headers)),
                    response_body=resp.text[:2000],  # preview up to 2KB
                    latency_ms=round(latency_ms, 2),
                ))
        except ScopeViolationError:
            raise
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return self._emit(RuntimeObservation(
                request_method=method.upper(),
                request_url=url,
                request_headers=redact_headers(headers),
                request_body=req_body_str,
                response_status=0,
                response_headers={},
                response_body=f"Connection Error: {str(e)}",
                latency_ms=round(latency_ms, 2),
                observation_notes=[f"Execution exception: {e}"],
            ))


def probe_target_online(
    scope_guard: ScopeGuard,
    url: str,
    timeout_seconds: float = 1.5,
) -> bool:
    """Guarded liveness probe: validate the URL before any request is sent.

    Returns True when the target answers, False when it is offline,
    unreachable, or rejected by the scope policy. Scope rejections fail
    safe (False) instead of raising so scan flows degrade to static-only
    mode rather than crashing -- or fetching -- an unauthorized target.
    """
    try:
        scope_guard.validate_url(url)
    except ScopeViolationError:
        return False
    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            client.get(url)
            return True
    except Exception:
        return False
