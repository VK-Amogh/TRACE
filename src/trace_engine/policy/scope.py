"""Scope Guard for enforcing local-only and lab-authorized boundaries."""

from urllib.parse import urlparse
from typing import List, Set
import ipaddress


class ScopeViolationError(Exception):
    """Raised when an action violates the defined target scope."""
    pass


class ScopeGuard:
    """Enforces strict boundaries to ensure tests only execute against approved local/lab targets."""

    def __init__(
        self,
        allowed_hosts: List[str] = None,
        allowed_ports: List[int] = None,
        mode: str = "local",
    ):
        self.mode = mode
        self.allowed_hosts: Set[str] = set(
            allowed_hosts or ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        )
        self.allowed_ports: Set[int] = set(
            allowed_ports or [80, 443, 3000, 5000, 8000, 8080, 18080]
        )

    def validate_url(self, url: str) -> bool:
        """Validates that a URL is strictly within the allowed target scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(f"Unsupported URL scheme: {parsed.scheme}")

        hostname = parsed.hostname or ""
        if not hostname:
            raise ScopeViolationError(f"Invalid URL host: {url}")

        # Check hostname directly
        if hostname.lower() in self.allowed_hosts:
            pass
        else:
            # Check if it is a private IP in private-lab mode
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_loopback or (self.mode == "private-lab" and ip.is_private):
                    pass
                else:
                    raise ScopeViolationError(
                        f"Target host '{hostname}' is not within local/private scope. External network requests are blocked by TRACE ScopeGuard."
                    )
            except ValueError:
                # Hostname is not an IP address and not in allowed hosts
                raise ScopeViolationError(
                    f"Target host '{hostname}' is blocked by TRACE ScopeGuard. Only approved local targets are permitted."
                )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.allowed_ports:
            raise ScopeViolationError(
                f"Target port {port} is not in allowed ports list: {sorted(list(self.allowed_ports))}"
            )

        return True
