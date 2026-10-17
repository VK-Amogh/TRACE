"""Scope Guard for enforcing local-only and lab-authorized boundaries.

Security model (authorization vs registration):

- Registration (``register_target``) only parses and inventories a URL. It
  grants no permission; a registered-but-unauthorized host stays blocked.
- Authorization happens in exactly two ways: operator configuration
  (``allowed_hosts``/``allowed_ports`` constructor arguments) and an
  explicit operator-approved call to ``allow_target``. ``allow_target`` now
  enforces the scope policy instead of whitelisting arbitrary hosts, so it
  must only be called on operator-approved URLs -- never on URLs extracted
  from scanned code, redirects, or model output.
- Every request path (``ScopedHttpClient`` and direct liveness probes) must
  call ``validate_url`` before connecting. ``validate_url`` additionally
  resolves hostnames (injectable resolver for tests) and refuses
  destinations whose current addresses fall in prohibited ranges
  (cloud metadata, link-local, public space), which also mitigates naive
  DNS-rebinding of an allowlisted name.

Known limitation: validation and connection are separate steps, so an
address change between ``validate_url`` and the socket connect (TOCTOU)
cannot be fully closed at this layer. Full pinning would require
connection-level IP checks inside the HTTP client; the residual risk is
documented and redirect targets are always revalidated.
"""

import socket
import struct
from urllib.parse import urlparse
from typing import Callable, Dict, List, Optional, Set
import ipaddress


class ScopeViolationError(Exception):
    """Raised when an action violates the defined target scope."""
    pass


# Hostnames that must never be authorized: cloud metadata and well-known
# internal-metadata names. IP-range checks below cover the literal forms;
# this set covers the name forms (also when DNS is unavailable).
_ALWAYS_BLOCKED_NAMES = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.google",
        "instance-data",
        "metadata.azure.com",
        "metadata.aws.internal",
    }
)

_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})


def _default_resolver(hostname: str) -> List[str]:
    """Resolve *hostname* to a list of IP-address strings."""
    infos = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    addresses: List[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in addresses:
            addresses.append(ip)
    return addresses


def _normalize_ip(hostname: str) -> Optional[ipaddress._BaseAddress]:
    """Parse *hostname* as an IP, including legacy IPv4 forms.

    Besides standard notation, handles integer (``2130706433``), hex
    (``0x7f.0.0.1``), octal, and short dotted forms (``127.1``) with
    ``inet_aton`` semantics so alternate loopback spellings are treated as
    loopback (and alternate metadata spellings as prohibited).
    """
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(hostname)
        return ipaddress.IPv4Address(struct.unpack("!I", packed)[0])
    except (OSError, struct.error):
        return None


class ScopeGuard:
    """Enforces strict boundaries to ensure tests only execute against approved local/lab targets."""

    def __init__(
        self,
        allowed_hosts: List[str] = None,
        allowed_ports: List[int] = None,
        mode: str = "local",
        resolver: Callable[[str], List[str]] = None,
    ):
        self.mode = mode
        self.allowed_hosts: Set[str] = set(
            h.lower() for h in (allowed_hosts or ["localhost", "127.0.0.1", "0.0.0.0", "::1"])
        )
        self.allowed_ports: Set[int] = set(
            allowed_ports or [80, 443, 3000, 5000, 8000, 8080, 18080]
        )
        # Hosts/ports authorized through explicit operator approval,
        # tracked per host so one failed call cannot revoke another host.
        self.explicit_hosts: Set[str] = set()
        self.explicit_ports: Dict[str, Set[int]] = {}
        self._resolver = resolver or _default_resolver
        # Inventory only; grants no permission (see register_target).
        self.registered_targets: List[Dict[str, str]] = []

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _normalize_host(hostname: str) -> str:
        host = (hostname or "").strip().lower()
        if host.endswith("."):
            host = host[:-1]
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            raise ScopeViolationError(f"Invalid URL host: {hostname!r}")
        return host

    def _check_address_policy(self, ip: ipaddress._BaseAddress, hostname: str) -> None:
        """Refuse prohibited address categories regardless of allowlists."""
        if getattr(ip, "ipv4_mapped", None) is not None:
            # Mapped forms (::ffff:127.0.0.1) are loopback-equivalent but
            # not loopback literals: fail closed and tell the operator to
            # use 127.0.0.1 explicitly.
            raise ScopeViolationError(
                f"Target host '{hostname}' uses an IPv4-mapped IPv6 form; "
                "use the literal loopback address 127.0.0.1 instead."
            )
        if ip.is_loopback:
            return
        # 0.0.0.0 is kept as a loopback-equivalent target for operator
        # convenience (requests to it reach localhost in practice).
        if ip.is_unspecified:
            return
        if (
            ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_global
        ):
            raise ScopeViolationError(
                f"Target host '{hostname}' resolves to prohibited address '{ip}'. "
                "Link-local/cloud-metadata/public destinations are blocked by TRACE ScopeGuard."
            )
        if ip.is_private and self.mode != "private-lab":
            raise ScopeViolationError(
                f"Target host '{hostname}' is not within local scope "
                f"(resolved '{ip}'). External network requests are blocked by TRACE ScopeGuard."
            )
        if not ip.is_private:
            raise ScopeViolationError(
                f"Target host '{hostname}' is blocked by TRACE ScopeGuard. "
                "Only approved local targets are permitted."
            )

    def _check_resolved_addresses(self, hostname: str) -> None:
        """Re-check currently-resolved IPs of an authorized name.

        Fail-open only when the name cannot be resolved at all (offline lab
        workflow); any successfully resolved address must satisfy policy.
        """
        try:
            addresses = self._resolver(hostname)
        except Exception:
            return  # unresolvable: name-allowlist decision stands (offline use)
        if not addresses:
            return
        for addr in addresses:
            ip = _normalize_ip(addr)
            if ip is None:
                raise ScopeViolationError(
                    f"Target host '{hostname}' resolved to unparseable address '{addr}'."
                )
            self._check_address_policy(ip, hostname)

    def _name_authorized(self, hostname: str) -> bool:
        return hostname in self.allowed_hosts or hostname in self.explicit_hosts

    # -- public API ------------------------------------------------------

    def register_target(self, url: str) -> Dict[str, str]:
        """Inventory a URL without granting any permission.

        Returns the parsed host/port record. A registered target remains
        blocked until it satisfies ``validate_url`` (operator configuration
        or explicit ``allow_target`` approval plus address policy).
        """
        parsed = urlparse(url)
        hostname = self._normalize_host(parsed.hostname or "")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            port = -1
        record = {"url": url, "host": hostname, "port": str(port), "scheme": parsed.scheme}
        self.registered_targets.append(record)
        return record

    def validate_url(self, url: str) -> bool:
        """Validates that a URL is strictly within the allowed target scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(f"Unsupported URL scheme: {parsed.scheme}")

        hostname = self._normalize_host(parsed.hostname or "")
        if not hostname:
            raise ScopeViolationError(f"Invalid URL host: {url}")
        if hostname in _ALWAYS_BLOCKED_NAMES:
            raise ScopeViolationError(
                f"Target host '{hostname}' is a prohibited metadata/internal destination."
            )

        ip_literal = _normalize_ip(hostname)
        if ip_literal is not None:
            # Literal address: must satisfy policy on its face.
            self._check_address_policy(ip_literal, hostname)
        elif not self._name_authorized(hostname):
            raise ScopeViolationError(
                f"Target host '{hostname}' is blocked by TRACE ScopeGuard. Only approved local targets are permitted."
            )
        else:
            # Authorized name: re-check what it currently resolves to.
            self._check_resolved_addresses(hostname)

        try:
            raw_port = parsed.port
        except ValueError as e:
            raise ScopeViolationError(f"Invalid URL port: {e}")
        if raw_port == 0:
            # NB: ``parsed.port or default`` would silently turn an explicit
            # ":0" into port 80, so the validated URL would differ from the
            # requested one. Port 0 is never a valid connect target.
            raise ScopeViolationError("Invalid TCP port: 0")
        port = raw_port or (443 if parsed.scheme == "https" else 80)

        loopback = ip_literal is not None and (ip_literal.is_loopback or ip_literal.is_unspecified)
        if hostname in _LOOPBACK_NAMES:
            loopback = True
        if not loopback and port not in self.allowed_ports and port not in self.explicit_ports.get(hostname, ()):
            raise ScopeViolationError(
                f"Target port {port} is not in allowed ports list: {sorted(list(self.allowed_ports | set().union(*self.explicit_ports.values())))}"
            )
        if not (1 <= port <= 65535):
            raise ScopeViolationError(f"Invalid TCP port: {port}")

        return True

    def _authorizable(self, hostname: str) -> None:
        """Check a host may receive explicit permission (no recording)."""
        if hostname in _ALWAYS_BLOCKED_NAMES:
            raise ScopeViolationError(
                f"Target host '{hostname}' is a prohibited metadata/internal destination."
            )
        ip_literal = _normalize_ip(hostname)
        if ip_literal is not None:
            self._check_address_policy(ip_literal, hostname)
            return
        if hostname in self.allowed_hosts or hostname in self.explicit_hosts:
            self._check_resolved_addresses(hostname)
            return
        # Unknown name: resolve first and judge the addresses. An operator
        # pointing at a fresh lab host must be able to authorize it; an
        # unresolvable name stays refused so nothing can be smuggled in
        # while offline.
        try:
            addresses = self._resolver(hostname)
        except Exception:
            addresses = []
        policy_ok = False
        for addr in addresses:
            ip = _normalize_ip(addr)
            if ip is None:
                raise ScopeViolationError(
                    f"Target host '{hostname}' resolved to unparseable address '{addr}'."
                )
            self._check_address_policy(ip, hostname)
            policy_ok = True
        if not policy_ok:
            raise ScopeViolationError(
                f"Target host '{hostname}' is blocked by TRACE ScopeGuard. Only approved local targets are permitted."
            )

    def allow_target(self, url: str) -> None:
        """Authorize an explicitly operator-approved target URL.

        Unlike registration, this records permission -- but only after the
        destination satisfies the scope policy. Raises
        :class:`ScopeViolationError` for external, metadata, or otherwise
        prohibited destinations. Must only be called on operator-approved
        URLs (CLI ``--target``, configured target, MCP ``target``); never on
        URLs extracted from scanned code, redirects, or model output.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(f"Unsupported URL scheme: {parsed.scheme}")
        hostname = self._normalize_host(parsed.hostname or "")
        if not hostname:
            raise ScopeViolationError(f"Invalid URL host: {url}")
        try:
            raw_port = parsed.port
        except ValueError as e:
            raise ScopeViolationError(f"Invalid URL port: {e}")
        if raw_port == 0:
            raise ScopeViolationError("Invalid TCP port: 0")
        port = raw_port or (443 if parsed.scheme == "https" else 80)
        if not (1 <= port <= 65535):
            raise ScopeViolationError(f"Invalid TCP port: {port}")
        # Host policy check first (no permission recorded on failure).
        self._authorizable(hostname)
        had_host = hostname in self.explicit_hosts
        host_ports = self.explicit_ports.setdefault(hostname, set())
        had_port = port in host_ports
        self.explicit_hosts.add(hostname)
        host_ports.add(port)
        # Full validation (port policy included) must pass with the new
        # permission recorded; roll back only what this call added.
        try:
            self.validate_url(url)
        except ScopeViolationError:
            if not had_port:
                self.explicit_ports.get(hostname, set()).discard(port)
            if not had_host and not self.explicit_ports.get(hostname):
                self.explicit_hosts.discard(hostname)
            raise
