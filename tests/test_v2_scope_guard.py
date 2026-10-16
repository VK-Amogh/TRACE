"""V2 regression: target authorization vs registration (red-green).

Baseline (vulnerable): ``allow_target()`` unconditionally whitelists any
hostname, so an attacker-influenced target (external host, cloud metadata)
passes later validation. Direct connectivity probes also bypass the guard.

Fixed behavior:
- ``allow_target()`` authorizes ONLY destinations satisfying the scope
  policy (loopback, or private in private-lab mode); anything else raises.
- Registering/inventorying a host (``register_target``) grants nothing.
- ``validate_url`` re-checks DNS-resolved IPs against prohibited ranges
  (metadata/link-local/public), with an injectable resolver for tests.
- Redirect and direct-probe paths validate before any request is sent.
"""

import socket
from pathlib import Path

import pytest

from trace_engine.policy.scope import ScopeGuard, ScopeViolationError
from trace_engine.runtime.client import ScopedHttpClient


def _unresolvable(host):
    def _resolve(h):
        assert h == host, h
        raise socket.gaierror("mock: no such host")
    return _resolve


def _resolves_to(host, *ips):
    def _resolve(h):
        assert h == host, h
        return list(ips)
    return _resolve


def test_allow_target_refuses_external_host():
    g = ScopeGuard(resolver=_unresolvable("evil.com"))
    with pytest.raises(ScopeViolationError):
        g.allow_target("http://evil.com/")
    # registration alone grants nothing
    info = g.register_target("http://evil.com/")
    assert info["host"] == "evil.com"
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://evil.com/")


def test_allow_target_refuses_metadata_even_when_requested():
    g = ScopeGuard(resolver=_resolves_to("169.254.169.254", "169.254.169.254"))
    with pytest.raises(ScopeViolationError):
        g.allow_target("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://169.254.169.254/latest/meta-data/")


def test_allow_target_accepts_loopback_and_authorizes_it():
    g = ScopeGuard()
    g.allow_target("http://127.0.0.1:18080/")
    assert g.validate_url("http://127.0.0.1:18080/")
    assert g.validate_url("http://127.0.0.1:9999/other")  # loopback: any valid port


def test_allow_target_accepts_config_listed_lab_name_offline():
    # Offline lab hostname present in operator config stays usable.
    g = ScopeGuard(
        allowed_hosts=["my-lab.local"],
        allowed_ports=[80],
        resolver=_unresolvable("my-lab.local"),
    )
    g.allow_target("http://my-lab.local:8443/api")
    assert g.validate_url("http://my-lab.local:8443/api")


def test_registered_but_unauthorized_host_stays_blocked():
    g = ScopeGuard(resolver=_unresolvable("evil.com"))
    g.register_target("http://evil.com:8000/path")
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://evil.com:8000/path")


def test_dns_resolving_to_public_blocks_allowlisted_name():
    # Even a listed name is refused when it currently resolves to public space.
    g = ScopeGuard(
        allowed_hosts=["sneaky.example"],
        resolver=_resolves_to("sneaky.example", "93.184.216.34"),
    )
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://sneaky.example/")


def test_dns_resolving_to_loopback_ok_for_listed_name():
    g = ScopeGuard(
        allowed_hosts=["lab.example"],
        resolver=_resolves_to("lab.example", "127.0.0.1"),
    )
    assert g.validate_url("http://lab.example:5000/")


def test_private_lab_mode_allows_private_ip_literal():
    g = ScopeGuard(mode="private-lab", resolver=_resolves_to("10.0.0.5", "10.0.0.5"))
    g.allow_target("http://10.0.0.5:8000/")
    assert g.validate_url("http://10.0.0.5:8000/")


def test_private_ip_blocked_in_default_local_mode():
    g = ScopeGuard(resolver=_resolves_to("10.0.0.5", "10.0.0.5"))
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://10.0.0.5:8000/")


def test_alt_ip_forms_of_loopback_treated_as_loopback():
    g = ScopeGuard()
    assert g.validate_url("http://127.1:8000/")
    assert g.validate_url("http://2130706433:8000/")


def test_alt_ip_form_of_metadata_blocked():
    g = ScopeGuard()
    # 0xA9FEA9FE == 169.254.169.254
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://0xA9FEA9FE/")


def test_explicit_port_zero_is_rejected_not_defaulted():
    g = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://127.0.0.1:0/")
    with pytest.raises(ScopeViolationError):
        g.allow_target("http://127.0.0.1:0/")


def test_userinfo_host_is_the_connect_target():
    g = ScopeGuard()
    # credentials part is not the host: this connects to loopback -> allowed
    assert g.validate_url("http://user:pass@127.0.0.1:8000/")
    # ...while the real host here is external -> blocked
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://127.0.0.1@evil.com/")


def test_ipv4_mapped_ipv6_loopback_is_conservatively_blocked():
    # ::ffff:127.0.0.1 is loopback-equivalent but not a loopback literal;
    # the guard fails closed here. Operators should use 127.0.0.1.
    g = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        g.validate_url("http://[::ffff:127.0.0.1]:8000/")


def test_redirect_to_disallowed_host_is_rejected_before_fetch():
    from unittest.mock import MagicMock, patch

    g = ScopeGuard()
    client = ScopedHttpClient(scope_guard=g)
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"location": "http://evil.com/steal"}
    with patch("httpx.Client.request", return_value=mock_resp):
        with pytest.raises(ScopeViolationError):
            client.execute(method="GET", url="http://127.0.0.1:18080/go")


def test_initial_url_validated_before_request():
    from unittest.mock import patch

    g = ScopeGuard()
    client = ScopedHttpClient(scope_guard=g)
    with patch("httpx.Client.request") as req:
        with pytest.raises(ScopeViolationError):
            client.execute(method="GET", url="http://evil.com/x")
        req.assert_not_called()


def test_probe_helper_validates_before_fetch():
    from unittest.mock import patch

    from trace_engine.runtime.client import probe_target_online

    g = ScopeGuard()
    with patch("httpx.Client") as cli:
        assert probe_target_online(g, "http://evil.com/") is False
        cli.assert_not_called()


def test_probe_helper_online_loopback():
    from unittest.mock import MagicMock, patch

    from trace_engine.runtime.client import probe_target_online

    g = ScopeGuard()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("httpx.Client") as cli:
        cli.return_value.__enter__.return_value.get.return_value = mock_resp
        assert probe_target_online(g, "http://127.0.0.1:18080/") is True
