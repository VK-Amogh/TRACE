"""Unit tests for the remaining testpacks: bola, cors, mass-assignment,
path-traversal, ssti, deserialization, authentication.

All runtime I/O is stubbed: packs must return well-formed results both when
the target answers and when it is unreachable.
"""

from trace_engine.testpacks.base import TestContext, TestExecutionResult
from trace_engine.testpacks.bola import BolaTestPack
from trace_engine.testpacks.cors import CorsTestPack
from trace_engine.testpacks.mass_assignment import MassAssignmentTestPack
from trace_engine.testpacks.path_traversal import PathTraversalTestPack
from trace_engine.testpacks.ssti import SstiTestPack
from trace_engine.testpacks.deserialization import DeserializationTestPack
from trace_engine.testpacks.authentication import AuthenticationTestPack
from trace_engine.testpacks.registry import default_registry
from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory
from trace_engine.runtime.observations import RuntimeObservation


def _obs(status=200, body="ok"):
    return RuntimeObservation(
        request_method="GET",
        request_url="http://127.0.0.1:18080/api/x",
        response_status=status,
        response_body=body,
        latency_ms=5.0,
    )


class _StubClient:
    def __init__(self, status=200, body="ok"):
        self._status = status
        self._body = body
        self.calls = []

    def execute(self, method="GET", url="", headers=None, **kwargs):
        self.calls.append((method, url))
        return _obs(self._status, self._body)


def _ctx():
    return TestContext(target_base_url="http://127.0.0.1:18080", active_tokens={})


def _hyp(category, display="GET /api/items/{id}", pack="bola"):
    return SecurityHypothesis(
        id="HYP-001",
        category=category,
        endpoint_id="ep_1",
        endpoint_display=display,
        title="t",
        description="d",
        recommended_test_pack=pack,
    )


PACK_CASES = [
    (BolaTestPack(), VulnerabilityCategory.BOLA, "bola"),
    (CorsTestPack(), VulnerabilityCategory.CORS, "cors"),
    (MassAssignmentTestPack(), VulnerabilityCategory.MASS_ASSIGNMENT, "mass_assignment"),
    (PathTraversalTestPack(), VulnerabilityCategory.PATH_TRAVERSAL, "path_traversal"),
    (SstiTestPack(), VulnerabilityCategory.SSTI, "ssti"),
    (DeserializationTestPack(), VulnerabilityCategory.DESERIALIZATION, "deserialization"),
    (AuthenticationTestPack(), VulnerabilityCategory.AUTHENTICATION, "authentication"),
]


def test_all_packs_registered():
    names = {p.name for p in default_registry.list_all()}
    for _, _, key in PACK_CASES:
        assert key in names
        assert default_registry.get(key.upper()) is not None  # case-insensitive


def test_packs_return_wellformed_results_when_reachable():
    for pack, category, key in PACK_CASES:
        res = pack.execute(_hyp(category, pack=key), _StubClient(), _ctx())
        assert isinstance(res, TestExecutionResult)
        assert res.testpack_name == pack.name
        assert isinstance(res.confidence, float)
        assert isinstance(res.observations, list)


def test_packs_survive_unreachable_target():
    for pack, category, key in PACK_CASES:
        res = pack.execute(_hyp(category, pack=key), _StubClient(status=0, body=""), _ctx())
        assert isinstance(res, TestExecutionResult)
        assert res.confirmed is False


def test_bola_offline_confidence_is_zero():
    res = BolaTestPack().execute(
        _hyp(VulnerabilityCategory.BOLA), _StubClient(status=0, body=""), _ctx()
    )
    assert res.confirmed is False
    assert res.confidence == 0.0
