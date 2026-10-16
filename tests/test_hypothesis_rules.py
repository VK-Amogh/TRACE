"""Vulnerability-rule corrections: evidence over names, pos/neg pairs.

Each pair pins why the rule fires (or stays silent). Fixture files are
written under tmp_path and endpoints reference them absolutely so the
engine's file evidence reads resolve.
"""

from pathlib import Path

from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation
from trace_engine.apm.builder import APMBuilder
from trace_engine.security.hypotheses import HypothesisEngine, has_unsafe_sql_construction, has_template_sink


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def _ep(method, route, filepath, lineno=1, **kw):
    params = kw.pop("params", [])
    return Endpoint(
        id=f"ep_test_{method}_{route}".replace("/", "_"),
        method=method,
        path=route,
        handler_name=kw.pop("handler", "handler"),
        auth_required=kw.pop("auth", False),
        roles=kw.pop("roles", []),
        parameters=params,
        database_access=kw.pop("db", False),
        object_identifier=kw.pop("obj", False),
        state_changing=kw.pop("state", False),
        external_network=kw.pop("ext", False),
        sensitive_data=kw.pop("sens", False),
        source=SourceLocation(file=filepath, line_start=lineno, line_end=lineno),
        registered=kw.pop("registered", True),
    )


def _hyps(endpoints, tmp_path):
    apm = APMBuilder(project_name="t").build(tmp_path, [], [], endpoints)
    return HypothesisEngine().derive_hypotheses(apm, endpoints)


def _cats(hyps):
    return {(h.category.value, h.endpoint_display) for h in hyps}


# --- unit-level evidence helpers -------------------------------------------

def test_unsafe_sql_detected_and_parameterized_is_safe():
    vuln = "query = f\"SELECT * FROM t WHERE c = '{v}'\"\ndb.execute(query)\n"
    safe = "cursor.execute(\"SELECT * FROM t WHERE c = %s\", [v])\n"
    plain = "return {'q': q}\n"
    assert has_unsafe_sql_construction(vuln) is True
    assert has_unsafe_sql_construction(safe) is False
    assert has_unsafe_sql_construction(plain) is False


def test_template_sink_detected_and_plain_fetch_is_not():
    assert has_template_sink("from jinja2 import Template\nTemplate(user).render()\n") is True
    assert has_template_sink("resp = http.Client().get(uri)\n") is False


# --- injection ---------------------------------------------------------------

def test_search_without_sql_sink_is_not_injection(tmp_path):
    f = _write(tmp_path / "search.py", "def search(q=''):\n    return {'query': q}\n")
    ep = _ep("GET", "/api/search", f, params=[EndpointParameter(name="q", location="query")], db=True)
    assert ("INJECTION", "GET /api/search") not in _cats(_hyps([ep], tmp_path))


def test_search_with_unsafe_sql_is_injection(tmp_path):
    f = _write(
        tmp_path / "vuln.py",
        "def analytics_metric_query(request):\n"
        "    v = request.data.get('f', '')\n"
        "    query = f\"SELECT * FROM m WHERE c = '{v}'\"\n"
        "    db.execute(query)\n",
    )
    ep = _ep("POST", "/api/v1/analytics/query", f, db=True)
    assert ("INJECTION", "POST /api/v1/analytics/query") in _cats(_hyps([ep], tmp_path))


def test_parameterized_query_is_not_injection(tmp_path):
    f = _write(
        tmp_path / "safe.py",
        "def lookup(request):\n"
        "    v = request.GET.get('q', '')\n"
        "    cursor.execute(\"SELECT * FROM m WHERE c = %s\", [v])\n",
    )
    ep = _ep("GET", "/api/query", f, db=True)
    assert ("INJECTION", "GET /api/query") not in _cats(_hyps([ep], tmp_path))


# --- SSTI vs SSRF --------------------------------------------------------------

def test_preview_without_template_sink_is_not_ssti_but_ssrf_stays(tmp_path):
    f = _write(
        tmp_path / "webhook.py",
        "async def preview(request):\n"
        "    target = payload['webhook_url']\n"
        "    response = await client.get(uri)\n",
    )
    ep = _ep(
        "POST", "/api/v1/integrations/webhooks/preview", f, auth=True, state=True, ext=True,
        params=[EndpointParameter(name="webhook_url", location="body")],
    )
    cats = _cats(_hyps([ep], tmp_path))
    assert ("SSTI", "POST /api/v1/integrations/webhooks/preview") not in cats
    assert ("SSRF", "POST /api/v1/integrations/webhooks/preview") in cats


def test_unsafe_template_evaluation_is_ssti(tmp_path):
    f = _write(
        tmp_path / "render.py",
        "from jinja2 import Template\ndef preview(name):\n    return Template(name).render()\n",
    )
    ep = _ep(
        "POST", "/api/v1/email/preview", f,
        params=[EndpointParameter(name="template", location="body")],
    )
    assert ("SSTI", "POST /api/v1/email/preview") in _cats(_hyps([ep], tmp_path))


# --- BFLA admin evidence ---------------------------------------------------------

def test_admin_path_is_bfla_but_role_only_without_route_evidence_is_not(tmp_path):
    # NOTE: files live in a neutral subdir so the sandbox path itself cannot
    # contribute "admin" evidence to the handler-context check.
    case = tmp_path / "case"
    case.mkdir()
    f = _write(case / "routes.py", "router.post('/api/v1/admin/users/role', h)\n")
    admin_ep = _ep("POST", "/api/v1/admin/users/role", f, auth=True)
    assert ("BFLA", "POST /api/v1/admin/users/role") in _cats(_hyps([admin_ep], case))

    g = _write(case / "other.py", "router.post('/api/v1/billing/refund', h)\n")
    # file-wide role contamination alone must not imply a privileged route
    other_ep = _ep("POST", "/api/v1/billing/refund", g, auth=True, roles=["admin"])
    assert ("BFLA", "POST /api/v1/billing/refund") not in _cats(_hyps([other_ep], case))


# --- registration gate ------------------------------------------------------------

def test_unregistered_endpoint_produces_no_findings(tmp_path):
    f = _write(tmp_path / "views.py", "def order_list(request):\n    return {}\n")
    ep = _ep("GET", "/api/order-list", f, obj=True, db=True, registered=False)
    assert _hyps([ep], tmp_path) == []


# --- preserved benchmark detections (positive controls) ------------------------------

def test_bola_order_without_ownership_still_detected(tmp_path):
    f = _write(tmp_path / "orders.py", "def get_order(id):\n    return ORDERS.get(id)\n")
    ep = _ep("GET", "/api/orders/{id}", f, obj=True, db=True, auth=True, sens=True,
             params=[EndpointParameter(name="id", location="path")])
    assert ("BOLA", "GET /api/orders/{id}") in _cats(_hyps([ep], tmp_path))


def test_mass_assignment_user_update_still_detected(tmp_path):
    f = _write(tmp_path / "users.py", "def update_user(id, payload):\n    user.update(payload)\n")
    ep = _ep(
        "PATCH", "/api/users/{id}", f, auth=True, obj=True, state=True,
        params=[
            EndpointParameter(name="id", location="path"),
            EndpointParameter(name="payload", location="body"),
            EndpointParameter(name="nickname", location="body"),
        ],
    )
    assert ("MASS_ASSIGNMENT", "PATCH /api/users/{id}") in _cats(_hyps([ep], tmp_path))
