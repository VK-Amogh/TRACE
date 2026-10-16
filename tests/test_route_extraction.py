"""Route-extraction corrections: real registrations vs inferred inventory."""

from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.django import DjangoFrameworkAdapter


def _extract(content, filename="views.py"):
    parser = CodeParser()
    parsed = parser.parse(filename, content, "python")
    return DjangoFrameworkAdapter().extract_endpoints(parsed, content)


def test_urlpatterns_prefer_handler_decorator_method():
    # analytics_metric_query is POST per @api_view but the name gives no signal;
    # the registration path is authoritative, the decorator fixes the method.
    content = """
from django.urls import path
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(["POST"])
def analytics_metric_query(request):
    filter_val = request.data.get("metric_filter", "")
    return Response({"status": "executed", "filter": filter_val})

urlpatterns = [
    path("api/v1/analytics/query", analytics_metric_query),
]
"""
    eps = _extract(content)
    by_path = {ep.path: ep for ep in eps if ep.registered}
    assert "/api/v1/analytics/query" in by_path
    assert by_path["/api/v1/analytics/query"].method == "POST"
    # no synthetic duplicate for the same handler
    assert "/api/analytics-metric-query" not in by_path


def test_unregistered_decorated_function_is_low_confidence_inventory():
    content = """
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def order_list(request):
    orders = Order.objects.filter(user=request.user)
    return Response(orders)
"""
    eps = _extract(content)
    # one inferred entry per declared @api_view method, all low-confidence
    assert len(eps) == 2
    assert all(ep.registered is False for ep in eps)
    assert all(ep.confidence == "low" for ep in eps)
    assert {ep.method for ep in eps} == {"GET", "POST"}


def test_duplicate_handler_reference_deduped():
    content = """
from django.urls import path
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(["GET"])
def tenant_entry(request, tenant_id, entry_id):
    return Response({"entry_id": entry_id})

urlpatterns = [
    path("api/v2/tenants/<str:tenant_id>/entries/<str:entry_id>", tenant_entry),
]
"""
    eps = _extract(content)
    registered = [ep for ep in eps if ep.registered]
    assert len(registered) == 1
    assert registered[0].path == "/api/v2/tenants/{tenant_id}/entries/{entry_id}"
    assert registered[0].method == "GET"


def test_method_inference_create_is_post_and_plain_is_medium():
    content = """
from django.urls import path

urlpatterns = [
    path("api/v1/orders/create/", views.create_order, name='create-order'),
    path("api/v1/status/", views.get_status, name='status'),
]
"""
    eps = _extract(content, filename="urls.py")
    by_path = {ep.path: ep for ep in eps}
    assert by_path["/api/v1/orders/create"].method == "POST"
    assert by_path["/api/v1/status"].method == "GET"
    assert by_path["/api/v1/status"].confidence == "medium"


def test_urlpattern_db_evidence_not_default_true():
    content = """
from django.urls import path

def plain_status(request):
    return {"ok": True}

urlpatterns = [
    path("api/v1/status/", plain_status),
]
"""
    eps = _extract(content, filename="urls.py")
    assert eps[0].database_access is False
