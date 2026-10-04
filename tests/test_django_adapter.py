"""Tests for Django and DRF framework adapter."""

from pathlib import Path
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.django import DjangoFrameworkAdapter


def test_django_urls_extraction():
    content = """
from django.urls import path, re_path
from . import views
from .views import OrderDetailView, ExportAuditView

urlpatterns = [
    path('api/v1/orders/<int:order_id>/', views.get_order, name='get-order'),
    path('api/v1/orders/create/', views.create_order, name='create-order'),
    path('api/v1/users/<str:username>/profile/', OrderDetailView.as_view(), name='user-profile'),
    re_path(r'^admin/export/?$', ExportAuditView.as_view(), name='admin-export'),
]
"""
    parser = CodeParser()
    parsed = parser.parse("urls.py", content, "python")

    adapter = DjangoFrameworkAdapter()
    assert adapter.can_handle(parsed) is True

    endpoints = adapter.extract_endpoints(parsed, content)
    assert len(endpoints) >= 4

    paths = [ep.path for ep in endpoints]
    assert "/api/v1/orders/{order_id}" in paths
    assert "/api/v1/orders/create" in paths
    assert "/api/v1/users/{username}/profile" in paths
    assert "/admin/export" in paths

    # Check path parameters
    order_ep = next(ep for ep in endpoints if "{order_id}" in ep.path)
    assert len(order_ep.parameters) == 1
    assert order_ep.parameters[0].name == "order_id"
    assert order_ep.object_identifier is True

    # Check state-changing
    create_ep = next(ep for ep in endpoints if "create" in ep.path)
    assert create_ep.method == "POST"
    assert create_ep.state_changing is True


def test_drf_views_extraction():
    content = """
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def order_list(request):
    orders = Order.objects.filter(user=request.user)
    return Response(orders)

class AdminMetricsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return Response({'stats': 'ok'})

    def post(self, request):
        db.raw('DELETE FROM metrics')
        return Response({'status': 'reset'})
"""
    parser = CodeParser()
    parsed = parser.parse("views.py", content, "python")

    adapter = DjangoFrameworkAdapter()
    assert adapter.can_handle(parsed) is True

    endpoints = adapter.extract_endpoints(parsed, content)
    assert len(endpoints) >= 3

    # Check DRF function view
    fn_eps = [ep for ep in endpoints if "order_list" in ep.handler_name]
    assert len(fn_eps) == 2  # GET and POST
    assert any(ep.method == "GET" for ep in fn_eps)
    assert any(ep.method == "POST" for ep in fn_eps)
    assert fn_eps[0].auth_required is True

    # Check Class-Based View
    cbv_eps = [ep for ep in endpoints if "AdminMetricsView" in ep.handler_name]
    assert len(cbv_eps) == 2  # GET and POST
    assert any(ep.method == "GET" for ep in cbv_eps)
    post_ep = next(ep for ep in cbv_eps if ep.method == "POST")
    assert post_ep.state_changing is True
    assert post_ep.database_access is True
    assert "admin" in post_ep.roles
