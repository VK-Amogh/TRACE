"""Hardcore multi-framework edge-case testbed.
Exposes complex real-world endpoints across Django, Dart Shelf, and Kotlin Spring Boot
with strict validation, header requirements, nested bodies, and subtle vulnerabilities.
"""

from django.urls import path
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response

# 1. Blind Timing SQLi Endpoint with strict headers and metric filters
@api_view(["POST"])
def analytics_metric_query(request):
    """Vulnerable to Blind SQLi via metric_filter when authenticated.
    Requires header X-Engine-Key: trace-prod-auth-99.
    """
    engine_key = request.headers.get("X-Engine-Key")
    filter_val = request.data.get("metric_filter", "")
    # Vulnerable raw SQL execution with timing delay:
    query = f"SELECT * FROM system_metrics WHERE category = '{filter_val}'"
    # AST sink: db.execute(query)
    return Response({"status": "executed", "records": 42})


# 2. BOLA Endpoint with URL/Tenant mismatch
@api_view(["GET"])
def tenant_vault_secret_entry(request, tenant_id, vault_id, entry_id):
    """Vulnerable to BOLA: fetches secret entry directly by entry_id without verifying tenant_id ownership."""
    # AST sink: db.query(SecretEntry).filter_by(id=entry_id).first()
    return Response({"entry_id": entry_id, "secret": "super-sensitive-vault-api-key"})


# 3. SSRF Webhook Dispatch with nested JSON payload
@api_view(["POST"])
def webhook_integration_dispatch(request):
    """Vulnerable to SSRF: Dispatches HTTP request to webhook.target_url."""
    webhook_cfg = request.data.get("webhook", {})
    target_url = webhook_cfg.get("target_url")
    # AST sink: requests.get(target_url)
    return Response({"status": "dispatched", "target": target_url})


# 4. BFLA Maintenance Endpoint with role override
@api_view(["POST"])
def system_vacuum_cleanup(request):
    """Vulnerable to BFLA: checks unvalidated client header X-Assigned-Role for admin access."""
    role = request.headers.get("X-Assigned-Role") or request.query_params.get("override_role")
    return Response({"status": "vacuumed", "freed_mb": 1024, "executed_by_role": role})


# 5. Path Traversal File Download
@api_view(["GET"])
def secure_file_download(request):
    """Vulnerable to Path Traversal via file_path parameter."""
    file_path = request.query_params.get("file_path", "")
    # AST sink: open(f"/var/data/exports/{file_path}", "rb")
    return Response({"file": file_path, "content": "BASE64_DATA"})


urlpatterns = [
    path("api/v1/analytics/query", analytics_metric_query),
    path("api/v2/tenants/<str:tenant_id>/vaults/<str:vault_id>/entries/<str:entry_id>", tenant_vault_secret_entry),
    path("api/v1/integrations/webhook/dispatch", webhook_integration_dispatch),
    path("api/v1/system/maintenance/vacuum", system_vacuum_cleanup),
    path("api/v1/files/download", secure_file_download),
]
