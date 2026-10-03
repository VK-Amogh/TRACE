"""High-fidelity live test server for enterprise test-repository.
Emulates live execution of Dart Shelf and Kotlin Spring Boot endpoints
to validate TRACE active runtime security test packs.
"""

import sys
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler


class EnterprisePortalHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = self.path

        # Health check
        if url in ("/", "/health"):
            return self._send_json(200, {"status": "healthy", "service": "enterprise-cloud-portal", "version": "2.4.0"})

        # BOLA: GET /api/v1/organizations/{orgId}/projects/{projectId}
        if re.search(r"^/api/v1/organizations/[^/]+/projects/[^/]+", url):
            return self._send_json(200, {
                "status": "success",
                "data": {
                    "projectId": "proj-alpha",
                    "organizationId": "org-tenant-100",
                    "user-a": "private-vault-access-key-sec99",
                    "items": [{"product": "enterprise-secrets", "total": 999999}],
                    "confidential_notes": "Proprietary architectural secrets and internal auth tokens."
                }
            })

        # BOLA / Records: GET /api/v2/records/{recordId}
        if re.search(r"^/api/v2/records/[^/]+", url):
            return self._send_json(200, {
                "recordId": "rec-101",
                "tenantId": "tenant-enterprise-99",
                "user-a": "audit-custodian",
                "items": [{"product": "Audit Record", "total": 100}],
                "payload": "Cryptographic audit trail: sha256:d8a94b291c89f..."
            })

        # Default fallback
        return self._send_json(404, {"error": "Not Found", "path": url})

    def do_POST(self):
        url = self.path
        content_len = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(body_raw)
        except Exception:
            payload = {}

        # BFLA: POST /api/v1/admin/users/{userId}/role
        if re.search(r"^/api/v1/admin/users/[^/]+/role", url):
            return self._send_json(200, {
                "status": "updated",
                "userId": "1",
                "assignedRole": payload.get("role", "SUPER_ADMIN"),
                "message": "Role escalation successful without admin token"
            })

        # SSRF: POST /api/v1/integrations/webhooks/preview
        if "/api/v1/integrations/webhooks/preview" in url:
            target = payload.get("url") or payload.get("webhook_url") or payload.get("target") or "http://internal"
            return self._send_json(200, {
                "status": "dispatched",
                "target": target,
                "data": {
                    "product": "internal-cloud-metadata",
                    "content": "AMI ID: ami-0928374291, Hostname: ip-10-0-1-42.internal",
                    "response_code": 200
                }
            })

        # SSRF Kotlin: POST /api/v2/records/export/dispatch
        if "/api/v2/records/export/dispatch" in url:
            return self._send_json(200, {
                "status": "dispatched",
                "target": payload.get("callbackUrl", "internal"),
                "data": {"product": "audit-export-package", "content": "Export delivered"}
            })

        # Auth Bypass: POST /api/v1/billing/invoices/{invoiceId}/refund
        if re.search(r"^/api/v1/billing/invoices/[^/]+/refund", url):
            return self._send_json(200, {
                "status": "success",
                "invoiceId": "inv-8849",
                "action": "REFUND_PROCESSED",
                "amount": payload.get("amount", 4500.0),
                "refund_status": "COMPLETED"
            })

        return self._send_json(404, {"error": "Not Found", "path": url})

    def do_PUT(self):
        url = self.path
        content_len = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(body_raw)
        except Exception:
            payload = {}

        # Mass Assignment: PUT /api/v1/users/profile
        if "/api/v1/users/profile" in url:
            return self._send_json(200, {
                "status": "updated",
                "profile": payload,
                "is_admin": payload.get("is_admin", True),
                "role": payload.get("role", "admin"),
                "message": "Profile fields applied successfully"
            })

        return self._send_json(404, {"error": "Not Found", "path": url})

    def log_message(self, format, *args):
        # Silent logger for clean test output
        pass


def run_server(port: int = 18082):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, EnterprisePortalHandler)
    print(f"Enterprise Test Server listening on http://127.0.0.1:{port}")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18082
    run_server(port)
