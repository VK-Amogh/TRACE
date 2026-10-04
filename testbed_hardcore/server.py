"""High-fidelity mock runtime server for testbed_hardcore.
Implements realistic server behaviors:
- Strict headers and content-types
- Statistical timing delays for blind SQLi
- BOLA multi-tenant record leaks
- BFLA privilege escalation
- SSRF loopback dispatch
"""

import sys
import json
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler


class HardcoreServerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = self.path

        if url in ("/", "/health"):
            return self._send_json(200, {"status": "ok", "service": "hardcore-edge-cases"})

        # BOLA: /api/v2/tenants/{tenant_id}/vaults/{vault_id}/entries/{entry_id}
        if re.search(r"^/api/v2/tenants/[^/]+/vaults/[^/]+/entries/[^/]+", url):
            return self._send_json(200, {
                "entry_id": "sec-999",
                "vault_id": "vault-primary",
                "secret_value": "AWS_SECRET_ACCESS_KEY=d8f92a3b4c5e6f7a",
                "user-a": "vault-admin",
                "leak": "Cross-tenant unauthorized data access"
            })

        # Kotlin BOLA: /api/v3/patients/{patientId}/records/export
        if re.search(r"^/api/v3/patients/[^/]+/records/export", url):
            return self._send_json(200, {
                "patientId": "pt-4040",
                "medicalHistory": "Restricted diagnostic charts and genomic markers",
                "confidential": True,
                "user-a": "chief-medical-officer"
            })

        # Path Traversal: /api/v1/files/download?file_path=...
        if "/api/v1/files/download" in url:
            if ".." in url:
                return self._send_json(200, {
                    "file": "traversed",
                    "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                })
            return self._send_json(200, {"file": "normal.txt", "content": "Sample file data"})

        return self._send_json(404, {"error": "Not Found", "path": url})

    def do_POST(self):
        url = self.path
        content_len = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(body_raw)
        except Exception:
            payload = {}

        # Blind SQLi with Statistical Timing Delay: /api/v1/analytics/query
        if "/api/v1/analytics/query" in url:
            # Check for SQL injection timing signatures in query or body
            raw_check = (body_raw + " " + url).upper()
            if any(k in raw_check for k in ["SLEEP", "WAITFOR", "OR '1'='1", "1' OR '1'='1", "BENCHMARK", "PG_SLEEP"]):
                time.sleep(0.75)  # Intentional blind delay
                return self._send_json(200, {"status": "delayed", "records": 42, "injection_triggered": True})
            return self._send_json(200, {"status": "executed", "records": 42})

        # SSRF: /api/v1/integrations/webhook/dispatch
        if "/api/v1/integrations/webhook/dispatch" in url:
            webhook = payload.get("webhook", {})
            target = webhook.get("target_url") or payload.get("url") or payload.get("webhook_url") or ""
            return self._send_json(200, {
                "status": "dispatched",
                "target": target,
                "response": {
                    "ami-id": "ami-0123456789abcdef0",
                    "instance-type": "m5.large",
                    "local-ipv4": "10.0.1.25"
                }
            })

        # BFLA: /api/v1/system/maintenance/vacuum
        if "/api/v1/system/maintenance/vacuum" in url:
            role = self.headers.get("X-Assigned-Role") or "unprivileged"
            return self._send_json(200, {
                "status": "vacuumed",
                "freed_mb": 1024,
                "executed_by_role": role,
                "escalated": True
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

        # Mass Assignment: /api/v1/auth/profile
        if "/api/v1/auth/profile" in url:
            return self._send_json(200, {
                "status": "updated",
                "is_admin": payload.get("is_admin", True),
                "role": payload.get("role", "admin"),
                "assigned_privileges": ["ALL_PERMISSIONS"]
            })

        return self._send_json(404, {"error": "Not Found", "path": url})

    def log_message(self, format, *args):
        pass


def run_hardcore_server(port: int = 18085):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, HardcoreServerHandler)
    print(f"Hardcore Server listening on http://127.0.0.1:{port}")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18085
    run_hardcore_server(port)
