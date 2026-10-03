"""Go framework adapter for Gin, Fiber, Chi, and HTTP mux routes."""

import re
from typing import List, Dict, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class GoFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Go web routes and middleware."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        return parsed_file.language == "go"

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        has_db_sink = any(
            term in content_lower
            for term in ("db.query", "db.exec", "gorm", "sqlx", "mongo.", "redis.", "findone")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("http.get", "http.post", "http.client", "fasthttp", "resty")
        )

        auth_signals = ("auth", "jwt", "bearer", "token", "requireauth", "admin", "middleware.auth")
        auth_required = any(sig in content_lower for sig in auth_signals) or "admin" in norm_file_path.lower()
        roles = ["admin"] if "admin" in content_lower or "admin" in norm_file_path.lower() else []

        # Route regex for Gin, Fiber, Chi: r.GET("/path", handler)
        pattern = re.compile(
            r"""\.(GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\s*\(\s*["']([^"']+)["']\s*,\s*([a-zA-Z0-9_\.]+)""",
            re.IGNORECASE
        )

        for match in pattern.finditer(content):
            raw_method = match.group(1).upper()
            method = "GET" if raw_method in ("HANDLE", "HANDLEFUNC") else raw_method
            raw_path = match.group(2)
            handler_name = match.group(3)
            line_no = content[:match.start()].count("\n") + 1

            # Convert :id or {id}
            norm_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
            norm_path = "/" + norm_path.lstrip("/")

            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)
            ep_id = f"ep_go_{norm_file_path}_{line_no}_{method}".replace("/", "_").replace(".", "_")

            sensitive = any(
                term in norm_path.lower() or term in content_lower
                for term in ("admin", "user", "auth", "billing", "payment", "token", "secret", "order")
            )

            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler_name,
                    auth_required=auth_required or ("admin" in norm_path.lower()),
                    roles=roles if "admin" not in norm_path.lower() else ["admin"],
                    parameters=[EndpointParameter(name=p, location="path", required=True) for p in path_params],
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data=sensitive,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        return endpoints
