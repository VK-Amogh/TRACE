"""Go framework adapter for Gin, Fiber, Chi, Echo, and standard net/http routes."""

import re
from typing import List, Dict, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class GoFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Go web routes, closures, parameters, and middleware across Gin, Echo, Fiber, Chi, and net/http."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "go":
            norm = parsed_file.file_path.replace("\\", "/").lower()
            return norm.endswith(".go")
        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        has_db_sink = any(
            term in content_lower
            for term in ("db.query", "db.exec", "db.raw", "gorm", "sqlx", "mongo.", "redis.", "findone", "sql.open")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("http.get", "http.post", "http.client", "fasthttp", "resty", "http.newrequest", "client.do")
        )

        auth_signals = ("auth", "jwt", "bearer", "token", "requireauth", "admin", "middleware.auth", "authrequired")
        auth_required = any(sig in content_lower for sig in auth_signals) or "admin" in norm_file_path.lower()
        roles = ["admin"] if "admin" in content_lower or "admin" in norm_file_path.lower() else []

        # Matches:
        # 1. Gin/Echo: r.GET("/path", handler) or r.GET("/path", func(c *gin.Context) {
        # 2. Chi/Fiber: r.Get("/path", handler) or app.Post("/path", func(...) {
        # 3. net/http: http.HandleFunc("/path", handler) or mux.Handle("/path", ...)
        pattern = re.compile(
            r"""(?:[a-zA-Z0-9_]+)\.(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch|Handle|HandleFunc)\s*\(\s*["']([^"']+)["']\s*,\s*([a-zA-Z0-9_\.]+|func\s*\([^)]*\))""",
            re.MULTILINE
        )

        for match in pattern.finditer(content):
            raw_method = match.group(1).upper()
            method = "GET" if raw_method in ("HANDLE", "HANDLEFUNC") else raw_method
            raw_path = match.group(2)
            raw_handler = match.group(3).strip()
            handler_name = "closure_handler" if raw_handler.startswith("func") else raw_handler
            line_no = content[:match.start()].count("\n") + 1

            # Convert Go :id or {id} or *wildcard to standard {id}
            norm_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
            norm_path = re.sub(r'\*([a-zA-Z0-9_]+)', r'{\1}', norm_path)
            norm_path = "/" + norm_path.lstrip("/")

            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)

            # Query and body parameter extraction from Go conventions
            query_params = re.findall(r"""(?:c\.Query|r\.URL\.Query\(\)\.Get)\s*\(\s*["']([a-zA-Z0-9_]+)["']""", content)
            body_params = re.findall(r"""(?:c\.PostForm|c\.BindJSON|c\.BodyParser)\s*\(\s*&?([a-zA-Z0-9_]+)""", content)

            params = [EndpointParameter(name=p, location="path", required=True) for p in path_params]
            params.extend([EndpointParameter(name=p, location="query", required=False) for p in query_params])
            params.extend([EndpointParameter(name=p, location="body", required=False) for p in body_params])

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
                    parameters=params,
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data=sensitive,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        return endpoints
