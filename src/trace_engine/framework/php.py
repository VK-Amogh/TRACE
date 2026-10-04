"""PHP and Laravel framework adapter for endpoint and route discovery."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class PHPFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts PHP endpoints from Laravel routes and native PHP API scripts."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "php":
            norm = parsed_file.file_path.replace("\\", "/").lower()
            return norm.endswith(".php")
        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        # Database and system sinks
        has_db_sink = any(
            term in content_lower
            for term in (
                "mysqli_query", "pdo::query", "db::raw", "db::select", "db::table",
                "eloquent", "->get()", "->find(", "->first()"
            )
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("curl_exec", "file_get_contents", "http::get", "guzzle")
        )

        # 1. Laravel Route definitions: Route::get('/users/{id}', [UserController::class, 'show'])
        laravel_pattern = re.compile(
            r"""Route::(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\)""",
            re.IGNORECASE,
        )
        for match in laravel_pattern.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2).strip()
            handler = match.group(3).strip()
            line_no = content[:match.start()].count("\n") + 1

            norm_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            path_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", norm_path)

            ep_id = f"ep_php_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler,
                    auth_required="auth" in content_lower or "middleware('auth" in content_lower,
                    roles=["admin"] if "admin" in norm_path.lower() or "admin" in content_lower else [],
                    parameters=[EndpointParameter(name=p, location="path", required=True) for p in path_params],
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data="admin" in norm_path.lower() or "user" in norm_path.lower(),
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        # 2. Native PHP file scripts: e.g. api/users.php or get_order.php
        if not endpoints and any(seg in norm_file.lower() for seg in ("/api/", "endpoints/", "public/")):
            script_path = "/" + norm_file.lstrip("/").replace(".php", "")
            params = []
            for get_match in re.findall(r"""\$_GET\s*\[\s*['"]([a-zA-Z0-9_]+)['"]\s*\]""", content):
                params.append(EndpointParameter(name=get_match, location="query", required=False))
            for post_match in re.findall(r"""\$_POST\s*\[\s*['"]([a-zA-Z0-9_]+)['"]\s*\]""", content):
                params.append(EndpointParameter(name=post_match, location="body", required=False))

            method = "POST" if "$_POST" in content else "GET"
            endpoints.append(
                Endpoint(
                    id=f"ep_php_script_{norm_file}".replace("/", "_").replace(".", "_"),
                    method=method,
                    path=script_path,
                    handler_name=parsed_file.file_path,
                    auth_required="session_start" in content_lower or "auth" in content_lower,
                    roles=["admin"] if "admin" in script_path.lower() else [],
                    parameters=params,
                    database_access=has_db_sink,
                    object_identifier=any(p.name in ("id", "user_id", "order_id") for p in params),
                    state_changing=method == "POST",
                    external_network=has_ext_sink,
                    sensitive_data="admin" in script_path.lower() or "user" in script_path.lower(),
                    source=SourceLocation(file=parsed_file.file_path, line_start=1, line_end=max(1, content.count("\n"))),
                )
            )

        return endpoints
