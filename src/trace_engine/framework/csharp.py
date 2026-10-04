"""C# and ASP.NET Core framework adapter for controller and minimal API route extraction."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class CSharpFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts C# ASP.NET Core endpoints, controller actions, and minimal APIs."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "csharp":
            norm = parsed_file.file_path.replace("\\", "/").lower()
            return norm.endswith(".cs")
        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        has_db_sink = any(
            term in content_lower
            for term in ("fromsqlraw", "executesqlraw", "dbcontext", "_context.", "sqlconnection", "dapper", "queryasync")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("httpclient", "getasync", "postasync", "restsharp")
        )

        # 1. Controller HTTP action attributes: [HttpGet("api/v1/users/{id}")] or [HttpPost("orders")]
        attr_pattern = re.compile(
            r"""\[Http(Get|Post|Put|Delete|Patch)\s*(?:\(\s*["']([^"']*)["']\s*\))?\]\s*(?:\[[^\]]+\]\s*)*public\s+(?:async\s+)?(?:Task<[a-zA-Z0-9_<>]+>|[a-zA-Z0-9_<>]+)\s+([a-zA-Z0-9_]+)""",
            re.MULTILINE
        )

        # Extract base route from [Route("api/[controller]")] if present
        base_route_match = re.search(r"""\[Route\s*\(\s*["']([^"']+)["']\s*\)\]""", content)
        base_route = base_route_match.group(1).rstrip("/") if base_route_match else ""

        for match in attr_pattern.finditer(content):
            method = match.group(1).upper()
            action_route = match.group(2) or ""
            handler = match.group(3)
            line_no = content[:match.start()].count("\n") + 1

            if action_route.startswith("/"):
                raw_path = action_route
            elif base_route:
                raw_path = f"/{base_route}/{action_route}".rstrip("/")
            else:
                raw_path = f"/{action_route}" if action_route else f"/{handler}"

            raw_path = "/" + raw_path.lstrip("/")
            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', raw_path)

            ep_id = f"ep_cs_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=raw_path,
                    handler_name=handler,
                    auth_required="[authorize]" in content_lower or "authorize" in content_lower,
                    roles=["admin"] if "admin" in raw_path.lower() else [],
                    parameters=[EndpointParameter(name=p, location="path", required=True) for p in path_params],
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data="admin" in raw_path.lower() or "user" in raw_path.lower(),
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        # 2. Minimal APIs: app.MapGet("/api/v1/users/{id}", ...)
        map_pattern = re.compile(
            r"""app\.Map(Get|Post|Put|Delete)\s*\(\s*["']([^"']+)["']\s*,\s*([a-zA-Z0-9_\.]+|async|\()""",
            re.IGNORECASE,
        )
        for match in map_pattern.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2).strip()
            handler = "minimal_api_handler"
            line_no = content[:match.start()].count("\n") + 1

            norm_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)

            ep_id = f"ep_cs_map_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler,
                    auth_required="requireauthorization" in content_lower,
                    roles=["admin"] if "admin" in norm_path.lower() else [],
                    parameters=[EndpointParameter(name=p, location="path", required=True) for p in path_params],
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data="admin" in norm_path.lower() or "user" in norm_path.lower(),
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        return endpoints
