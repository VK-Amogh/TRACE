"""Ruby on Rails framework adapter for endpoint and route discovery."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class RubyFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Ruby on Rails routes, controllers, and sinks."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "ruby":
            norm = parsed_file.file_path.replace("\\", "/").lower()
            return norm.endswith(".rb")
        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        has_db_sink = any(
            term in content_lower
            for term in ("active_record", "connection.execute", "find_by_sql", "where(", "find(")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("net::http", "httparty", "faraday", "restclient")
        )

        # Rails routes: get '/users/:id', to: 'users#show'
        # post '/orders', to: 'orders#create'
        route_pattern = re.compile(
            r"""(?:get|post|put|delete|patch)\s+['"]([^'"]+)['"](?:\s*,\s*to:\s*['"]([^'"]+)['"])?""",
            re.IGNORECASE,
        )

        for match in route_pattern.finditer(content):
            raw_path = match.group(1).strip()
            handler = match.group(2) or "rails_controller_action"
            line_no = content[:match.start()].count("\n") + 1

            method = match.group(0).split()[0].upper()
            norm_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
            norm_path = "/" + norm_path.lstrip("/")
            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)

            ep_id = f"ep_ruby_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler,
                    auth_required="authenticate" in content_lower or "before_action :authenticate" in content_lower,
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
