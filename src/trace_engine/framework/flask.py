"""Flask framework adapter for endpoint discovery."""

import re
from typing import List
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class FlaskFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Flask routes and auth decorators."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "python":
            return False
        for imp in parsed_file.imports:
            if "flask" in imp.module.lower():
                return True
        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        for fn in parsed_file.functions:
            for dec in fn.decorators:
                dec_text = dec.raw_text.strip()
                # Pattern: @app.route('/path', methods=['GET', 'POST'])
                route_match = re.search(
                    r"""@?(?:[a-zA-Z0-9_]+)\.route\s*\(\s*["']([^"']+)["'](?:\s*,\s*methods=\[([^\]]+)\])?""",
                    dec_text,
                    re.IGNORECASE,
                )
                if route_match:
                    path = route_match.group(1)
                    methods_raw = route_match.group(2)
                    methods = ["GET"]
                    if methods_raw:
                        methods = [
                            m.strip().strip("'\"").upper()
                            for m in methods_raw.split(",")
                            if m.strip()
                        ]

                    path_params = re.findall(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", path)
                    # Normalize flask param format <id> to {id}
                    norm_path = re.sub(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", r"{\1}", path)

                    fn_body = fn.body_text or ""
                    auth_required = any(
                        term in dec_text.lower()
                        for term in ("login_required", "auth", "jwt_required", "roles_required")
                    )
                    roles = ["admin"] if "admin" in dec_text.lower() or "admin" in norm_path.lower() else []

                    for m in methods:
                        ep_id = f"ep_flask_{parsed_file.file_path}_{fn.name}_{m}".replace("/", "_").replace(".", "_")
                        endpoints.append(
                            Endpoint(
                                id=ep_id,
                                method=m,
                                path=norm_path,
                                handler_name=fn.qualified_name,
                                auth_required=auth_required,
                                roles=roles,
                                parameters=[
                                    EndpointParameter(name=p, location="path", required=True)
                                    for p in path_params
                                ],
                                database_access="db." in fn_body or "query" in fn_body,
                                object_identifier=bool(path_params),
                                state_changing=m in ("POST", "PUT", "DELETE", "PATCH"),
                                external_network="requests." in fn_body or "urllib" in fn_body,
                                sensitive_data="admin" in norm_path.lower() or "user" in norm_path.lower(),
                                source=fn.location,
                            )
                        )
        return endpoints
