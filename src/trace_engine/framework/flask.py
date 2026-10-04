"""Flask framework adapter for endpoint, Blueprint, and parameter extraction."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class FlaskFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Flask routes, Blueprints, parameters, and database/network sinks."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "python":
            return False

        for imp in parsed_file.imports:
            mod = imp.module.lower()
            if "flask" in mod:
                return True

        # Check for typical Flask route decorators in content
        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        content_lower = content.lower()

        # Database and sink detection
        has_db_sink = any(
            term in content_lower
            for term in (
                "db.session", ".query.", "session.execute", "cursor.execute",
                "sqlite3.connect", "psycopg2.connect", "find_one", "find(", "collection."
            )
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request")
        )

        for fn in parsed_file.functions:
            fn_body = fn.body_text or ""
            fn_body_lower = fn_body.lower()

            for dec in fn.decorators:
                dec_text = dec.raw_text.strip()
                # Matches @app.route('/path', methods=['GET', 'POST']) or @bp.route('/path') or @blueprint.route
                route_match = re.search(
                    r"""@?(?:[a-zA-Z0-9_]+)\.route\s*\(\s*["']([^"']+)["'](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""",
                    dec_text,
                    re.IGNORECASE,
                )
                if not route_match:
                    continue

                raw_path = route_match.group(1).strip()
                methods_raw = route_match.group(2)

                if methods_raw:
                    methods = [
                        m.strip().strip("'\"").upper()
                        for m in methods_raw.split(",")
                        if m.strip()
                    ]
                else:
                    methods = ["GET"]

                # Flask path parameters: <int:id>, <string:slug>, <path:filename>, <uuid:pk> -> {id}, {slug}, {filename}, {pk}
                clean_path = re.sub(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", r"{\1}", raw_path)
                norm_path = clean_path if clean_path.startswith("/") else f"/{clean_path}"
                path_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", norm_path)

                # Extract request.args or request.form parameters from function body
                query_params = re.findall(r"""request\.args\.get\s*\(\s*["']([a-zA-Z0-9_]+)["']""", fn_body)
                body_params = re.findall(r"""request\.(?:form|json)\.get\s*\(\s*["']([a-zA-Z0-9_]+)["']""", fn_body)

                params = [EndpointParameter(name=p, location="path", required=True) for p in path_params]
                params.extend([EndpointParameter(name=p, location="query", required=False) for p in query_params])
                params.extend([EndpointParameter(name=p, location="body", required=False) for p in body_params])

                auth_required = any(
                    sig in fn_body_lower or sig in dec_text.lower()
                    for sig in ("@login_required", "@jwt_required", "current_user", "get_jwt_identity", "auth")
                )
                roles = ["admin"] if "admin" in fn.name.lower() or "admin" in norm_path.lower() else []

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
                            parameters=params,
                            database_access=has_db_sink or "execute(" in fn_body_lower or "query" in fn_body_lower,
                            object_identifier=bool(path_params),
                            state_changing=m in ("POST", "PUT", "DELETE", "PATCH"),
                            external_network=has_ext_sink or "requests." in fn_body_lower or "urllib" in fn_body_lower,
                            sensitive_data="admin" in norm_path.lower() or "user" in norm_path.lower() or "secret" in norm_path.lower(),
                            source=fn.location,
                        )
                    )

        return endpoints
