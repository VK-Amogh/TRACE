"""Dart framework adapter for Shelf, Dart Frog, Angel, and Flutter API routes."""

import re
from typing import List, Dict, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class DartFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Dart API endpoints, Shelf routes, and Dart Frog handlers."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "dart":
            return False

        norm_path = parsed_file.file_path.replace("\\", "/").lower()

        # If in routes, controllers, or api directory
        if any(f"/{d}/" in norm_path or norm_path.startswith(f"{d}/") for d in ("routes", "controllers", "api", "endpoints")):
            return True

        # Check imports
        for imp in parsed_file.imports:
            mod_low = imp.module.lower()
            if any(term in mod_low for term in ("shelf", "dart_frog", "angel", "conduit")):
                return True

        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        # Database sinks
        has_db_sink = any(
            term in content_lower
            for term in (
                "postgres", "mysql", "sqlite", "drift", "sembast", "mongo",
                "supabase", "db.query", "db.execute", "findbyid", "findone",
                "repository", "table("
            )
        )

        # External network sinks
        has_ext_sink = any(
            term in content_lower
            for term in (
                "http.get", "http.post", "http.put", "http.delete",
                "client.get", "client.post", "dio.get", "dio.post"
            )
        )

        # Authentication detection
        auth_signals = (
            "requireauth", "verifytoken", "jwt", "bearer", "authmiddleware",
            "isauthenticated", "currentuser", "admin", "hasrole"
        )
        auth_required = any(sig in content_lower for sig in auth_signals) or "admin" in norm_file_path.lower()
        roles = ["admin"] if "admin" in content_lower or "admin" in norm_file_path.lower() else []

        # 1. Shelf Router: router.get('/path', _handler)
        shelf_pattern = re.compile(
            r"""(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z0-9_$]+)""",
            re.IGNORECASE
        )
        for match in shelf_pattern.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2)
            handler_name = match.group(3)
            line_no = content[:match.start()].count("\n") + 1

            # Convert Shelf <param> and :param to {param}
            norm_path = re.sub(r'<([a-zA-Z0-9_]+)>', r'{\1}', raw_path)
            norm_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', norm_path)
            norm_path = "/" + norm_path.lstrip("/")

            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)
            ep_id = f"ep_dart_{norm_file_path}_{line_no}_{method}".replace("/", "_").replace(".", "_")

            sensitive = any(
                term in norm_path.lower() or term in content_lower
                for term in ("admin", "user", "auth", "billing", "payment", "order", "token", "secret", "webhook")
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

        # 2. Dart Frog: routes/api/v1/projects/[id].dart
        if not endpoints and "routes/" in norm_file_path:
            clean = norm_file_path
            idx = clean.find("routes/")
            clean = clean[idx + 7:]
            clean = re.sub(r'\.dart$', '', clean)
            clean = re.sub(r'\[([a-zA-Z0-9_]+)\]', r'{\1}', clean)
            clean = re.sub(r'(?:^|/)index$', '', clean)
            norm_path = "/" + clean.lstrip("/")
            if not norm_path:
                norm_path = "/"

            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)
            sensitive = any(
                term in norm_path.lower() or term in content_lower
                for term in ("admin", "user", "auth", "billing", "payment", "token", "webhook")
            )

            # Look for onRequest or method checks
            methods = []
            for m in re.finditer(r'''HttpMethod\.(get|post|put|delete)''', content, re.IGNORECASE):
                methods.append(m.group(1).upper())

            if not methods:
                methods = ["GET", "POST"]

            for meth in set(methods):
                ep_id = f"ep_dart_frog_{norm_file_path}_{meth}".replace("/", "_").replace(".", "_")
                endpoints.append(
                    Endpoint(
                        id=ep_id,
                        method=meth,
                        path=norm_path,
                        handler_name="onRequest",
                        auth_required=auth_required or ("admin" in norm_path.lower()),
                        roles=roles if "admin" not in norm_path.lower() else ["admin"],
                        parameters=[EndpointParameter(name=p, location="path", required=True) for p in path_params],
                        database_access=has_db_sink,
                        object_identifier=bool(path_params),
                        state_changing=meth in ("POST", "PUT", "DELETE", "PATCH"),
                        external_network=has_ext_sink,
                        sensitive_data=sensitive,
                        source=SourceLocation(file=parsed_file.file_path, line_start=1, line_end=1),
                    )
                )

        return endpoints
