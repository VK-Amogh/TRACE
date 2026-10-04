"""Rust framework adapter for Actix-web, Axum, and Rocket route extraction."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class RustFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Rust routes from Actix-web, Axum, and Rocket."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "rust":
            norm = parsed_file.file_path.replace("\\", "/").lower()
            return norm.endswith(".rs")
        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        has_db_sink = any(
            term in content_lower
            for term in ("sqlx::", "diesel::", "sea_orm", "query_as!", "query!", "execute(")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("reqwest::", "hyper::", "surf::")
        )

        # 1. Actix-web / Rocket macros: #[get("/path/{id}")] or #[post("/path")]
        macro_pattern = re.compile(
            r"""#\[(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*\)\]\s*(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)""",
            re.IGNORECASE,
        )
        for match in macro_pattern.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2).strip()
            handler = match.group(3).strip()
            line_no = content[:match.start()].count("\n") + 1

            norm_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            norm_path = re.sub(r'<([a-zA-Z0-9_]+)>', r'{\1}', norm_path)
            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)

            ep_id = f"ep_rust_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler,
                    auth_required="auth" in content_lower or "claims" in content_lower,
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

        # 2. Axum routes: .route("/path", get(handler)) or post(handler)
        axum_pattern = re.compile(
            r"""\.route\s*\(\s*["']([^"']+)["']\s*,\s*(get|post|put|delete|patch)\s*\(\s*([a-zA-Z0-9_:]+)\s*\)\s*\)""",
            re.IGNORECASE,
        )
        for match in axum_pattern.finditer(content):
            raw_path = match.group(1).strip()
            method = match.group(2).upper()
            handler = match.group(3).strip()
            line_no = content[:match.start()].count("\n") + 1

            norm_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
            norm_path = "/" + norm_path.lstrip("/")
            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', norm_path)

            ep_id = f"ep_rust_axum_{norm_file}_{line_no}_{method}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=norm_path,
                    handler_name=handler,
                    auth_required="auth" in content_lower or "claims" in content_lower,
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
