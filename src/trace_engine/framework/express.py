"""Express.js framework adapter for endpoint discovery."""

import re
from typing import List
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class ExpressFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Express.js routes and middleware."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language not in ("javascript", "typescript"):
            return False
        return any("express" in imp.module.lower() for imp in parsed_file.imports)

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        lines = content.splitlines()

        # Regex for app.get('/path', ...) or router.post('/path', authMiddleware, ...)
        pattern = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*(?:,\s*([a-zA-Z0-9_,\s]+))?""",
            re.IGNORECASE,
        )

        for line_no, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                method = match.group(1).upper()
                raw_path = match.group(2)
                middleware_str = match.group(3) or ""

                # Convert Express :id into {id}
                norm_path = re.sub(r":([a-zA-Z0-9_]+)", r"{\1}", raw_path)
                path_params = re.findall(r":([a-zA-Z0-9_]+)", raw_path)

                auth_required = any(
                    term in middleware_str.lower()
                    for term in ("auth", "jwt", "passport", "verifytoken", "isauthenticated")
                )
                roles = ["admin"] if "admin" in middleware_str.lower() or "admin" in norm_path.lower() else []

                ep_id = f"ep_express_{parsed_file.file_path}_{line_no}_{method}".replace("/", "_").replace(".", "_")

                endpoints.append(
                    Endpoint(
                        id=ep_id,
                        method=method,
                        path=norm_path,
                        handler_name=f"route_handler_L{line_no}",
                        auth_required=auth_required,
                        roles=roles,
                        parameters=[
                            EndpointParameter(name=p, location="path", required=True)
                            for p in path_params
                        ],
                        database_access=False,
                        object_identifier=bool(path_params),
                        state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                        external_network=False,
                        sensitive_data="admin" in norm_path.lower() or "user" in norm_path.lower(),
                        source=SourceLocation(
                            file=parsed_file.file_path,
                            line_start=line_no,
                            line_end=line_no,
                        ),
                    )
                )

        return endpoints
