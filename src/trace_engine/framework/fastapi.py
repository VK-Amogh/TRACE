"""FastAPI framework adapter for endpoint and attack-surface discovery."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


class FastAPIFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts FastAPI/Starlette routes and auth gates."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "python":
            return False
        for imp in parsed_file.imports:
            if "fastapi" in imp.module.lower() or "starlette" in imp.module.lower():
                return True
        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        ep_count = 0

        # Also search decorators in parsed functions
        for fn in parsed_file.functions:
            for dec in fn.decorators:
                dec_text = dec.raw_text.strip()
                # Pattern: @app.get('/path' ...) or @router.post('/path' ...)
                match = re.search(
                    r"""@?(?:[a-zA-Z0-9_]+)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""",
                    dec_text,
                    re.IGNORECASE,
                )
                if match:
                    ep_count += 1
                    method = match.group(1).upper()
                    path = match.group(2)
                    ep_id = f"ep_{parsed_file.file_path.replace('/', '_').replace('.', '_')}_{fn.name}_{method}"

                    # Detect path parameters: {param_name}
                    path_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
                    params: List[EndpointParameter] = [
                        EndpointParameter(name=p, location="path", required=True)
                        for p in path_params
                    ]

                    # Detect function params from AST
                    for p in fn.parameters:
                        if p.name not in ("self", "cls") and p.name not in path_params:
                            params.append(
                                EndpointParameter(
                                    name=p.name,
                                    location="query" if method == "GET" else "body",
                                    param_type=p.type_annotation or "string",
                                )
                            )

                    # Analyze auth dependencies in decorator or args
                    auth_required = False
                    roles = []
                    fn_body = fn.body_text or ""
                    
                    auth_indicators = [
                        "current_user",
                        "auth",
                        "token",
                        "security",
                        "jwt",
                        "oauth",
                        "credentials",
                        "verify_token",
                        "api_key",
                    ]
                    for p in fn.parameters:
                        p_ann = (p.type_annotation or "").lower()
                        p_def = (p.default_value or "").lower()
                        if any(ind in p.name.lower() or ind in p_ann or ind in p_def for ind in auth_indicators):
                            auth_required = True
                        if "admin" in p.name.lower() or "admin" in p_ann or "admin" in p_def:
                            roles.append("admin")

                    if "require_admin" in dec_text.lower() or "admin" in path.lower():
                        roles.append("admin")
                    if "current_user" in dec_text.lower() or "depends(get_current_user" in dec_text.lower():
                        auth_required = True

                    # Object identifier flag (e.g. /items/{id})
                    has_obj_id = any(
                        p in ("id", "user_id", "order_id", "product_id", "item_id")
                        for p in path_params
                    )

                    # State changing
                    state_changing = method in ("POST", "PUT", "DELETE", "PATCH")

                    # Database access check
                    db_access = any(
                        term in fn_body.lower()
                        for term in ("db.", "session.", "cursor.", "repository", "query(", ".filter(", "orders", "database", "find")
                    )

                    # Outbound network (SSRF indicator)
                    ext_network = any(
                        term in fn_body.lower()
                        for term in ("requests.", "httpx.", "urllib.", "aiohttp.", "fetch(")
                    )

                    # Sensitive data
                    sensitive = any(
                        term in path.lower() or term in fn_body.lower()
                        for term in ("password", "secret", "token", "credit", "card", "user", "order", "refund", "admin")
                    )

                    endpoints.append(
                        Endpoint(
                            id=ep_id,
                            method=method,
                            path=path,
                            handler_name=fn.qualified_name,
                            auth_required=auth_required,
                            roles=list(set(roles)),
                            parameters=params,
                            database_access=db_access,
                            object_identifier=has_obj_id,
                            state_changing=state_changing,
                            external_network=ext_network,
                            sensitive_data=sensitive,
                            source=fn.location,
                        )
                    )

        return endpoints
