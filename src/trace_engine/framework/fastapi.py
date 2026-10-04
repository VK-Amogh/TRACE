"""FastAPI framework adapter for endpoint and attack-surface discovery."""

import re
from typing import List, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "websocket"}


class FastAPIFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts FastAPI/Starlette routes, WebSockets, static mounts, and auth gates."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "python":
            return False
        for imp in parsed_file.imports:
            if "fastapi" in imp.module.lower() or "starlette" in imp.module.lower():
                return True
        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        existing_keys = set()

        # 1. Search decorators on parsed AST functions
        for fn in parsed_file.functions:
            for dec in fn.decorators:
                dec_text = dec.raw_text.strip()
                # Pattern: @app.get('/path' ...), @router.post('/path' ...), @app.websocket('/ws/...')
                match = re.search(
                    r"""@?(?:[a-zA-Z0-9_]+)\.(get|post|put|delete|patch|websocket|api_route)\s*\(\s*["']([^"']+)["']""",
                    dec_text,
                    re.IGNORECASE,
                )
                if match:
                    raw_verb = match.group(1).upper()
                    method = "WEBSOCKET" if raw_verb == "WEBSOCKET" else ("GET" if raw_verb == "API_ROUTE" else raw_verb)
                    path = match.group(2)
                    key = (method, path)
                    if key in existing_keys:
                        continue
                    existing_keys.add(key)

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
                                    location="query" if method in ("GET", "WEBSOCKET") else "body",
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
                        "require_admin",
                        "get_current_user",
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
                    if "current_user" in dec_text.lower() or "depends(" in dec_text.lower():
                        auth_required = True

                    # Object identifier flag: e.g. /items/{id}, /athlete/{athlete_id}, /coach/{coach_id}
                    has_obj_id = any(
                        p.lower() == "id" or p.lower().endswith("_id") or p.lower().endswith("id")
                        for p in path_params
                    )

                    # State changing
                    state_changing = method in ("POST", "PUT", "DELETE", "PATCH")

                    # Database access check
                    db_access = any(
                        term in fn_body.lower()
                        for term in ("db.", "session.", "cursor.", "repository", "query(", ".filter(", "database", "models.")
                    )

                    # Outbound network (SSRF indicator)
                    ext_network = any(
                        term in fn_body.lower()
                        for term in ("requests.", "httpx.", "urllib.", "aiohttp.", "fetch(")
                    )

                    # Sensitive data
                    sensitive = any(
                        term in path.lower() or term in fn_body.lower()
                        for term in ("password", "secret", "token", "credit", "card", "user", "order", "refund", "admin", "coach", "athlete", "story", "session")
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

        # 2. Detect StaticFiles mounts e.g. app.mount("/session_videos", StaticFiles(directory="session_videos"), name="session_videos")
        mount_pattern = re.compile(
            r"""(?:app|router)\.mount\s*\(\s*["']([^"']+)["']\s*,\s*StaticFiles\s*\(\s*(?:directory\s*=\s*)?["']([^"']+)["']""",
            re.IGNORECASE,
        )
        for match in mount_pattern.finditer(content):
            mount_path = match.group(1).rstrip("/")
            directory = match.group(2)
            line_no = content[:match.start()].count("\n") + 1
            ep_id = f"ep_{parsed_file.file_path.replace('/', '_').replace('.', '_')}_mount_{directory}_GET"
            key = ("GET", f"{mount_path}/{{filepath}}")
            if key not in existing_keys:
                existing_keys.add(key)
                endpoints.append(
                    Endpoint(
                        id=ep_id,
                        method="GET",
                        path=f"{mount_path}/{{filepath}}",
                        handler_name=f"StaticFiles({directory})",
                        auth_required=False,
                        roles=[],
                        parameters=[
                            EndpointParameter(name="filepath", location="path", required=True)
                        ],
                        database_access=False,
                        object_identifier=True,
                        state_changing=False,
                        external_network=False,
                        sensitive_data=True,
                        source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                    )
                )

        # 3. Direct regex fallback across raw content to catch routes missed by AST function traversal
        raw_route_pat = re.compile(
            r"""@(?:app|router|api_router)\.(get|post|put|delete|patch|websocket)\s*\(\s*["']([^"']+)["']""",
            re.IGNORECASE,
        )
        for match in raw_route_pat.finditer(content):
            raw_verb = match.group(1).upper()
            method = "WEBSOCKET" if raw_verb == "WEBSOCKET" else raw_verb
            path = match.group(2)
            key = (method, path)
            if key in existing_keys:
                continue
            existing_keys.add(key)

            line_no = content[:match.start()].count("\n") + 1
            path_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
            has_obj_id = any(
                p.lower() == "id" or p.lower().endswith("_id") or p.lower().endswith("id")
                for p in path_params
            )
            endpoints.append(
                Endpoint(
                    id=f"ep_{parsed_file.file_path.replace('/', '_').replace('.', '_')}_L{line_no}_{method}",
                    method=method,
                    path=path,
                    handler_name=f"route_L{line_no}",
                    auth_required=False,
                    roles=["admin"] if "admin" in path.lower() else [],
                    parameters=[
                        EndpointParameter(name=p, location="path", required=True)
                        for p in path_params
                    ],
                    database_access=True,
                    object_identifier=has_obj_id,
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=False,
                    sensitive_data="admin" in path.lower() or "user" in path.lower() or "session" in path.lower() or "story" in path.lower(),
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        return endpoints
