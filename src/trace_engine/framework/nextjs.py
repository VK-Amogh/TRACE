"""Next.js framework adapter for App Router and Pages Router endpoint discovery."""

import re
from pathlib import Path
from typing import List, Dict, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class NextJSFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Next.js API routes, route handlers, and page endpoints."""

    def _infer_app_router_path(self, norm_path: str) -> str:
        # Strip leading app/ or src/app/
        clean = norm_path
        if clean.startswith("src/app/"):
            clean = clean[8:]
        elif clean.startswith("app/"):
            clean = clean[4:]

        # Strip trailing /route.ts, /route.js, /page.tsx, etc.
        clean = re.sub(r'/(?:route|page)\.[a-zA-Z0-9]+$', '', clean)

        # Remove route groups like (auth), (dashboard)
        parts = [p for p in clean.split("/") if not (p.startswith("(") and p.endswith(")"))]
        clean = "/".join(parts)

        # Normalize Next.js params: [[...slug]] -> {slug}, [...slug] -> {slug}, [id] -> {id}
        clean = re.sub(r'\[\[?\.\.\.([a-zA-Z0-9_]+)\]?\]', r'{\1}', clean)
        clean = re.sub(r'\[([a-zA-Z0-9_]+)\]', r'{\1}', clean)

        norm_url = "/" + clean.lstrip("/")
        return norm_url or "/"

    def _infer_pages_router_path(self, norm_path: str) -> str:
        # Strip leading pages/ or src/pages/
        clean = norm_path
        if clean.startswith("src/pages/"):
            clean = clean[10:]
        elif clean.startswith("pages/"):
            clean = clean[6:]

        # Strip file extension
        clean = re.sub(r'\.[a-zA-Z0-9]+$', '', clean)

        # Normalize params: [id] -> {id}
        clean = re.sub(r'\[\[?\.\.\.([a-zA-Z0-9_]+)\]?\]', r'{\1}', clean)
        clean = re.sub(r'\[([a-zA-Z0-9_]+)\]', r'{\1}', clean)

        # Strip index
        clean = re.sub(r'(?:^|/)index$', '', clean)

        norm_url = "/" + clean.lstrip("/")
        return norm_url or "/"

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language not in ("javascript", "typescript"):
            return False

        norm_path = parsed_file.file_path.replace("\\", "/")

        # App Router route/page
        if re.search(r'(?:^|/)(?:src/)?app/.+/(?:route|page)\.[a-zA-Z0-9]+$', norm_path):
            return True

        # Pages Router api or page
        if re.search(r'(?:^|/)(?:src/)?pages/(?:api/)?.+\.[a-zA-Z0-9]+$', norm_path):
            return True

        # Imports from next
        for imp in parsed_file.imports:
            mod_low = imp.module.lower()
            if mod_low == "next" or mod_low.startswith("next/"):
                return True

        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")

        is_app_router = bool(re.search(r'(?:^|/)(?:src/)?app/', norm_file_path))
        is_pages_router = bool(re.search(r'(?:^|/)(?:src/)?pages/', norm_file_path))

        if is_app_router:
            url_path = self._infer_app_router_path(norm_file_path)
        elif is_pages_router:
            url_path = self._infer_pages_router_path(norm_file_path)
        else:
            url_path = "/" + norm_file_path.split("/")[-1].split(".")[0]

        path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', url_path)

        content_lower = content.lower()
        has_db_sink = any(
            term in content_lower
            for term in (
                "prisma", "mongoose", "sequelize", "supabase", "knex",
                "pool.query", "client.query", "db.query", "db.select", ".from("
            )
        )
        has_ext_sink = any(
            term in content_lower
            for term in (
                "axios", "fetch(", "nodemailer", "got(", "needle",
                "http.request", "https.request", "transporter.sendmail", "octokit", "stripe"
            )
        )

        auth_signals = (
            "getserversession", "getauth", "auth()", "clerk", "next-auth",
            "verifytoken", "requireauth", "requireadmin", "jwt.verify", "supabase.auth"
        )
        auth_required = any(sig in content_lower for sig in auth_signals) or "admin" in url_path.lower()
        roles = ["admin"] if "admin" in content_lower or "admin" in url_path.lower() else []

        sensitive_data = any(
            term in url_path.lower() or term in content_lower
            for term in (
                "admin", "user", "auth", "login", "register", "profile",
                "password", "token", "secret", "webhook", "session", "payment"
            )
        )

        parameters: List[EndpointParameter] = [
            EndpointParameter(name=p, location="path", required=True, user_controlled=True)
            for p in path_params
        ]

        # Extract searchParams
        for m in re.finditer(r'''(?:searchParams|nextUrl\.searchParams)\.get\s*\(\s*["']([^"']+)["']''', content):
            p_name = m.group(1)
            if not any(p.name == p_name for p in parameters):
                parameters.append(
                    EndpointParameter(name=p_name, location="query", required=False, user_controlled=True)
                )

        # App Router named exports: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
        app_verbs = list(re.finditer(
            r'''export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b''',
            content
        ))

        for v_match in app_verbs:
            verb = v_match.group(1).upper()
            line_no = content[:v_match.start()].count("\n") + 1
            ep_id = f"ep_next_{verb.lower()}_{norm_file_path}_{line_no}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=verb,
                    path=url_path,
                    handler_name=verb,
                    auth_required=auth_required,
                    roles=roles,
                    parameters=parameters,
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=verb in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data=sensitive_data,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        # Pages Router or App Router default export
        if not endpoints:
            # Check for checked HTTP methods in handler body
            checked_methods = []
            for m in re.finditer(r'''req\.method\s*===?\s*["'](GET|POST|PUT|DELETE|PATCH)["']''', content):
                checked_methods.append(m.group(1).upper())

            methods_to_add = set(checked_methods) if checked_methods else (["GET"] if "page." in norm_file_path else ["GET", "POST"])

            default_match = re.search(r'''export\s+default\s+(?:async\s+)?(?:function|const|class)?\s*([a-zA-Z0-9_$]+)?''', content)
            handler_name = default_match.group(1) if (default_match and default_match.group(1)) else "handler"
            line_no = content[:default_match.start()].count("\n") + 1 if default_match else 1

            for meth in sorted(methods_to_add):
                ep_id = f"ep_next_{meth.lower()}_{norm_file_path}_{line_no}".replace("/", "_").replace(".", "_")
                endpoints.append(
                    Endpoint(
                        id=ep_id,
                        method=meth,
                        path=url_path,
                        handler_name=handler_name,
                        auth_required=auth_required,
                        roles=roles,
                        parameters=parameters,
                        database_access=has_db_sink,
                        object_identifier=bool(path_params),
                        state_changing=meth in ("POST", "PUT", "DELETE", "PATCH"),
                        external_network=has_ext_sink,
                        sensitive_data=sensitive_data,
                        source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                    )
                )

        return endpoints
