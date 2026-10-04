"""React Router v7 and Remix framework adapter for endpoint discovery."""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class ReactRouterFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts React Router v7 and Remix endpoints, loaders, and actions."""

    def __init__(self):
        # Maps (normalized_file_key) -> url_path
        self._route_cache: Dict[str, str] = {}
        self._parsed_route_files: set = set()

    def _normalize_key(self, path_str: str) -> str:
        clean = path_str.replace("\\", "/").strip("/")
        if clean.startswith("app/"):
            clean = clean[4:]
        return clean

    def _discover_and_parse_routes_file(self, parsed_file: ParsedFile) -> None:
        """Looks up routes.ts / routes.js up the directory tree and caches mappings."""
        file_p = Path(parsed_file.absolute_path) if parsed_file.absolute_path else Path(parsed_file.file_path)
        candidates = []

        if file_p.is_absolute():
            search_dirs = [file_p.parent] + list(file_p.parents)
        else:
            search_dirs = [Path(".").resolve()]

        for d in search_dirs:
            for cand_name in ("app/routes.ts", "routes.ts", "app/routes.js", "routes.js", "app/routes.tsx", "routes.tsx"):
                cand = d / cand_name
                if cand.exists() and cand.is_file():
                    candidates.append(cand)
                    break
            if candidates:
                break

        for cand in candidates:
            abs_cand_str = str(cand.resolve())
            if abs_cand_str in self._parsed_route_files:
                continue
            self._parsed_route_files.add(abs_cand_str)
            try:
                content = cand.read_text(encoding="utf-8", errors="replace")
                self._parse_routes_config(content)
            except Exception:
                pass

    def _parse_routes_config(self, content: str) -> None:
        """Parses route definitions from React Router v7 routes.ts."""
        # 1. index("routes/home.tsx")
        for m in re.finditer(r'''index\s*\(\s*["']([^"']+)["']''', content):
            file_target = self._normalize_key(m.group(1))
            self._route_cache[file_target] = "/"

        # 2. route("path", "file")
        for m in re.finditer(r'''route\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']''', content):
            path_part = m.group(1)
            file_target = self._normalize_key(m.group(2))
            norm_url = "/" + path_part.lstrip("/")
            self._route_cache[file_target] = norm_url

        # 3. layout("layout_file", [ ... ])
        # Also map layout file if needed
        for m in re.finditer(r'''layout\s*\(\s*["']([^"']+)["']''', content):
            file_target = self._normalize_key(m.group(1))
            if file_target not in self._route_cache:
                self._route_cache[file_target] = "/admin" if "admin" in file_target else "/"

    def _infer_path_from_filename(self, file_path: str) -> str:
        """Derives route path from Remix / React Router convention-based file names."""
        clean = self._normalize_key(file_path)
        # Strip routes/ prefix
        if clean.startswith("routes/"):
            clean = clean[7:]

        # Strip extension
        clean = re.sub(r'\.(tsx|ts|jsx|js)$', '', clean)

        # Handle escaped characters like sitemap[.xml] -> sitemap.xml
        clean = clean.replace("[.", ".").replace(".]", ".")
        clean = clean.replace("[", "").replace("]", "")

        # Dots in flat routes represent slashes: api.check-username -> api/check-username
        clean = clean.replace(".", "/")

        # Remix param conventions: $id -> {id}, :id -> {id}
        clean = re.sub(r'\$([a-zA-Z0-9_]+)', r'{\1}', clean)
        clean = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', clean)

        # Index routes
        clean = re.sub(r'(?:^|/)_?index$', '', clean)

        # Remove pathless layout segments (e.g. _auth, _public)
        parts = [p for p in clean.split("/") if not (p.startswith("_") and not p == "")]
        clean = "/".join(parts)

        norm_path = "/" + clean.lstrip("/")
        return norm_path or "/"

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language not in ("javascript", "typescript"):
            return False

        norm_path = parsed_file.file_path.replace("\\", "/").lower()
        basename = norm_path.split("/")[-1]

        # Ignore configuration files, test files, and hidden/dot files
        if "config" in basename or basename.startswith(".") or ".test." in basename or ".spec." in basename:
            return False

        # Reject Express / Koa / Fastify backend route files
        for imp in parsed_file.imports:
            imp_low = imp.module.lower()
            if imp_low in ("express", "koa", "fastify", "hapi", "@nestjs/common"):
                return False

        # Reject backend directories (Express / Node.js backend controllers are not React Router)
        if any(norm_path.startswith(d) or f"/{d}" in norm_path for d in ("backend/", "server/", "api/", "controllers/", "srv/")):
            return False

        # Reject UI component directories and non-route code
        non_route_dirs = (
            "/components/", "/ui/", "/layouts/", "/widgets/",
            "/hooks/", "/context/", "/styles/", "/types/",
            "/lib/", "/utils/", "/helpers/", "/assets/", "/icons/"
        )
        if any(d in norm_path for d in non_route_dirs) or any(norm_path.startswith(d.lstrip("/")) for d in non_route_dirs):
            return False

        # If it's the routes configuration file itself
        if re.search(r'(?:^|/)(?:app/)?routes\.(ts|js|tsx|jsx)$', norm_path):
            return True

        # Lazy check and load routes.ts if present
        self._discover_and_parse_routes_file(parsed_file)

        # Check if file is in cached route table
        key = self._normalize_key(norm_path)
        if key in self._route_cache:
            return True

        # Only match files strictly in frontend routes directory (app/routes/ or src/routes/)
        if re.search(r'(?:^|/)(?:src/|app/)?routes/.+\.[a-zA-Z0-9]+$', norm_path):
            if any(f"/{d}/" in norm_path for d in ("styles", "assets", "types", "+types", "components")):
                return False
            return True

        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")

        # Ensure routes.ts is parsed
        self._discover_and_parse_routes_file(parsed_file)

        # If this file is routes.ts itself, the routes are mapped to individual handler files
        if re.search(r'(?:^|/)(?:app/)?routes\.(ts|js|tsx|jsx)$', norm_file_path):
            # Parse route config to make sure route cache is up to date
            self._parse_routes_config(content)
            return []

        # Determine route URL path
        norm_key = self._normalize_key(norm_file_path)
        raw_path = self._route_cache.get(norm_key)
        if not raw_path:
            # Try alternate key without leading dir
            basename = norm_file_path.split("/")[-1]
            raw_path = self._route_cache.get(basename)

        if not raw_path:
            raw_path = self._infer_path_from_filename(norm_file_path)

        # Normalize dynamic path segments :id -> {id}
        url_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', raw_path)
        url_path = re.sub(r'\$([a-zA-Z0-9_]+)', r'{\1}', url_path)

        path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', url_path)

        # Analyze handler bodies and symbols
        content_lower = content.lower()

        # Database sinks
        has_db_sink = any(
            term in content_lower
            for term in (
                "supabase", "prisma", "sequelize", "mongoose", "knex",
                "pool.query", "client.query", "db.query", "db.select",
                ".from(", ".rpc(", ".server"
            )
        )

        # External network sinks
        has_ext_sink = any(
            term in content_lower
            for term in (
                "axios", "fetch(", "nodemailer", "got(", "needle",
                "http.request", "https.request", "transporter.sendmail",
                "octokit", "stripe"
            )
        )

        # Authentication & Role detection
        auth_signals = (
            "requireauth", "requireadmin", "requireadmingate", "getsessionuser",
            "requiregithub", "supabase.auth", "verifytoken", "jwt.verify",
            "isauthenticated", "authsession", "getserversession", "getauth"
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

        # Parameters
        parameters: List[EndpointParameter] = [
            EndpointParameter(name=p, location="path", required=True, user_controlled=True)
            for p in path_params
        ]

        # Extract Query Parameters: searchParams.get("...")
        for m in re.finditer(r'''(?:searchParams|nextUrl\.searchParams)\.get\s*\(\s*["']([^"']+)["']''', content):
            p_name = m.group(1)
            if not any(p.name == p_name for p in parameters):
                parameters.append(
                    EndpointParameter(name=p_name, location="query", required=False, user_controlled=True)
                )

        # Extract Body Parameters: formData.get("...")
        for m in re.finditer(r'''formData\.get\s*\(\s*["']([^"']+)["']''', content):
            p_name = m.group(1)
            if not any(p.name == p_name for p in parameters):
                parameters.append(
                    EndpointParameter(name=p_name, location="body", required=True, user_controlled=True)
                )

        # Check for loader (GET)
        loader_match = re.search(
            r'''(?:export\s+)?(?:async\s+)?function\s+loader\b|export\s+(?:const|let|var)\s+loader\b''',
            content
        )
        if loader_match:
            line_no = content[:loader_match.start()].count("\n") + 1
            ep_id = f"ep_rr_get_{norm_file_path}_{line_no}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method="GET",
                    path=url_path,
                    handler_name="loader",
                    auth_required=auth_required,
                    roles=roles,
                    parameters=parameters,
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=False,
                    external_network=has_ext_sink,
                    sensitive_data=sensitive_data,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        # Check for action (POST / mutation)
        action_match = re.search(
            r'''(?:export\s+)?(?:async\s+)?function\s+action\b|export\s+(?:const|let|var)\s+action\b''',
            content
        )
        if action_match:
            line_no = content[:action_match.start()].count("\n") + 1
            ep_id = f"ep_rr_post_{norm_file_path}_{line_no}".replace("/", "_").replace(".", "_")
            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method="POST",
                    path=url_path,
                    handler_name="action",
                    auth_required=auth_required,
                    roles=roles,
                    parameters=parameters,
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=True,
                    external_network=has_ext_sink,
                    sensitive_data=sensitive_data,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        # Check for explicit HTTP verbs: GET, POST, PUT, DELETE, PATCH
        for v_match in re.finditer(r'''export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b''', content):
            verb = v_match.group(1).upper()
            line_no = content[:v_match.start()].count("\n") + 1
            ep_id = f"ep_rr_{verb.lower()}_{norm_file_path}_{line_no}".replace("/", "_").replace(".", "_")
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

        # If file defines neither loader nor action nor explicit HTTP verbs, it is a pure UI component
        # and has no backend server attack surface
        return endpoints
