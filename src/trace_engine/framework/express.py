"""Express.js framework adapter for endpoint discovery."""

import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class ExpressFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Express.js routes and middleware."""

    def __init__(self):
        # Cache for parsed server/entrypoint mount configurations: {server_file_abs_path: {router_stem: (prefix, has_auth)}}
        self._server_mount_cache: Dict[str, Dict[str, Tuple[str, bool]]] = {}

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language not in ("javascript", "typescript"):
            return False
        # Express route files must import express
        return any("express" in imp.module.lower() for imp in parsed_file.imports)

    def _discover_server_mounts(self, server_path: Path) -> Dict[str, Tuple[str, bool]]:
        """Parses server.js / app.js to find router mounts like app.use('/api/discovery', discoveryRoutes)."""
        resolved_key = str(server_path.resolve())
        if resolved_key in self._server_mount_cache:
            return self._server_mount_cache[resolved_key]

        mount_map: Dict[str, Tuple[str, bool]] = {}
        try:
            content = server_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            self._server_mount_cache[resolved_key] = mount_map
            return mount_map

        # 1. Map variable names to imported file stems
        # e.g., const discoveryRoutes = require('./routes/discoveryRoutes')
        # or import discoveryRoutes from './routes/discoveryRoutes'
        var_to_stem: Dict[str, str] = {}
        import_pattern = re.compile(
            r"""(?:const|let|var|import)\s+([a-zA-Z0-9_$]+)\s*(?:=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s*['"]([^'"]+)['"])""",
            re.IGNORECASE,
        )
        for m in import_pattern.finditer(content):
            var_name = m.group(1).lower()
            imp_path = m.group(2) or m.group(3) or ""
            stem = imp_path.replace("\\", "/").split("/")[-1].split(".")[0].lower()
            if stem:
                var_to_stem[var_name] = stem
                var_to_stem[stem] = stem

        # 2. Extract app.use('/prefix', ...) statements
        # e.g., app.use('/api/discovery', discoveryRoutes);
        # or app.use('/api/discovery', verifyToken, discoveryRoutes);
        # or app.use('/api/discovery', require('./routes/discoveryRoutes'));
        use_pattern = re.compile(
            r"""(?:app|server|api|router)\.use\s*\(\s*["']([^"']+)["']\s*,\s*([^;]+)\)""",
            re.IGNORECASE | re.DOTALL,
        )
        for m in use_pattern.finditer(content):
            raw_prefix = m.group(1).strip()
            prefix = "/" + raw_prefix.strip("/") if raw_prefix.strip("/") else ""
            args_str = m.group(2)

            args = [a.strip() for a in args_str.split(",") if a.strip()]
            if not args:
                continue

            router_arg = args[-1]
            middleware_args = args[:-1]

            has_auth = any(
                any(sig in m_arg.lower() for sig in ("auth", "jwt", "passport", "verifytoken", "isauthenticated", "requireauth"))
                for m_arg in middleware_args
            )

            # Determine target router stem
            target_stem = ""
            inline_req = re.search(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", router_arg)
            if inline_req:
                req_path = inline_req.group(1)
                target_stem = req_path.replace("\\", "/").split("/")[-1].split(".")[0].lower()
            else:
                var_key = router_arg.strip().split("(")[0].strip().lower()
                target_stem = var_to_stem.get(var_key, var_key)

            if target_stem:
                mount_map[target_stem] = (prefix, has_auth)
                core_stem = re.sub(r'routes?$', '', target_stem)
                if core_stem and core_stem != target_stem:
                    mount_map[core_stem] = (prefix, has_auth)

        self._server_mount_cache[resolved_key] = mount_map
        return mount_map

    def _resolve_mount_prefix_and_auth(self, parsed_file: ParsedFile) -> Tuple[str, bool]:
        """Resolves the mount prefix and any mount-level authentication middleware for this file."""
        norm_path = parsed_file.file_path.replace("\\", "/")
        filename = norm_path.split("/")[-1]
        stem = filename.rsplit(".", 1)[0].lower()
        core_stem = re.sub(r'routes?$', '', stem)

        # Candidate directories to look for server files
        start_path = Path(parsed_file.absolute_path or parsed_file.file_path).resolve()
        candidate_dirs = [start_path.parent]
        for p in start_path.parents:
            candidate_dirs.append(p)
            if len(candidate_dirs) > 5:
                break

        server_names = (
            "server.js", "server.ts", "server.mjs", "server.cjs",
            "app.js", "app.ts", "app.mjs", "app.cjs",
            "index.js", "index.ts", "index.mjs", "index.cjs",
            "main.js", "main.ts",
        )

        for cdir in candidate_dirs:
            # Check server files directly in cdir
            for sname in server_names:
                candidate_file = cdir / sname
                if candidate_file.is_file():
                    mounts = self._discover_server_mounts(candidate_file)
                    if stem in mounts:
                        return mounts[stem]
                    if core_stem in mounts:
                        return mounts[core_stem]
                    for k, (pref, has_auth) in mounts.items():
                        if k in norm_path.lower():
                            return (pref, has_auth)

            # Check subdirectories like backend/ or src/
            for subdir in ("backend", "server", "src"):
                for sname in server_names:
                    candidate_file = cdir / subdir / sname
                    if candidate_file.is_file():
                        mounts = self._discover_server_mounts(candidate_file)
                        if stem in mounts:
                            return mounts[stem]
                        if core_stem in mounts:
                            return mounts[core_stem]
                        for k, (pref, has_auth) in mounts.items():
                            if k in norm_path.lower():
                                return (pref, has_auth)

        return ("", False)

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []

        # Multi-line regex supporting app, router, server, api
        pattern = re.compile(
            r"""(?:app|router|server|api)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*(?:,\s*([^)]+))?""",
            re.IGNORECASE | re.DOTALL,
        )

        content_lower = content.lower()
        has_db_sink = any(
            term in content_lower
            for term in ("mongoose", "prisma", "sequelize", "knex", "pool.query", "db.query", "db.collection")
        )
        has_ext_sink = any(
            term in content_lower
            for term in ("axios", "node-fetch", "fetch(", "needle", "got(", "http.request", "https.request")
        )

        # File-level router middleware: e.g. router.use(verifyToken)
        file_has_auth = bool(
            re.search(
                r"""(?:router|app)\.use\s*\(\s*[^)]*(?:auth|jwt|passport|verifytoken|isauthenticated|requireauth)""",
                content,
                re.IGNORECASE,
            )
        )

        # Discover parent mount prefix and mount-level auth
        mount_prefix, mount_has_auth = self._resolve_mount_prefix_and_auth(parsed_file)

        for match in pattern.finditer(content):
            method = match.group(1).upper()
            raw_path = match.group(2)
            handler_and_middleware = match.group(3) or ""

            # Calculate accurate line number
            line_no = content[:match.start()].count("\n") + 1

            # Convert Express :id into {id}
            norm_sub_path = re.sub(r":([a-zA-Z0-9_]+)", r"{\1}", raw_path)
            path_params = re.findall(r":([a-zA-Z0-9_]+)", raw_path)

            # Prepend mount prefix if available
            if mount_prefix:
                if norm_sub_path == "/" or not norm_sub_path:
                    final_path = mount_prefix
                elif norm_sub_path.startswith(mount_prefix):
                    final_path = norm_sub_path
                else:
                    final_path = f"{mount_prefix}/{norm_sub_path.lstrip('/')}"
            else:
                final_path = norm_sub_path

            # Clean duplicate slashes
            final_path = re.sub(r"/+", "/", final_path)

            route_auth = any(
                term in handler_and_middleware.lower()
                for term in ("auth", "jwt", "passport", "verifytoken", "isauthenticated", "requireauth")
            )
            auth_required = file_has_auth or mount_has_auth or route_auth
            roles = ["admin"] if "admin" in handler_and_middleware.lower() or "admin" in final_path.lower() else []

            ep_id = f"ep_express_{parsed_file.file_path}_{line_no}_{method}".replace("/", "_").replace(".", "_")

            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=final_path,
                    handler_name=f"route_handler_L{line_no}",
                    auth_required=auth_required,
                    roles=roles,
                    parameters=[
                        EndpointParameter(name=p, location="path", required=True)
                        for p in path_params
                    ],
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data=any(
                        term in final_path.lower()
                        for term in ("admin", "user", "order", "deliverable", "workspace", "account", "profile")
                    ),
                    source=SourceLocation(
                        file=parsed_file.file_path,
                        line_start=line_no,
                        line_end=line_no,
                    ),
                )
            )

        return endpoints
