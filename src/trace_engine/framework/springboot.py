"""Spring Boot Java and Kotlin framework adapter."""

import re
from typing import List, Dict, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation


class SpringBootFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Spring Boot REST endpoints, annotations, and security policies."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language not in ("java", "kotlin"):
            return False

        # Check imports
        for imp in parsed_file.imports:
            mod_low = imp.module.lower()
            if any(term in mod_low for term in ("org.springframework", "io.ktor", "javax.ws.rs", "jakarta.ws.rs")):
                return True

        return True

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        norm_file_path = parsed_file.file_path.replace("\\", "/")
        content_lower = content.lower()

        # Database sinks
        has_db_sink = any(
            term in content_lower
            for term in (
                "repository", "findbyid", "findall", "save(", "deletebyid",
                "jdbctemplate", "entitymanager", "hibernate", "jpa", "r2dbc",
                "select ", "from "
            )
        )

        # External network sinks
        has_ext_sink = any(
            term in content_lower
            for term in (
                "resttemplate", "webclient", "httpclient", "feignclient",
                "openfeign", "okhttp", "httpurlconnection"
            )
        )

        # Class-level RequestMapping
        class_base = ""
        class_rm = re.search(
            r'''@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']''',
            content
        )
        if class_rm:
            class_base = "/" + class_rm.group(1).strip("/")

        # Method-level mappings: @GetMapping, @PostMapping, etc.
        annot_pat = re.compile(
            r'''@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']\s*\))?''',
            re.IGNORECASE
        )

        verbs = {
            "getmapping": "GET",
            "postmapping": "POST",
            "putmapping": "PUT",
            "deletemapping": "DELETE",
            "patchmapping": "PATCH",
            "requestmapping": "GET",
        }

        for match in annot_pat.finditer(content):
            annot = match.group(1).lower()
            sub_path = match.group(2) or ""

            # Skip class-level RequestMapping
            after_snippet = content[match.end():match.end() + 100]
            if re.search(r'\bclass\s+[a-zA-Z0-9_$]+', after_snippet):
                continue

            method = verbs.get(annot, "GET")
            line_no = content[:match.start()].count("\n") + 1

            # Extract method name and parameters following the annotation
            after_annot = content[match.end():match.end() + 500]
            fn_match = re.search(
                r'''(?:fun\s+|[a-zA-Z0-9_<>,?\[\]\s]+\s+)([a-zA-Z0-9_$]+)\s*\((.*?)\)''',
                after_annot,
                re.DOTALL
            )
            fn_name = fn_match.group(1) if fn_match else f"handler_L{line_no}"
            raw_params = fn_match.group(2) if fn_match else ""

            full_path = (class_base + "/" + sub_path.strip("/")).rstrip("/")
            if not full_path:
                full_path = "/"

            path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', full_path)

            # Parameters extraction from method signature
            parameters: List[EndpointParameter] = [
                EndpointParameter(name=p, location="path", required=True) for p in path_params
            ]

            # Query params: @RequestParam("...")
            for qm in re.finditer(r'''@RequestParam\s*(?:\(\s*(?:value\s*=\s*)?["']([^"']+)["']\s*\))?''', raw_params):
                p_name = qm.group(1) or "query"
                if not any(p.name == p_name for p in parameters):
                    parameters.append(EndpointParameter(name=p_name, location="query", required=False))

            # Auth detection
            snippet = content[max(0, match.start() - 200) : match.end() + 200].lower()
            auth_required = any(
                term in snippet for term in ("preauthorize", "secured", "rolesallowed", "securitycontext", "authentication")
            ) or ("admin" in full_path.lower())

            roles = ["admin"] if "admin" in snippet or "admin" in full_path.lower() else []

            sensitive = any(
                term in full_path.lower() or term in content_lower
                for term in ("admin", "user", "auth", "patient", "order", "billing", "payment", "token", "secret", "record")
            )

            ep_id = f"ep_jvm_{norm_file_path}_{line_no}_{method}".replace("/", "_").replace(".", "_")

            endpoints.append(
                Endpoint(
                    id=ep_id,
                    method=method,
                    path=full_path,
                    handler_name=fn_name,
                    auth_required=auth_required,
                    roles=roles,
                    parameters=parameters,
                    database_access=has_db_sink,
                    object_identifier=bool(path_params),
                    state_changing=method in ("POST", "PUT", "DELETE", "PATCH"),
                    external_network=has_ext_sink,
                    sensitive_data=sensitive,
                    source=SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no),
                )
            )

        return endpoints
