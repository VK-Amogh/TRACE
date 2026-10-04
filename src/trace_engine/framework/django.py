"""Django and Django REST Framework adapter for endpoint and route discovery."""

import re
from typing import List, Set, Optional
from trace_engine.parsing.parser import ParsedFile
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter


class DjangoFrameworkAdapter(FrameworkAdapter):
    """Detects and extracts Django and Django REST Framework (DRF) endpoints, URL routing, and security decorators."""

    def can_handle(self, parsed_file: ParsedFile) -> bool:
        if parsed_file.language != "python":
            return False
        # Check imports for Django or DRF
        for imp in parsed_file.imports:
            mod = imp.module.lower()
            if "django" in mod or "rest_framework" in mod:
                return True
        # Check file naming conventions or patterns
        if "urls.py" in parsed_file.file_path.lower() or "views.py" in parsed_file.file_path.lower():
            return True
        return False

    def extract_endpoints(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []

        # 1. Parse urls.py patterns: path('api/v1/orders/<int:order_id>/', views.get_order)
        endpoints.extend(self._extract_from_urlpatterns(parsed_file, content))

        # 2. Parse views.py: Class-Based Views (APIView, View, ViewSet) and function views (@api_view)
        endpoints.extend(self._extract_from_views(parsed_file, content))

        return endpoints

    def _extract_from_urlpatterns(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        if "urlpatterns" not in content and "path(" not in content and "re_path(" not in content:
            return endpoints

        # Pattern: path('orders/<int:order_id>/', views.order_detail, name='order-detail')
        # Pattern: re_path(r'^api/v1/export/?$', ExportView.as_view())
        path_pattern = re.compile(
            r"""(?:path|re_path)\s*\(\s*r?["']([^"']*)["']\s*,\s*([a-zA-Z0-9_\.]+)(?:\.as_view\s*\(\s*\))?""",
            re.MULTILINE,
        )

        for match in path_pattern.finditer(content):
            raw_path = match.group(1).strip()
            handler_name = match.group(2).strip()

            # Normalize Django path converters: <int:id>, <str:slug>, <uuid:pk> -> {id}, {slug}, {pk}
            path_params = re.findall(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", raw_path)
            clean_path = re.sub(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", r"{\1}", raw_path)
            # Remove regex anchor symbols
            clean_path = re.sub(r"[\^\$\?]+", "", clean_path).rstrip("/")
            norm_path = clean_path if clean_path.startswith("/") else f"/{clean_path}"

            # Infer methods: standard Django views typically handle GET or POST
            methods = ["GET"]
            if any(term in handler_name.lower() for term in ("create", "delete", "update", "post", "mutation", "reset", "patch")):
                methods = ["POST"]

            auth_required = any(
                term in content.lower()
                for term in ("login_required", "isauthenticated", "permission_classes", "tokenauthentication")
            )
            roles = ["admin"] if "admin" in handler_name.lower() or "admin" in norm_path.lower() else []

            line_no = content[: match.start()].count("\n") + 1
            src_loc = SourceLocation(file=parsed_file.file_path, line_start=line_no, line_end=line_no, column_start=0, column_end=0)

            for m in methods:
                ep_id = f"ep_django_{parsed_file.file_path}_{handler_name}_{m}".replace("/", "_").replace(".", "_")
                endpoints.append(
                    Endpoint(
                        id=ep_id,
                        method=m,
                        path=norm_path,
                        handler_name=handler_name,
                        auth_required=auth_required,
                        roles=roles,
                        parameters=[
                            EndpointParameter(name=p, location="path", required=True)
                            for p in path_params
                        ],
                        database_access=True,  # Django views almost universally access ORM models
                        object_identifier=bool(path_params),
                        state_changing=m in ("POST", "PUT", "DELETE", "PATCH"),
                        external_network=False,
                        sensitive_data="admin" in norm_path.lower() or "auth" in norm_path.lower() or "user" in norm_path.lower(),
                        source=src_loc,
                    )
                )

        return endpoints

    def _extract_from_views(self, parsed_file: ParsedFile, content: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        content_lines = content.splitlines()

        # 1. DRF @api_view(['GET', 'POST'])
        for fn in parsed_file.functions:
            fn_methods = []
            for dec in fn.decorators:
                dec_text = dec.raw_text.strip()
                api_match = re.search(r"""@?api_view\s*\(\s*\[([^\]]+)\]""", dec_text, re.IGNORECASE)
                if api_match:
                    fn_methods = [
                        m.strip().strip("'\"").upper()
                        for m in api_match.group(1).split(",")
                        if m.strip()
                    ]

            if fn_methods:
                fn_body = fn.body_text or ""
                auth_required = any(
                    term in fn_body.lower() or term in "".join(d.raw_text.lower() for d in fn.decorators)
                    for term in ("isauthenticated", "isadminuser", "login_required", "permission_classes")
                )
                roles = ["admin"] if "admin" in fn.name.lower() else []
                for m in fn_methods:
                    ep_id = f"ep_drf_{parsed_file.file_path}_{fn.name}_{m}".replace("/", "_").replace(".", "_")
                    endpoints.append(
                        Endpoint(
                            id=ep_id,
                            method=m,
                            path=f"/api/{fn.name.replace('_', '-')}",
                            handler_name=fn.qualified_name,
                            auth_required=auth_required,
                            roles=roles,
                            parameters=[],
                            database_access="objects." in fn_body or "filter(" in fn_body or ".raw(" in fn_body,
                            object_identifier=False,
                            state_changing=m in ("POST", "PUT", "DELETE", "PATCH"),
                            external_network="requests." in fn_body or "httpx." in fn_body or "urllib" in fn_body,
                            sensitive_data="admin" in fn.name.lower() or "secret" in fn.name.lower(),
                            source=fn.location,
                        )
                    )

        # 2. DRF Class-Based Views (APIView, ModelViewSet, GenericAPIView)
        for cls in parsed_file.classes:
            is_view_class = any(
                base in cls.base_classes
                for base in ("APIView", "View", "GenericAPIView", "ModelViewSet", "ViewSet", "ReadOnlyModelViewSet")
            ) or cls.name.endswith("View") or cls.name.endswith("ViewSet")

            if is_view_class:
                start_l = max(0, cls.location.line_start - 1)
                end_l = min(len(content_lines), cls.location.line_end)
                class_body = "\n".join(content_lines[start_l:end_l])

                auth_required = any(
                    term in class_body.lower()
                    for term in ("isauthenticated", "isadminuser", "permission_classes", "isauthenticatedorreadonly")
                )
                roles = ["admin"] if "admin" in cls.name.lower() or "isadminuser" in class_body.lower() else []

                # Look for handler methods: get, post, put, delete, patch
                for fn in cls.methods:
                    method_name = fn.name.lower()
                    if method_name in ("get", "post", "put", "delete", "patch"):
                        http_method = method_name.upper()
                        ep_id = f"ep_cbv_{parsed_file.file_path}_{cls.name}_{http_method}".replace("/", "_").replace(".", "_")
                        base_path = f"/api/{cls.name.replace('View', '').replace('ViewSet', '').lower()}"
                        fn_body = fn.body_text or ""

                        endpoints.append(
                            Endpoint(
                                id=ep_id,
                                method=http_method,
                                path=base_path,
                                handler_name=f"{cls.name}.{fn.name}",
                                auth_required=auth_required,
                                roles=roles,
                                parameters=[],
                                database_access="objects." in fn_body or "filter(" in fn_body or ".raw(" in fn_body,
                                object_identifier=http_method in ("PUT", "DELETE", "PATCH"),
                                state_changing=http_method in ("POST", "PUT", "DELETE", "PATCH"),
                                external_network="requests." in fn_body or "httpx." in fn_body,
                                sensitive_data="admin" in cls.name.lower() or "user" in cls.name.lower(),
                                source=fn.location,
                            )
                        )

        return endpoints
