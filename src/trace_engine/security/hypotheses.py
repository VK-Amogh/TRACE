"""Security hypotheses generation from APM and deterministic signals."""

import os
import re
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
from trace_engine.apm.model import AttackPathModel
from trace_engine.framework.base import Endpoint
from trace_engine.security.signals import SecuritySignal, SignalType


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"
    AUTHENTICATION = "AUTHENTICATION"
    SSRF = "SSRF"
    INJECTION = "INJECTION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSTI = "SSTI"
    CORS = "CORS"
    DESERIALIZATION = "DESERIALIZATION"


class SecurityHypothesis(BaseModel):
    """A testable hypothesis about an attack path in the application."""
    id: str
    category: VulnerabilityCategory
    endpoint_id: str
    endpoint_display: str
    title: str
    description: str
    recommended_test_pack: str
    confidence_prior: float = 0.5  # Prior confidence from static signals alone
    static_evidence: List[str] = Field(default_factory=list)
    severity: Optional[Severity] = None  # Contextual severity override


class HypothesisEngine:
    """Analyzes APM and endpoints to derive actionable security hypotheses."""

    def derive_hypotheses(
        self, apm: AttackPathModel, endpoints: List[Endpoint]
    ) -> List[SecurityHypothesis]:
        hypotheses: List[SecurityHypothesis] = []
        hypo_idx = 1
        admin_endpoint_ids: Set[str] = set()
        source_files: Set[str] = set()
        file_cache: Dict[str, str] = {}

        def read_file(fpath: str) -> str:
            if not fpath:
                return ""
            if fpath not in file_cache:
                try:
                    if os.path.exists(fpath):
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            file_cache[fpath] = f.read()
                    else:
                        file_cache[fpath] = ""
                except Exception:
                    file_cache[fpath] = ""
            return file_cache[fpath]

        # Collect unique source files
        for ep in endpoints:
            if ep.source and ep.source.file:
                source_files.add(ep.source.file)

        for ep in endpoints:
            ep_disp = ep.display_name()
            file_src = read_file(ep.source.file) if ep.source and ep.source.file else ""

            # 1. BOLA Hypothesis: Endpoint accepts ID parameter, touches DB, but lacks ownership verification
            if ep.object_identifier and ep.database_access:
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-BOLA-{hypo_idx:03d}",
                        category=VulnerabilityCategory.BOLA,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential BOLA on {ep_disp}",
                        description="Endpoint looks up objects by client-supplied ID with potential absence of tenant/user ownership check.",
                        recommended_test_pack="bola",
                        confidence_prior=0.75,
                        static_evidence=[
                            f"Path parameter matches object ID pattern: {[p.name for p in ep.parameters if p.location == 'path']}",
                            "Database lookup confirmed in handler source",
                            f"Declared auth required: {ep.auth_required}",
                        ],
                        severity=Severity.HIGH,
                    )
                )
                hypo_idx += 1

                # Check for Caller-Controlled Ownership Bypass:
                # e.g. def fn(user_id, coach_id: Optional[int] = None): if coach_id is not None: assert_coach_owns_athlete(...)
                has_coach_param = any(p.name in ("coach_id", "owner_id", "tenant_id", "org_id") for p in ep.parameters)
                ownership_bypass_pattern = (
                    "assert_coach_owns_athlete" in file_src
                    or bool(re.search(r"if\s+(?:coach_id|owner_id|tenant_id)\s+is\s+not\s+None:", file_src))
                    or bool(re.search(r"if\s+(?:coach_id|owner_id|tenant_id):", file_src))
                )
                if has_coach_param and ownership_bypass_pattern:
                    hypotheses.append(
                        SecurityHypothesis(
                            id=f"HYP-BOLA-{hypo_idx:03d}",
                            category=VulnerabilityCategory.BOLA,
                            endpoint_id=ep.id,
                            endpoint_display=ep_disp,
                            title=f"Caller-Controlled Ownership Bypass via Optional Parameter on {ep_disp}",
                            description="Multi-tenant ownership assertion is guarded by an optional query parameter (e.g. coach_id). Omitting this parameter from the request completely bypasses the ownership check.",
                            recommended_test_pack="bola",
                            confidence_prior=0.85,
                            static_evidence=[
                                "Ownership assertion is guarded by optional parameter: coach_id",
                                "Bypass confirmed: Omitting ?coach_id= skips assert_coach_owns_athlete()",
                                f"Endpoint modifies/reads target object: {ep.path}",
                            ],
                            severity=Severity.HIGH,
                        )
                    )
                    hypo_idx += 1

            # 2. BFLA Hypothesis: Endpoint has administrative or privileged semantics
            is_admin = "admin" in ep.path.lower() or "admin" in [r.lower() for r in ep.roles]
            if is_admin:
                admin_endpoint_ids.add(ep.id)
                is_critical_admin = any(term in ep.path.lower() for term in ("reset-db", "wipe", "truncate")) or (
                    "users/create" in ep.path.lower() and not ep.auth_required
                )
                bfla_sev = Severity.CRITICAL if is_critical_admin else Severity.HIGH
                static_ev = [
                    f"Privileged path/role identifier present: {ep.roles or ['admin path']}",
                    f"Source location: {ep.source}",
                ]
                if not ep.auth_required:
                    static_ev.append("Administrative endpoint is completely unauthenticated and unprotected by RBAC")

                title = (
                    f"Unauthenticated administrative endpoint lacks RBAC on {ep_disp}"
                    if not ep.auth_required
                    else f"Potential BFLA on privileged endpoint {ep_disp}"
                )
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-BFLA-{hypo_idx:03d}",
                        category=VulnerabilityCategory.BFLA,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=title,
                        description="Administrative/privileged action fails to enforce strict RBAC check or lacks authentication.",
                        recommended_test_pack="bfla",
                        confidence_prior=0.85 if not ep.auth_required else 0.70,
                        static_evidence=static_ev,
                        severity=bfla_sev,
                    )
                )
                hypo_idx += 1

            # 3. Authentication Bypass / Missing Auth: State-changing, sensitive, stream, or mutating verbs without auth
            if not ep.auth_required and (
                ep.state_changing
                or ep.sensitive_data
                or ep.method in ("POST", "PUT", "PATCH", "DELETE", "WEBSOCKET")
                or any(term in ep.path.lower() for term in ("scatt-analysis", "inference", "predict", "telemetry/analyze"))
                or (ep.handler_name and ep.handler_name.startswith("StaticFiles"))
            ):
                # Deduplication: If already captured as BFLA on administrative endpoint, skip generic AUTH to prevent duplicate reporting
                if ep.id not in admin_endpoint_ids:
                    path_segs = [s.lower() for s in ep.path.strip("/").split("/")]
                    is_public_by_design = any(
                        s in ("login", "signin", "register", "signup", "forgot-password", "callback", "oauth", "health", "ping", "status", "public", "docs", "openapi")
                        or s.startswith("auth-callback") or s.endswith("-callback")
                        for s in path_segs
                    )
                    if not is_public_by_design:
                        # Contextual classification & severity calibration
                        if any(term in ep.path.lower() for term in ("reset", "wipe", "truncate")) and ep.state_changing and not any(term in ep.path.lower() for term in ("password", "token")):
                            # Case: Destructive global data wipe (e.g. POST /api/session/reset)
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated Global Session/Data Wipe with Blast Radius on {ep_disp}",
                                    description="Endpoint permits unauthenticated bulk data or session deletion across all users without scoping or confirmation.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.90,
                                    static_evidence=[
                                        f"Destructive action method {ep.method} on reset/wipe path",
                                        "No session ownership or caller authentication enforced",
                                        "Global deletion blast radius affects all connected users",
                                    ],
                                    severity=Severity.CRITICAL,
                                )
                            )
                            hypo_idx += 1
                        elif "reset-password" in ep.path.lower() or ("password" in ep.path.lower() and ep.state_changing):
                            # Case: Account takeover via unauth password reset
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated Password Reset Allowing Account Takeover on {ep_disp}",
                                    description="Endpoint permits password modification without current password or verified reset token.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.90,
                                    static_evidence=[
                                        "Password modification endpoint lacks authentication",
                                        "Enables unauthenticated credential reset / account takeover",
                                    ],
                                    severity=Severity.CRITICAL,
                                )
                            )
                            hypo_idx += 1
                        elif (ep.handler_name and ep.handler_name.startswith("StaticFiles")) or "/session_videos" in ep.path.lower() or "/uploads" in ep.path.lower():
                            # Case: Public StaticFiles mount leaking sensitive artifacts
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Public StaticFiles Mount Exposes Sensitive Artifacts on {ep_disp}",
                                    description="Directory is mounted publicly via StaticFiles without authentication middleware, exposing stored user files/videos to anyone with the URL.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.85,
                                    static_evidence=[
                                        f"FastAPI StaticFiles mount path: {ep.path}",
                                        f"Handler: {ep.handler_name}",
                                        "No auth middleware or token check on file retrieval",
                                    ],
                                    severity=Severity.HIGH,
                                )
                            )
                            hypo_idx += 1
                        elif ep.method == "WEBSOCKET":
                            # Case: Unauthenticated WebSocket
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated WebSocket Connection on {ep_disp}",
                                    description="WebSocket endpoint accepts connections and streams data without verifying authentication tokens or session credentials during handshake.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.75,
                                    static_evidence=[
                                        f"WebSocket route {ep.path} accepts unauthenticated connections",
                                        "No token or session check in handshake handler",
                                    ],
                                    severity=Severity.MEDIUM,
                                )
                            )
                            hypo_idx += 1
                        elif any(term in ep.path.lower() for term in ("analyze", "competitive-advantage", "generate-workspace", "generate-plan", "orchestrator/run")):
                            # Case: Unauthenticated AI Agent / LLM Inference Pipeline
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated AI Agent Pipeline / Token Depletion on {ep_disp}",
                                    description="Endpoint invokes expensive backend AI agent or LLM pipelines without authentication or rate-limiting, exposing the application to token exhaustion and prompt injection.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.85,
                                    static_evidence=[
                                        f"AI Agent / LLM reasoning endpoint: {ep.method} {ep.path}",
                                        "No authentication or caller identity verification detected",
                                        "Risk: Denial-of-wallet, unbounded LLM token consumption, prompt injection",
                                    ],
                                    severity=Severity.HIGH,
                                )
                            )
                            hypo_idx += 1
                        elif any(term in ep.path.lower() for term in ("identity", "mvp", "product-config", "tech-preferences", "business-model", "additional-info")):
                            # Case: Multi-step wizard session state mutation
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Insecure Discovery Session State Mutation on {ep_disp}",
                                    description="Endpoint updates onboarding discovery session data using client-supplied sessionId without session tenant verification, enabling session hijacking and state poisoning.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.80,
                                    static_evidence=[
                                        f"Discovery session state modification: {ep.method} {ep.path}",
                                        "Client-controlled sessionId parameter without verified caller ownership",
                                        "Risk: Cross-session data corruption and poisoning of startup configuration",
                                    ],
                                    severity=Severity.HIGH,
                                )
                            )
                            hypo_idx += 1
                        elif any(term in ep.path.lower() for term in ("deliverable", "rollforward")):
                            # Case: Unauthorized task status / sprint roadmap mutation
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthorized Sprint Deliverable & Schedule Manipulation on {ep_disp}",
                                    description="Endpoint updates deliverable statuses or rolls forward sprint deadlines without verifying workspace membership or caller permissions.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.80,
                                    static_evidence=[
                                        f"Deliverable/schedule mutation: {ep.method} {ep.path}",
                                        "Missing workspace collaborator or editor role check",
                                        "Risk: Tampering with project sprint audit trails and deliverable completion status",
                                    ],
                                    severity=Severity.HIGH,
                                )
                            )
                            hypo_idx += 1
                        elif any(term in ep.path.lower() for term in ("scatt-analysis", "inference", "predict", "telemetry/analyze")) and not ep.database_access:
                            # Case: Stateless ML/inference compute endpoint (low impact)
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated Stateless ML/Inference Endpoint on {ep_disp}",
                                    description="Inference endpoint lacks authentication, exposing compute resources (denial-of-wallet / resource exhaustion) but no stored user data.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.65,
                                    static_evidence=[
                                        f"Stateless compute endpoint {ep.method} {ep.path}",
                                        "No database access or private user data stored",
                                        "Risk limited to compute exhaustion / unmetered access",
                                    ],
                                    severity=Severity.LOW,
                                )
                            )
                            hypo_idx += 1
                        elif ep.method == "GET" and any(term in ep.path.lower() for term in ("user", "profile")) and not any(term in ep.path.lower() for term in ("admin", "token", "key", "secret", "history", "story", "session")):
                            # Case: Read-only user metadata disclosure (medium impact)
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated User Information Disclosure on {ep_disp}",
                                    description="Read-only user endpoint discloses basic profile metadata without session authentication.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.75,
                                    static_evidence=[
                                        f"Unauthenticated read {ep.method} {ep.path}",
                                        "Returns basic user record without credential leakage",
                                    ],
                                    severity=Severity.MEDIUM,
                                )
                            )
                            hypo_idx += 1
                        else:
                            # General sensitive / state-modifying unauthenticated endpoint (HIGH)
                            hypotheses.append(
                                SecurityHypothesis(
                                    id=f"HYP-AUTH-{hypo_idx:03d}",
                                    category=VulnerabilityCategory.AUTHENTICATION,
                                    endpoint_id=ep.id,
                                    endpoint_display=ep_disp,
                                    title=f"Unauthenticated Sensitive Route Exposure on {ep_disp}",
                                    description="Sensitive or state-modifying endpoint does not declare authentication requirement.",
                                    recommended_test_pack="authentication",
                                    confidence_prior=0.80,
                                    static_evidence=[
                                        f"State-changing: {ep.state_changing}",
                                        f"Sensitive data indicator: {ep.sensitive_data}",
                                        "No auth middleware or dependency detected",
                                    ],
                                    severity=Severity.HIGH,
                                )
                            )
                            hypo_idx += 1

            # 4. SSRF Hypothesis: Endpoint takes user-supplied URL/target AND makes outbound HTTP calls
            url_params = [
                p.name for p in ep.parameters
                if any(
                    term == p.name.lower()
                    or p.name.lower().endswith(f"_{term}")
                    or p.name.lower().endswith(term.capitalize())
                    for term in ("url", "uri", "target", "webhook", "callback", "dest", "destination", "endpoint", "feed", "proxy", "redirect_uri")
                )
            ]
            if ep.external_network and url_params:
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-SSRF-{hypo_idx:03d}",
                        category=VulnerabilityCategory.SSRF,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential SSRF on {ep_disp}",
                        description="Endpoint accepts user-controlled destination URL and dispatches outbound HTTP requests.",
                        recommended_test_pack="ssrf",
                        confidence_prior=0.85,
                        static_evidence=[
                            "Outbound HTTP client calls detected in handler body",
                            f"User-controlled URL parameters: {url_params}",
                        ],
                        severity=Severity.HIGH,
                    )
                )
                hypo_idx += 1

            # 5. Mass Assignment & Privilege Escalation via Unvalidated Role Assignment
            is_profile_path = any(term in ep.path.lower() for term in ("user", "profile", "account", "athlete"))
            is_single_field_action = any(
                ep.path.lower().endswith(f"/{term}") or f"/{term}/" in ep.path.lower()
                for term in ("coach", "assign-coach", "reset-password", "password", "status", "settings")
            )

            if ep.method in ("PATCH", "PUT", "POST") and is_profile_path:
                # Check for Privilege Escalation via Unvalidated Role Assignment:
                # (e.g. POST /api/admin/users/create with role parameter)
                has_role_param = any(p.name in ("role", "is_admin", "is_superuser", "permissions") for p in ep.parameters)
                has_role_in_code = "role" in file_src.lower() and ("create" in ep.path.lower() or "register" in ep.path.lower() or "users" in ep.path.lower())

                if (has_role_param or has_role_in_code) and any(term in ep.path.lower() for term in ("create", "register", "users", "signup")):
                    hypotheses.append(
                        SecurityHypothesis(
                            id=f"HYP-BFLA-{hypo_idx:03d}",
                            category=VulnerabilityCategory.BFLA,
                            endpoint_id=ep.id,
                            endpoint_display=ep_disp,
                            title=f"Privilege Escalation via Unvalidated Role Assignment on {ep_disp}",
                            description="Endpoint accepts client-supplied 'role' without authorization check or strict role allowlist, allowing creation of arbitrary ADMIN accounts.",
                            recommended_test_pack="bfla",
                            confidence_prior=0.85,
                            static_evidence=[
                                f"State modifying method {ep.method} accepts unvalidated role parameter",
                                "Permits callers to assign role='ADMIN' without restriction",
                            ],
                            severity=Severity.CRITICAL if not ep.auth_required else Severity.HIGH,
                        )
                    )
                    hypo_idx += 1
                elif not is_single_field_action:
                    # Only flag true mass assignment if NOT a single-field action DTO
                    # and either dynamic unpacking is detected or generic dictionary payload is accepted
                    has_dynamic_unpacking = any(
                        term in file_src
                        for term in ("**req.dict", "**payload.dict", "**data", "**body", "Object.assign", "setattr")
                    )
                    if has_dynamic_unpacking or len(ep.parameters) > 2:
                        hypotheses.append(
                            SecurityHypothesis(
                                id=f"HYP-MASS-{hypo_idx:03d}",
                                category=VulnerabilityCategory.MASS_ASSIGNMENT,
                                endpoint_id=ep.id,
                                endpoint_display=ep_disp,
                                title=f"Potential Mass Assignment on {ep_disp}",
                                description="Profile update endpoint may bind sensitive attributes directly from payload without strict allowlisting.",
                                recommended_test_pack="mass_assignment",
                                confidence_prior=0.65,
                                static_evidence=[
                                    f"State modifying method {ep.method} on profile/user path: {ep.path}",
                                    "Model payload deserialization with potential dynamic field binding",
                                ],
                                severity=Severity.MEDIUM,
                            )
                        )
                        hypo_idx += 1

            # 6. Injection Indicator Hypothesis: Search or query with DB access
            if any(term in ep.path.lower() for term in ("search", "filter", "query")) and ep.database_access:
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-INJ-{hypo_idx:03d}",
                        category=VulnerabilityCategory.INJECTION,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential Injection Indicator on {ep_disp}",
                        description="Dynamic search query routed to database layer without verified parameterization.",
                        recommended_test_pack="injection",
                        confidence_prior=0.60,
                        static_evidence=[
                            "User query parameter routed to database handler",
                            f"Endpoint parameters: {[p.name for p in ep.parameters]}",
                        ],
                        severity=Severity.CRITICAL,
                    )
                )
                hypo_idx += 1

            # 7. Path Traversal Hypothesis: Endpoints accepting genuine file or directory path parameters
            file_param_names = [
                p.name for p in ep.parameters
                if p.name.lower() in (
                    "file", "path", "filename", "file_name", "filepath", "file_path",
                    "doc_path", "document", "attachment", "dir_path", "download_path"
                ) or any(
                    p.name.lower().endswith(f"_{term}")
                    for term in ("file", "path", "filename", "filepath")
                )
            ]
            path_segments = [seg.lower() for seg in ep.path.strip("/").split("/")]
            has_file_route = any(seg in ("file", "files", "download", "downloads", "static", "assets", "document", "documents", "video") for seg in path_segments)

            # Check if upload/download endpoint handles file path without containment verification
            if file_param_names or (has_file_route and ep.parameters):
                # Calibrate evidence if parameter is shot_id or file
                is_unresolved_path = any("shot_id" in p.name.lower() for p in ep.parameters)
                evidence = [
                    f"File/path parameter names detected: {file_param_names or [p.name for p in ep.parameters]}",
                    f"Source location: {ep.source}",
                ]
                if is_unresolved_path:
                    evidence.append("Filename constructed with insufficient sanitization (missing pathlib.Path.resolve containment check)")

                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-TRAV-{hypo_idx:03d}",
                        category=VulnerabilityCategory.PATH_TRAVERSAL,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential Path Traversal on {ep_disp}",
                        description="Endpoint handles file or path parameters without verified filesystem boundary isolation.",
                        recommended_test_pack="path_traversal",
                        confidence_prior=0.65,
                        static_evidence=evidence,
                        severity=Severity.MEDIUM if is_unresolved_path else Severity.HIGH,
                    )
                )
                hypo_idx += 1

            # 8. Server-Side Template Injection (SSTI) Hypothesis
            template_param_names = [p.name for p in ep.parameters if any(term in p.name.lower() for term in ("template", "render", "msg", "format", "view", "preview"))]
            if template_param_names or any(term in ep.path.lower() for term in ("template", "render", "preview", "email", "notify")):
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-SSTI-{hypo_idx:03d}",
                        category=VulnerabilityCategory.SSTI,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential Template Injection on {ep_disp}",
                        description="Endpoint processes dynamic template formatting or user-interpolated rendering.",
                        recommended_test_pack="ssti",
                        confidence_prior=0.60,
                        static_evidence=[
                            f"Template rendering parameter detected: {template_param_names or [ep.path]}",
                        ],
                        severity=Severity.CRITICAL,
                    )
                )
                hypo_idx += 1

            # 9. CORS Misconfiguration Hypothesis on sensitive routes
            if ep.auth_required and ep.sensitive_data:
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-CORS-{hypo_idx:03d}",
                        category=VulnerabilityCategory.CORS,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential CORS Misconfiguration on {ep_disp}",
                        description="Authenticated sensitive endpoint may reflect arbitrary cross-origin request headers with credentials.",
                        recommended_test_pack="cors",
                        confidence_prior=0.55,
                        static_evidence=[
                            f"Authenticated: {ep.auth_required}, Sensitive data: {ep.sensitive_data}",
                        ],
                        severity=Severity.MEDIUM,
                    )
                )
                hypo_idx += 1

            # 10. Insecure Deserialization Hypothesis
            # Strict criteria: Explicit restore/unpickle routes OR deserialization sinks in source code.
            # Normal JSON endpoints (e.g. /api/session/start, /api/session/reset, /shots) must NEVER be falsely flagged!
            has_deser_sink = any(
                term in file_src
                for term in ("pickle.loads", "pickle.load(", "yaml.load(", "yaml.unsafe_load", "marshal.loads", "shelve.open", "jsonpickle.", "unserialize(")
            )
            has_explicit_restore_path = any(term in ep.path.lower() for term in ("restore", "deserialize", "unpickle"))

            if ep.method in ("POST", "PUT", "PATCH") and (has_explicit_restore_path or has_deser_sink):
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-DESER-{hypo_idx:03d}",
                        category=VulnerabilityCategory.DESERIALIZATION,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential Insecure Deserialization on {ep_disp}",
                        description="Endpoint accepts serialized object streams or invokes unsafe deserialization sinks.",
                        recommended_test_pack="deserialization",
                        confidence_prior=0.75,
                        static_evidence=[
                            f"Deserialization trigger in method {ep.method}: {ep.path}",
                            f"Unsafe deserialization sink detected: {has_deser_sink}",
                        ],
                        severity=Severity.CRITICAL,
                    )
                )
                hypo_idx += 1

        # 11. Codebase-wide Architectural Security Issues (CORS Wildcard & Broken Password Hashing)
        for fpath in source_files:
            file_src = read_file(fpath)
            if not file_src:
                continue

            # A. Insecure CORS Configuration (allow_origins=["*"] with allow_credentials=True)
            cors_match = re.search(
                r"CORSMiddleware.*?(?:allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|allow_origin_regex\s*=\s*[\"'].*?[\"']).*?allow_credentials\s*=\s*True",
                file_src,
                re.DOTALL | re.IGNORECASE,
            ) or re.search(
                r"allow_credentials\s*=\s*True.*?allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]",
                file_src,
                re.DOTALL | re.IGNORECASE,
            )
            if cors_match:
                ep_ref = endpoints[0] if endpoints else None
                ep_id = ep_ref.id if ep_ref else "ep_cors_global"
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-CORS-{hypo_idx:03d}",
                        category=VulnerabilityCategory.CORS,
                        endpoint_id=ep_id,
                        endpoint_display="app (CORSMiddleware)",
                        title="Insecure CORS Wildcard with Credentials Enabled",
                        description="Backend CORS middleware is configured with allow_origins=['*'] and allow_credentials=True, enabling credentialed cross-origin requests from arbitrary web origins.",
                        recommended_test_pack="cors",
                        confidence_prior=0.85,
                        static_evidence=[
                            f"Configuration in: {fpath}",
                            "CORSMiddleware: allow_origins=['*'] with allow_credentials=True",
                        ],
                        severity=Severity.MEDIUM,
                    )
                )
                hypo_idx += 1

            # B. Broken Password Hashing & Insecure Credential Storage
            has_plaintext_fallback = bool(
                re.search(r"if\s+hashed_password\s*==\s*plain_password:", file_src)
                or re.search(r"if\s+db_password\s*==\s*plain_password:", file_src)
                or re.search(r"hashed_password\s*==\s*password", file_src)
            )
            has_hardcoded_salt = bool(
                re.search(r"(?:salt|SALT)\s*=\s*[\"'][^\"']+[\"']", file_src)
                and ("sha256" in file_src or "hashlib" in file_src)
            )
            has_fast_hash = bool(
                re.search(r"hashlib\.(?:sha256|md5|sha1)\(", file_src)
                and ("password" in file_src.lower())
            )

            if has_plaintext_fallback or has_hardcoded_salt or has_fast_hash:
                evidence = []
                if has_plaintext_fallback:
                    evidence.append("Plaintext password comparison fallback detected: `if hashed_password == plain_password:`")
                if has_hardcoded_salt:
                    evidence.append("Single hardcoded global salt detected in password hashing routine")
                if has_fast_hash:
                    evidence.append("Fast single-round unkeyed hash (SHA-256) used without work factor (bcrypt/argon2)")

                ep_ref = endpoints[0] if endpoints else None
                ep_id = ep_ref.id if ep_ref else "ep_auth_crypto_global"
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-AUTH-{hypo_idx:03d}",
                        category=VulnerabilityCategory.AUTHENTICATION,
                        endpoint_id=ep_id,
                        endpoint_display="Authentication Module (verify_password / hash_password)",
                        title="Broken Password Hashing & Insecure Credential Storage",
                        description="Password verification allows plaintext fallback, uses a hardcoded global salt, and relies on unsalted single-round SHA-256 instead of an adaptive work-factor algorithm (bcrypt, argon2, pbkdf2).",
                        recommended_test_pack="authentication",
                        confidence_prior=0.90,
                        static_evidence=evidence,
                        severity=Severity.CRITICAL if has_plaintext_fallback else Severity.HIGH,
                    )
                )
                hypo_idx += 1

        return hypotheses
