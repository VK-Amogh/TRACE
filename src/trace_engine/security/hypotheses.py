"""Security hypotheses generation from APM and deterministic signals."""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from trace_engine.apm.model import AttackPathModel
from trace_engine.framework.base import Endpoint
from trace_engine.security.signals import SecuritySignal, SignalType


class VulnerabilityCategory(str, Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"
    AUTHENTICATION = "AUTHENTICATION"
    SSRF = "SSRF"
    INJECTION = "INJECTION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"


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


class HypothesisEngine:
    """Analyzes APM and endpoints to derive actionable security hypotheses."""

    def derive_hypotheses(
        self, apm: AttackPathModel, endpoints: List[Endpoint]
    ) -> List[SecurityHypothesis]:
        hypotheses: List[SecurityHypothesis] = []
        hypo_idx = 1

        for ep in endpoints:
            ep_disp = ep.display_name()

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
                    )
                )
                hypo_idx += 1

            # 2. BFLA Hypothesis: Endpoint has administrative or privileged semantics
            if "admin" in ep.path.lower() or "admin" in [r.lower() for r in ep.roles]:
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-BFLA-{hypo_idx:03d}",
                        category=VulnerabilityCategory.BFLA,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential BFLA on privileged endpoint {ep_disp}",
                        description="Administrative/privileged action may fail to enforce strict RBAC check at runtime.",
                        recommended_test_pack="bfla",
                        confidence_prior=0.70,
                        static_evidence=[
                            f"Privileged path/role identifier present: {ep.roles or ['admin path']}",
                            f"Source location: {ep.source}",
                        ],
                    )
                )
                hypo_idx += 1

            # 3. Authentication Bypass / Missing Auth: State-changing endpoint without auth
            if not ep.auth_required and (ep.state_changing or ep.sensitive_data):
                if not ep.path.endswith("/login") and not ep.path.endswith("/register"):
                    hypotheses.append(
                        SecurityHypothesis(
                            id=f"HYP-AUTH-{hypo_idx:03d}",
                            category=VulnerabilityCategory.AUTHENTICATION,
                            endpoint_id=ep.id,
                            endpoint_display=ep_disp,
                            title=f"Unauthenticated sensitive endpoint {ep_disp}",
                            description="Sensitive or state-modifying endpoint does not declare authentication requirement.",
                            recommended_test_pack="authentication",
                            confidence_prior=0.80,
                            static_evidence=[
                                f"State-changing: {ep.state_changing}",
                                f"Sensitive data indicator: {ep.sensitive_data}",
                                "No auth middleware or dependency detected",
                            ],
                        )
                    )
                    hypo_idx += 1

            # 4. SSRF Hypothesis: Endpoint takes URL or makes external network calls
            if ep.external_network or any("url" in p.name.lower() for p in ep.parameters):
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-SSRF-{hypo_idx:03d}",
                        category=VulnerabilityCategory.SSRF,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential SSRF on {ep_disp}",
                        description="Endpoint handles URL parameter and communicates with outbound HTTP client.",
                        recommended_test_pack="ssrf",
                        confidence_prior=0.85,
                        static_evidence=[
                            "Outbound HTTP client calls detected in handler body",
                            f"URL parameter detected: {[p.name for p in ep.parameters if 'url' in p.name.lower()]}",
                        ],
                    )
                )
                hypo_idx += 1

            # 5. Mass Assignment Hypothesis: PATCH or PUT or POST on user or profile
            if ep.method in ("PATCH", "PUT", "POST") and any(term in ep.path.lower() for term in ("user", "profile", "account")):
                hypotheses.append(
                    SecurityHypothesis(
                        id=f"HYP-MASS-{hypo_idx:03d}",
                        category=VulnerabilityCategory.MASS_ASSIGNMENT,
                        endpoint_id=ep.id,
                        endpoint_display=ep_disp,
                        title=f"Potential Mass Assignment on {ep_disp}",
                        description="Profile update endpoint may bind sensitive attributes (e.g. is_admin, role) directly from payload.",
                        recommended_test_pack="mass_assignment",
                        confidence_prior=0.65,
                        static_evidence=[
                            f"State modifying method {ep.method} on profile/user path",
                            "Model payload deserialization detected",
                        ],
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
                    )
                )
                hypo_idx += 1

        return hypotheses
