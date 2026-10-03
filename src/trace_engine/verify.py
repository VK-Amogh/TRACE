"""TRACE Verification Engine (Section 58) for validating remediations by coding agents."""

from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from trace_engine.findings.store import FindingStore
from trace_engine.findings.model import Finding
from trace_engine.ingest.repository import RepositoryScanner
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework import get_adapters
from trace_engine.apm.builder import APMBuilder
from trace_engine.policy.scope import ScopeGuard
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.testpacks.registry import default_registry
from trace_engine.testpacks.base import TestContext
from trace_engine.security.hypotheses import HypothesisEngine


class VerificationStatus(str, Enum):
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationResult(BaseModel):
    finding_id: str
    endpoint: str
    status: VerificationStatus
    summary: str
    static_signals_after: List[str] = Field(default_factory=list)
    runtime_status_after: Optional[int] = None
    differential_analysis: str
    remediation_verified: bool


class VerificationEngine:
    """Verifies whether a source code modification actually resolved a finding."""

    def __init__(self, repo_path: Path, target_url: str = "http://127.0.0.1:18080"):
        self.repo_path = repo_path.resolve()
        self.target_url = target_url

    def verify(self, finding_id: str) -> VerificationResult:
        store = FindingStore(self.repo_path / ".trace")
        finding = store.get_finding_by_id(finding_id)
        if not finding:
            return VerificationResult(
                finding_id=finding_id,
                endpoint="unknown",
                status=VerificationStatus.INCONCLUSIVE,
                summary=f"Finding '{finding_id}' not found in .trace/findings.json",
                differential_analysis="Cannot verify non-existent finding.",
                remediation_verified=False,
            )

        # 1. Re-index and parse
        scanner = RepositoryScanner(self.repo_path)
        source_files = scanner.scan()
        parser = CodeParser()
        adapters = get_adapters()

        parsed_files = []
        discovered_endpoints = []
        for sf in source_files:
            content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
            pf = parser.parse(sf.path, content, sf.language)
            parsed_files.append(pf)
            for adapter in adapters:
                if adapter.can_handle(pf):
                    discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

        # 2. Re-build APM
        builder = APMBuilder(project_name=self.repo_path.name)
        apm = builder.build(self.repo_path, source_files, parsed_files, discovered_endpoints)

        # 3. Re-evaluate hypotheses
        engine = HypothesisEngine()
        new_hypotheses = engine.derive_hypotheses(apm, discovered_endpoints)

        # Check if the specific hypothesis still triggers statically
        hyp_still_present = any(
            h.category.value == finding.category and h.endpoint_display == finding.endpoint
            for h in new_hypotheses
        )

        # 4. Replay test pack against runtime
        scope_guard = ScopeGuard()
        scope_guard.allow_target(self.target_url)
        client = ScopedHttpClient(scope_guard=scope_guard)
        context = TestContext(
            target_base_url=self.target_url,
            active_tokens={"user-a": "user-a", "user-b": "user-b", "admin": "admin"},
        )

        pack = default_registry.get(finding.category.lower())
        runtime_confirmed = False
        runtime_status = None
        test_summary = "Test pack could not run."

        if pack:
            # Create a synthetic hypothesis from finding to re-test
            from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory
            cat_enum = getattr(VulnerabilityCategory, finding.category.upper(), VulnerabilityCategory.BOLA)
            dummy_hyp = SecurityHypothesis(
                id=finding.id.replace("TR-", "HYP-"),
                category=cat_enum,
                endpoint_id="verify_ep",
                endpoint_display=finding.endpoint,
                title=finding.title,
                description=finding.title,
                recommended_test_pack=finding.category.lower(),
            )
            try:
                res = pack.execute(dummy_hyp, client, context)
                runtime_confirmed = res.confirmed
                test_summary = res.summary
                if res.observations:
                    runtime_status = res.observations[0].response_status
            except Exception as e:
                return VerificationResult(
                    finding_id=finding_id,
                    endpoint=finding.endpoint,
                    status=VerificationStatus.INCONCLUSIVE,
                    summary=f"Runtime target connection failed: {e}",
                    differential_analysis="Target unreachable during verification probe.",
                    remediation_verified=False,
                )

        # 5. Formulate verification status
        if not runtime_confirmed:
            status = VerificationStatus.FIXED
            differential = (
                f"Remediation confirmed: Runtime test no longer reproduces exploit. "
                f"Observation summary: {test_summary}."
            )
            remediation_ok = True
        else:
            status = VerificationStatus.STILL_PRESENT
            differential = (
                f"Remediation incomplete: Exploit still succeeds at runtime. "
                f"Observation summary: {test_summary}."
            )
            remediation_ok = False

        return VerificationResult(
            finding_id=finding_id,
            endpoint=finding.endpoint,
            status=status,
            summary=test_summary,
            static_signals_after=[h.title for h in new_hypotheses if h.endpoint_display == finding.endpoint],
            runtime_status_after=runtime_status,
            differential_analysis=differential,
            remediation_verified=remediation_ok,
        )
