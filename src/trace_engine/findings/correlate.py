"""Evidence correlator connecting static attack paths to runtime test results."""

from typing import List, Optional
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.testpacks.base import TestExecutionResult
from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.findings.recommendations import get_remediation_for_category
from trace_engine.apm.model import AttackPathModel


SEVERITY_BY_CATEGORY = {
    "BOLA": Severity.HIGH,
    "BFLA": Severity.HIGH,
    "AUTHENTICATION": Severity.CRITICAL,
    "SSRF": Severity.HIGH,
    "INJECTION": Severity.CRITICAL,
    "MASS_ASSIGNMENT": Severity.MEDIUM,
    "PATH_TRAVERSAL": Severity.HIGH,
    "SSTI": Severity.CRITICAL,
    "CORS": Severity.MEDIUM,
    "DESERIALIZATION": Severity.CRITICAL,
}


class EvidenceCorrelator:
    """Correlates static code evidence with runtime test executions using Neuro-Symbolic Bayesian Calibration."""

    def correlate(
        self,
        hypothesis: SecurityHypothesis,
        test_result: Optional[TestExecutionResult],
        apm: AttackPathModel,
    ) -> Optional[Finding]:
        from trace_engine.security.fusion import NeuroSymbolicConfidenceEngine, ConfidenceEvidence

        category_str = hypothesis.category.value

        # Calculate combined confidence using Neuro-Symbolic Bayesian Fusion
        evidence = ConfidenceEvidence(
            symbolic_ast_score=hypothesis.confidence_prior,
            dynamic_test_score=test_result.confidence if test_result else None,
            is_dynamically_confirmed=bool(test_result and test_result.confirmed),
        )
        fused = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)
        confidence = fused.confidence_level

        # If not confirmed and posterior probability is below 0.40, do not generate noisy finding
        if not (test_result and test_result.confirmed) and fused.posterior_probability < 0.40:
            return None

        # Build attack path node trail from APM
        attack_path_nodes = []
        if hypothesis.endpoint_id in apm.graph:
            sinks = apm.find_paths_to_sinks(hypothesis.endpoint_id)
            if sinks:
                attack_path_nodes = sinks[0]
            else:
                paths = apm.find_paths_from_endpoint(hypothesis.endpoint_id, max_depth=3)
                if paths:
                    attack_path_nodes = paths[0]

        # Runtime evidence bullet points
        runtime_evidence = []
        if test_result:
            runtime_evidence.append(test_result.summary)
            for obs in test_result.observations:
                runtime_evidence.append(
                    f"HTTP {obs.request_method} {obs.request_url} -> Status {obs.response_status} ({obs.latency_ms}ms)"
                )

        # Correlation explanation
        if test_result and test_result.confirmed:
            correlation_notes = (
                f"Static Attack-Path Model identified vulnerable structure in source code, "
                f"and active runtime test pack '{test_result.testpack_name}' successfully proved exploitability."
            )
        else:
            correlation_notes = (
                f"Static Attack-Path Model detected missing control boundary; runtime validation pending or inconclusive."
            )

        finding_id = hypothesis.id.replace("HYP-", "TR-")
        severity = SEVERITY_BY_CATEGORY.get(category_str, Severity.MEDIUM)

        ep_node = apm.get_node(hypothesis.endpoint_id)
        source_loc = ep_node.location if ep_node else None

        return Finding(
            id=finding_id,
            title=hypothesis.title,
            category=category_str,
            severity=severity,
            confidence=confidence,
            endpoint=hypothesis.endpoint_display,
            source_location=source_loc,
            attack_path=attack_path_nodes,
            static_evidence=hypothesis.static_evidence,
            runtime_evidence=runtime_evidence,
            correlation_notes=correlation_notes,
            remediation=get_remediation_for_category(category_str),
            reproduction_steps=test_result.reproduction_steps if test_result else [],
            observations=test_result.observations if test_result else [],
        )
