"""Build ``Finding`` objects for analyzers that do not come from route hypotheses."""

from typing import List, Optional

from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.findings.recommendations import get_detailed_remediation_and_root_cause
from trace_engine.parsing.locations import SourceLocation


def make_finding(
    *,
    finding_id: str,
    category: str,
    title: str,
    endpoint: str,
    severity: Severity,
    confidence: FindingConfidence,
    evidence: List[str],
    file: Optional[str] = None,
    line: int = 0,
    attack_path: Optional[List[str]] = None,
    notes: str = "",
    extra_remediation: str = "",
) -> Finding:
    """A finding with category-specific remediation and fixture provenance."""
    from trace_engine.ingest.scan_scope import get_path_provenance, is_fixture_path

    location = (
        SourceLocation(file=file, line_start=max(line, 1), line_end=max(line, 1)) if file else None
    )
    root_cause, remediation, short_action = get_detailed_remediation_and_root_cause(
        title=title,
        category=category,
        endpoint=endpoint,
        static_evidence=evidence,
        filepath=file or "",
    )
    if extra_remediation:
        remediation = f"{remediation}\n{extra_remediation}"
    return Finding(
        id=finding_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        source_location=location,
        attack_path=attack_path or [],
        static_evidence=evidence,
        runtime_evidence=["Static analysis only; no runtime probe applies to this check."],
        correlation_notes=notes or "Detected by static analysis of repository files.",
        remediation=remediation,
        root_cause=root_cause,
        short_action=short_action,
        provenance=get_path_provenance(file or ""),
        is_fixture=is_fixture_path(file or ""),
    )
