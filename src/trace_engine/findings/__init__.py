"""Findings and evidence correlation module."""

from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.findings.correlate import EvidenceCorrelator
from trace_engine.findings.store import FindingStore
from trace_engine.findings.recommendations import get_remediation_for_category

__all__ = [
    "Finding",
    "Severity",
    "FindingConfidence",
    "EvidenceCorrelator",
    "FindingStore",
    "get_remediation_for_category",
]
