"""Tests for Neuro-Symbolic Bayesian Confidence Fusion Engine."""

import pytest
from trace_engine.security.fusion import NeuroSymbolicConfidenceEngine, ConfidenceEvidence
from trace_engine.findings.model import FindingConfidence


def test_fusion_dynamically_confirmed_triple_match():
    evidence = ConfidenceEvidence(
        neural_score=0.92,
        symbolic_ast_score=0.85,
        dynamic_test_score=0.98,
        is_dynamically_confirmed=True,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    assert result.confidence_level == FindingConfidence.CONFIRMED
    assert result.posterior_probability >= 0.98
    assert "empirically verified" in result.rationale


def test_fusion_sanitizer_mitigation_downweights_finding():
    # Model and AST think it's vulnerable, but sanitizer is present in dataflow
    evidence = ConfidenceEvidence(
        neural_score=0.80,
        symbolic_ast_score=0.75,
        has_sanitizer=True,
        is_dynamically_confirmed=False,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    # Sanitizer penalty should drastically lower posterior confidence
    assert result.posterior_probability < 0.55
    assert result.confidence_level == FindingConfidence.POTENTIAL
    assert "mitigated by detected input sanitizer" in result.rationale


def test_fusion_static_only_hypothesis():
    evidence = ConfidenceEvidence(
        neural_score=0.70,
        symbolic_ast_score=0.75,
        dynamic_test_score=None,
        is_dynamically_confirmed=False,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    # Solid static signals without dynamic confirmation calibrate to Medium / High
    assert result.confidence_level in (FindingConfidence.MEDIUM, FindingConfidence.HIGH)
    assert 0.55 <= result.posterior_probability < 0.95
