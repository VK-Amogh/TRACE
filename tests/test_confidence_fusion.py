"""Tests for Neuro-Symbolic Bayesian Confidence Fusion Engine."""

import pytest
from trace_engine.security.fusion import NeuroSymbolicConfidenceEngine, ConfidenceEvidence
from trace_engine.findings.model import FindingConfidence


def test_fusion_level3_triple_match():
    """Level 3 (Triple Match): SecureBERT (0.85) + AST sink (0.90) + Dynamic probe (0.99) -> ~99.8%."""
    evidence = ConfidenceEvidence(
        neural_score=0.85,
        symbolic_ast_score=0.90,
        dynamic_test_score=0.99,
        is_dynamically_confirmed=True,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    assert result.confidence_level == FindingConfidence.CONFIRMED
    assert result.posterior_probability >= 0.998
    assert "Level 3" in result.fusion_level
    assert "empirically verified" in result.rationale


def test_fusion_level2_static_dataflow_proven():
    """Level 2 (Static + Dynamic Partial): Probe blocked by WAF (dyn=0), AST dataflow proven (0.70) + BERT (0.40) -> 82%."""
    evidence = ConfidenceEvidence(
        neural_score=0.40,
        symbolic_ast_score=0.70,
        dynamic_test_score=0.0,
        is_dynamically_confirmed=False,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    # 1 - (1 - 0.40) * (1 - 0.70) = 1 - 0.18 = 0.82 -> 82%
    assert result.confidence_level == FindingConfidence.HIGH
    assert round(result.posterior_probability, 2) == 0.82
    assert "Level 2" in result.fusion_level


def test_fusion_level1_single_signal():
    """Level 1 (Single Signal): Only SecureBERT flags it with no AST sink -> exploratory hypothesis."""
    evidence = ConfidenceEvidence(
        neural_score=0.50,
        symbolic_ast_score=0.0,
        dynamic_test_score=None,
        is_dynamically_confirmed=False,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    # 1 - (1 - 0.50) = 0.50
    assert result.confidence_level == FindingConfidence.MEDIUM
    assert round(result.posterior_probability, 2) == 0.50
    assert "Level 1" in result.fusion_level


def test_fusion_sanitizer_mitigation_downweights_finding():
    """Model and AST indicate vulnerability, but AST sanitizer is detected."""
    evidence = ConfidenceEvidence(
        neural_score=0.60,
        symbolic_ast_score=0.80,
        has_sanitizer=True,
        is_dynamically_confirmed=False,
    )
    result = NeuroSymbolicConfidenceEngine.fuse_evidence(evidence)

    # Sanitizer penalty reduces AST score from 0.80 to 0.12, yielding ~65%
    assert result.posterior_probability < 0.75
    assert "downweighted: input sanitizer detected" in result.rationale
