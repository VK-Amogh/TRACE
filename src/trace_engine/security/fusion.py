"""Neuro-Symbolic Confidence Fusion Engine combining Neural, AST, and Dynamic Evidence via Bayesian calibration."""

import math
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from trace_engine.findings.model import FindingConfidence


class ConfidenceEvidence(BaseModel):
    """Signals supplied to the Bayesian Fusion Engine."""
    neural_score: Optional[float] = Field(None, description="SecureBERT 2.0 probability [0.0 - 1.0]")
    symbolic_ast_score: float = Field(0.5, description="AST dataflow & reachability confidence [0.0 - 1.0]")
    dynamic_test_score: Optional[float] = Field(None, description="Active probe verification confidence [0.0 - 1.0]")
    is_dynamically_confirmed: bool = Field(False, description="True if exploit payload was actively verified")
    has_sanitizer: bool = Field(False, description="True if defensive guard/sanitizer was identified in AST")


class FusedConfidenceResult(BaseModel):
    """Calibrated result from Neuro-Symbolic Bayesian evidence fusion."""
    posterior_probability: float = Field(..., description="Calibrated Bayesian posterior [0.0 - 1.0]")
    confidence_level: FindingConfidence = Field(..., description="Discrete confidence category")
    log_odds: float = Field(..., description="Log-odds score")
    evidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    rationale: str = Field(..., description="Explanation of signal weights and fusion outcome")


class NeuroSymbolicConfidenceEngine:
    """Combines Neural (System 1 SecureBERT), Symbolic AST (System 2 Dataflow Sinks),

    and Dynamic Verification signals into mathematically calibrated Bayesian confidence.
    """

    # Conservative baseline prior probability of vulnerability in enterprise code: 20%
    BASE_PRIOR_P: float = 0.20

    @classmethod
    def fuse_evidence(cls, evidence: ConfidenceEvidence) -> FusedConfidenceResult:
        """Calculates calibrated posterior probability from multiple independent security signals."""
        # Initial prior log-odds
        p0 = max(0.01, min(0.99, cls.BASE_PRIOR_P))
        log_odds = math.log(p0 / (1.0 - p0))

        breakdown: Dict[str, float] = {"prior": p0}

        # 1. Neural Evidence (SecureBERT)
        # Calibrated weight: 0.65 to prevent neural hallucinations from overpowering symbolic reality
        if evidence.neural_score is not None:
            p_bert = max(0.05, min(0.95, evidence.neural_score))
            lr_bert = p_bert / (1.0 - p_bert)
            w_bert = 0.65
            log_odds += w_bert * math.log(lr_bert)
            breakdown["neural_bert"] = p_bert

        # 2. Symbolic AST Evidence (Static Sinks & Control Flow)
        p_ast = max(0.05, min(0.95, evidence.symbolic_ast_score))
        if evidence.has_sanitizer:
            p_ast = max(0.02, p_ast * 0.15)  # Heavy penalty if sanitizer detected in dataflow

        lr_ast = p_ast / (1.0 - p_ast)
        w_ast = 1.0  # Full symbolic weight
        log_odds += w_ast * math.log(lr_ast)
        breakdown["symbolic_ast"] = p_ast

        # 3. Dynamic Runtime Evidence (Active Testpack Probes)
        if evidence.is_dynamically_confirmed:
            # Overwhelming likelihood ratio for mathematically/empirically proven exploits
            w_dyn = 2.5
            lr_dyn = 0.99 / 0.01
            log_odds += w_dyn * math.log(lr_dyn)
            breakdown["dynamic_test"] = 0.99
        elif evidence.dynamic_test_score is not None:
            p_dyn = max(0.05, min(0.95, evidence.dynamic_test_score))
            lr_dyn = p_dyn / (1.0 - p_dyn)
            w_dyn = 1.2
            log_odds += w_dyn * math.log(lr_dyn)
            breakdown["dynamic_test"] = p_dyn

        # Compute posterior probability from log-odds
        # Clamp log_odds to [-10, 10] to avoid float overflow
        clamped_lo = max(-10.0, min(10.0, log_odds))
        odds = math.exp(clamped_lo)
        posterior = odds / (1.0 + odds)
        posterior = round(max(0.01, min(0.999, posterior)), 4)

        # Categorize into standard discrete levels
        if evidence.is_dynamically_confirmed or posterior >= 0.95:
            level = FindingConfidence.CONFIRMED
        elif posterior >= 0.80:
            level = FindingConfidence.HIGH
        elif posterior >= 0.55:
            level = FindingConfidence.MEDIUM
        else:
            level = FindingConfidence.POTENTIAL

        # Generate explanatory rationale
        signals = []
        if evidence.is_dynamically_confirmed:
            signals.append("empirically verified by dynamic testpack")
        if evidence.neural_score and evidence.neural_score > 0.5:
            signals.append(f"SecureBERT semantic match ({int(evidence.neural_score*100)}%)")
        if evidence.symbolic_ast_score > 0.6:
            signals.append("AST dataflow path to sensitive sink confirmed")
        if evidence.has_sanitizer:
            signals.append("mitigated by detected input sanitizer")

        rationale = f"Bayesian calibrated confidence {int(posterior*100)}% based on: {', '.join(signals) if signals else 'baseline signals'}."

        return FusedConfidenceResult(
            posterior_probability=posterior,
            confidence_level=level,
            log_odds=round(clamped_lo, 3),
            evidence_breakdown=breakdown,
            rationale=rationale,
        )
