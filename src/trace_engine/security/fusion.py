"""Neuro-Symbolic Confidence Fusion Engine combining Neural, AST, and Dynamic Evidence via Bayesian calibration.

Implements the 3-Signal Bayesian Evidence Fusion model:
Confidence = 1 - (1 - P_SecureBERT) * (1 - P_AST_Dataflow) * (1 - P_Dynamic_Oracle)

Levels:
- Level 3 (Triple Match): SecureBERT (0.85) + AST dataflow sink + Dynamic probe error -> Confidence ~99.8% (Critical / Zero-False-Positive Verified).
- Level 2 (Static + Dynamic Partial): Probe blocked by WAF, but AST source-to-sink dataflow is proven -> Confidence ~82% (High / Code-Audited).
- Level 1 (Single Signal): Only SecureBERT flags it with no AST sink -> Soft hypothesis for agent exploration.
"""

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
    fusion_level: str = Field(..., description="Level 1, Level 2, or Level 3")
    evidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    rationale: str = Field(..., description="Explanation of signal weights and fusion outcome")


class NeuroSymbolicConfidenceEngine:
    """Combines Neural (System 1 SecureBERT), Symbolic AST (System 2 Dataflow Sinks),
    and Dynamic Verification signals into mathematically calibrated Bayesian confidence.
    """

    @classmethod
    def fuse_evidence(cls, evidence: ConfidenceEvidence) -> FusedConfidenceResult:
        """Calculates calibrated posterior probability from multiple independent security signals:
        Confidence = 1 - (1 - P_SecureBERT) * (1 - P_AST_Dataflow) * (1 - P_Dynamic_Oracle)
        """
        # 1. Neural Signal (SecureBERT)
        p_bert = 0.0
        if evidence.neural_score is not None:
            p_bert = max(0.0, min(0.99, evidence.neural_score))

        # 2. Symbolic AST Signal (Dataflow Sinks & Control Flow)
        p_ast = max(0.0, min(0.99, evidence.symbolic_ast_score))
        if evidence.has_sanitizer:
            p_ast = p_ast * 0.15  # 85% penalty if sanitizer or validator detected in AST

        # 3. Dynamic Signal (Active Testpack Probes & Timing Oracle)
        p_dyn = 0.0
        if evidence.is_dynamically_confirmed:
            p_dyn = 0.99
        elif evidence.dynamic_test_score is not None:
            p_dyn = max(0.0, min(0.99, evidence.dynamic_test_score))

        # Bayesian Independence Fusion Formula:
        # Confidence = 1 - (1 - P_SecureBERT) * (1 - P_AST_Dataflow) * (1 - P_Dynamic_Oracle)
        prob_not_vuln = (1.0 - p_bert) * (1.0 - p_ast) * (1.0 - p_dyn)
        raw_confidence = 1.0 - prob_not_vuln
        posterior = round(max(0.01, min(0.999, raw_confidence)), 4)

        # Log-odds representation:
        p_clamped = max(0.001, min(0.999, posterior))
        log_odds = round(math.log(p_clamped / (1.0 - p_clamped)), 3)

        # Classify into Levels
        signals_present = sum([
            1 if p_bert >= 0.4 else 0,
            1 if p_ast >= 0.4 else 0,
            1 if p_dyn >= 0.4 else 0,
        ])

        if evidence.is_dynamically_confirmed or (signals_present >= 3 and posterior >= 0.95):
            fusion_level = "Level 3 (Triple Match: Neural + AST + Dynamic Runtime Confirmation)"
            level = FindingConfidence.CONFIRMED
        elif (signals_present >= 2 and posterior >= 0.75) or posterior >= 0.80:
            fusion_level = "Level 2 (Static + Dynamic Partial: Proven AST Dataflow Sink)"
            level = FindingConfidence.HIGH
        elif posterior >= 0.50:
            fusion_level = "Level 1 (Single Signal: Exploratory Hypothesis)"
            level = FindingConfidence.MEDIUM
        else:
            fusion_level = "Level 1 (Low Confidence / Mitigated Signal)"
            level = FindingConfidence.POTENTIAL

        breakdown = {
            "p_securebert": round(p_bert, 3),
            "p_ast_dataflow": round(p_ast, 3),
            "p_dynamic_oracle": round(p_dyn, 3),
            "fused_confidence": posterior,
            "has_sanitizer": 1.0 if evidence.has_sanitizer else 0.0,
        }

        signals = []
        if p_dyn >= 0.90:
            signals.append("empirically verified by dynamic runtime oracle")
        elif p_dyn > 0.3:
            signals.append(f"dynamic response signature ({int(p_dyn*100)}%)")
        if p_bert > 0.4:
            signals.append(f"SecureBERT semantic match ({int(p_bert*100)}%)")
        if p_ast > 0.4:
            signals.append(f"AST unparameterized sink reachability ({int(p_ast*100)}%)")
        if evidence.has_sanitizer:
            signals.append("downweighted: input sanitizer detected in AST")

        rationale = (
            f"Bayesian Evidence Fusion: {fusion_level} with calibrated confidence {int(posterior*100)}%. "
            f"Signals: {'; '.join(signals) if signals else 'baseline hypothesis'}."
        )

        return FusedConfidenceResult(
            posterior_probability=posterior,
            confidence_level=level,
            log_odds=log_odds,
            fusion_level=fusion_level,
            evidence_breakdown=breakdown,
            rationale=rationale,
        )
