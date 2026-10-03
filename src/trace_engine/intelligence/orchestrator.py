"""Intelligence Orchestrator implementing Section 9 model hierarchy.

Deterministic rules -> SecureBERT -> Laya System 1 -> Local LLM -> Test Engine
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel
from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory
from trace_engine.intelligence.securebert.classifier import SecureBERTClassifier
from trace_engine.intelligence.laya.router import LayaDecisionEngine
from trace_engine.ai.planner import TestPlanner


class TestPlanRecommendation(BaseModel):
    endpoint_id: str
    endpoint_display: str
    primary_testpack: str
    priority_level: str
    securebert_scores: Dict[str, float]
    laya_confidence: float
    decision_path: str
    rationale: str


class IntelligenceOrchestrator:
    """Orchestrates deterministic signals, SecureBERT embeddings, and Laya decisions."""

    def __init__(
        self,
        securebert: Optional[SecureBERTClassifier] = None,
        laya_engine: Optional[LayaDecisionEngine] = None,
        llm_planner: Optional[TestPlanner] = None,
    ):
        self.securebert = securebert or SecureBERTClassifier()
        self.laya = laya_engine or LayaDecisionEngine()
        self.llm_planner = llm_planner or TestPlanner()

    def evaluate_endpoint(
        self,
        endpoint: Endpoint,
        code_slice: str,
        apm: AttackPathModel,
        hypotheses: List[SecurityHypothesis],
    ) -> TestPlanRecommendation:
        """Evaluates an endpoint through the complete intelligence stack."""
        # 1. SecureBERT vulnerability family scoring
        bert_scores = self.securebert.classify_slice(code_slice, endpoint)

        # 2. Laya System 1 decision (priority & test selection)
        priority_dec = self.laya.decide_priority(endpoint, apm)
        test_dec = self.laya.decide_test_selection(endpoint, apm, hypotheses)

        # 3. Model hierarchy reconciliation
        # If SecureBERT shows high probability for a specific category (e.g. BOLA > 0.4)
        top_category = max(bert_scores, key=bert_scores.get)
        chosen_pack = test_dec.primary_testpack

        decision_path = "deterministic"
        if self.laya.is_available():
            decision_path = "laya_system1"
        elif bert_scores.get(top_category, 0) > 0.35:
            decision_path = "securebert_guided"

        rationale = (
            f"Evaluated via {decision_path}. "
            f"Top vulnerability family: {top_category} ({int(bert_scores.get(top_category, 0) * 100)}%). "
            f"Assigned priority: {priority_dec.priority_level}."
        )

        return TestPlanRecommendation(
            endpoint_id=endpoint.id,
            endpoint_display=endpoint.display_name(),
            primary_testpack=chosen_pack,
            priority_level=priority_dec.priority_level,
            securebert_scores=bert_scores,
            laya_confidence=test_dec.confidence,
            decision_path=decision_path,
            rationale=rationale,
        )
