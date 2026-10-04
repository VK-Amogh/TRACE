"""Laya System 1 decision engine integration for TRACE."""

import time
import logging
from typing import Optional, List, Dict, Any

from trace_engine.intelligence.laya.schemas import (
    EndpointPriorityDecision,
    TestSelectionDecision,
    EvidenceStrengthDecision,
    ContinueTestingDecision,
)
from trace_engine.intelligence.laya.thresholds import LayaThresholds
from trace_engine.intelligence.laya.prompts import (
    format_endpoint_state,
    format_observation_state,
)
from trace_engine.intelligence.laya.telemetry import LayaTelemetry
from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel
from trace_engine.security.hypotheses import SecurityHypothesis

logger = logging.getLogger(__name__)


class LayaDecisionEngine:
    """Fast, non-autoregressive System 1 decision layer powered by Laya."""

    def __init__(self, model_id: str = "convaiinnovations/laya", thresholds: Optional[LayaThresholds] = None):
        self.model_id = model_id
        self.thresholds = thresholds or LayaThresholds()
        self.telemetry = LayaTelemetry()
        self._agent = None
        self._finetuned_model = None
        self._finetuned_tokenizer = None
        self._finetuned_device = "cpu"
        self._load_finetuned_model()
        if not self._finetuned_model:
            self._load_agent()

    def _load_finetuned_model(self) -> None:
        """Attempt to load fine-tuned Laya dual-head model from .trace/models/laya-finetuned."""
        from pathlib import Path
        model_dir = Path(".trace/models/laya-finetuned")
        weights_path = model_dir / "laya_dual_head.pt"
        if weights_path.exists():
            try:
                import torch
                from transformers import AutoTokenizer
                from trace_engine.intelligence.training.laya_trainer import LayaDualHeadModel

                self._finetuned_device = "cuda:0" if torch.cuda.is_available() else "cpu"
                self._finetuned_tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
                self._finetuned_model = LayaDualHeadModel().to(self._finetuned_device)
                self._finetuned_model.load_state_dict(
                    torch.load(weights_path, map_location=self._finetuned_device, weights_only=True)
                )
                self._finetuned_model.eval()
                logger.info("Fine-tuned Laya System 1 dual-head model loaded successfully")
            except Exception as e:
                logger.debug(f"Failed to load fine-tuned Laya model: {e}")
                self._finetuned_model = None

    def _load_agent(self) -> None:
        """Attempt to load Laya in-process model."""
        try:
            import laya
            self._agent = laya.load(self.model_id)
            logger.info(f"Laya agent loaded: {self.model_id}")
        except Exception as e:
            logger.debug(f"Laya in-process loading: {e}. Using calibrated fallback.")
            self._agent = None

    def is_available(self) -> bool:
        return self._finetuned_model is not None or self._agent is not None

    def decide_priority(self, endpoint: Endpoint, apm: AttackPathModel) -> EndpointPriorityDecision:
        """Assigns test priority to an endpoint using fine-tuned Laya, base Laya, or calibrated APM signals."""
        start_time = time.perf_counter()
        state = format_endpoint_state(endpoint, apm)

        if self._finetuned_model and self._finetuned_tokenizer:
            try:
                import torch
                from trace_engine.intelligence.training.laya_trainer import PRIORITY_LABELS
                enc = self._finetuned_tokenizer(state, max_length=128, padding="max_length", truncation=True, return_tensors="pt")
                input_ids = enc["input_ids"].to(self._finetuned_device)
                attention_mask = enc["attention_mask"].to(self._finetuned_device)
                with torch.no_grad():
                    prio_logits, _ = self._finetuned_model(input_ids, attention_mask)
                    prio_idx = torch.argmax(prio_logits, dim=-1).item()
                    prio_level = PRIORITY_LABELS[prio_idx]
                latency = (time.perf_counter() - start_time) * 1000
                decision = EndpointPriorityDecision(priority_level=prio_level, should_test=(prio_level != "low"))
                self.telemetry.record("priority", endpoint.display_name(), decision.model_dump(), latency)
                return decision
            except Exception as e:
                logger.debug(f"Finetuned Laya priority inference failed: {e}")

        if self._agent:
            try:
                res = self._agent.decide(state, schema=EndpointPriorityDecision)
                latency = (time.perf_counter() - start_time) * 1000
                self.telemetry.record("priority", endpoint.display_name(), res if isinstance(res, dict) else res.model_dump(), latency)
                if isinstance(res, dict):
                    return EndpointPriorityDecision.model_validate(res)
                return res
            except Exception as e:
                logger.debug(f"Laya decide_priority failed: {e}")

        # Calibrated fast deterministic rule when abstaining or model unavailable
        is_crit = (
            endpoint.sensitive_data
            or endpoint.external_network
            or (endpoint.object_identifier and not endpoint.auth_required)
        )
        is_high = endpoint.state_changing or endpoint.object_identifier or ("admin" in endpoint.roles)
        level = "critical" if is_crit else "high" if is_high else "medium"
        decision = EndpointPriorityDecision(priority_level=level, should_test=True)

        latency = (time.perf_counter() - start_time) * 1000
        self.telemetry.record("priority", endpoint.display_name(), decision.model_dump(), latency, abstained=True)
        return decision

    def decide_test_selection(
        self, endpoint: Endpoint, apm: AttackPathModel, hypotheses: List[SecurityHypothesis]
    ) -> TestSelectionDecision:
        """Selects the highest-information security test pack for this attack path."""
        start_time = time.perf_counter()
        state = format_endpoint_state(endpoint, apm)

        if self._finetuned_model and self._finetuned_tokenizer:
            try:
                import torch
                from trace_engine.intelligence.training.laya_trainer import TESTPACK_LABELS
                enc = self._finetuned_tokenizer(state, max_length=128, padding="max_length", truncation=True, return_tensors="pt")
                input_ids = enc["input_ids"].to(self._finetuned_device)
                attention_mask = enc["attention_mask"].to(self._finetuned_device)
                with torch.no_grad():
                    _, pack_logits = self._finetuned_model(input_ids, attention_mask)
                    probs = torch.softmax(pack_logits, dim=-1)
                    pack_idx = torch.argmax(pack_logits, dim=-1).item()
                    conf = probs[0, pack_idx].item()
                    pack_name = TESTPACK_LABELS[pack_idx]
                latency = (time.perf_counter() - start_time) * 1000
                decision = TestSelectionDecision(primary_testpack=pack_name, confidence=float(conf))
                self.telemetry.record("test_selection", endpoint.display_name(), decision.model_dump(), latency)
                return decision
            except Exception as e:
                logger.debug(f"Finetuned Laya testpack inference failed: {e}")

        if self._agent:
            try:
                res = self._agent.decide(state, schema=TestSelectionDecision)
                if isinstance(res, dict):
                    decision = TestSelectionDecision.model_validate(res)
                else:
                    decision = res
                if decision.confidence >= self.thresholds.min_confidence:
                    latency = (time.perf_counter() - start_time) * 1000
                    self.telemetry.record("test_selection", endpoint.display_name(), decision.model_dump(), latency)
                    return decision
            except Exception as e:
                logger.debug(f"Laya decide_test_selection failed: {e}")

        # Calibrated deterministic fallback
        # Check matching hypothesis
        matched_pack = "none"
        for h in hypotheses:
            if h.endpoint_id == endpoint.id:
                matched_pack = h.recommended_test_pack.lower()
                break

        if matched_pack == "none":
            if endpoint.external_network:
                matched_pack = "ssrf"
            elif endpoint.object_identifier:
                matched_pack = "bola"
            elif "admin" in endpoint.roles:
                matched_pack = "bfla"
            elif not endpoint.auth_required and endpoint.state_changing:
                matched_pack = "authentication"
            else:
                matched_pack = "injection"

        decision = TestSelectionDecision(primary_testpack=matched_pack, confidence=0.88)
        latency = (time.perf_counter() - start_time) * 1000
        self.telemetry.record("test_selection", endpoint.display_name(), decision.model_dump(), latency, abstained=True)
        return decision

    def decide_evidence_strength(
        self, endpoint: Endpoint, observation_summary: str, response_status: int
    ) -> EvidenceStrengthDecision:
        """Evaluates whether runtime observation provides conclusive proof of vulnerability."""
        start_time = time.perf_counter()
        state = format_observation_state(endpoint, observation_summary, response_status)

        if self._agent:
            try:
                res = self._agent.decide(state, schema=EvidenceStrengthDecision)
                latency = (time.perf_counter() - start_time) * 1000
                if isinstance(res, dict):
                    return EvidenceStrengthDecision.model_validate(res)
                return res
            except Exception:
                pass

        # Deterministic calibration
        obs_lower = observation_summary.lower()
        is_confirmed = "confirmed" in obs_lower or (response_status == 200 and "unauthorized" in obs_lower)
        strength = "strong" if is_confirmed else "moderate" if response_status in (200, 500) else "weak"

        decision = EvidenceStrengthDecision(
            strength=strength,
            confirmed_vulnerability=is_confirmed,
        )
        latency = (time.perf_counter() - start_time) * 1000
        self.telemetry.record("evidence_strength", endpoint.display_name(), decision.model_dump(), latency, abstained=True)
        return decision
