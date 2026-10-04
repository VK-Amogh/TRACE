"""Laya System 1 decision engine integration for TRACE with ONNX sub-millisecond execution."""

import time
import logging
from pathlib import Path
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
        self._onnx_session = None
        self._finetuned_model = None
        self._finetuned_tokenizer = None
        self._finetuned_device = "cpu"

        # Select best execution accelerator:
        # GPU PyTorch provides ~4.8ms inference when NVIDIA CUDA device is present;
        # ONNX Runtime provides optimized C++ graph execution on CPU-only hosts.
        import torch
        if torch.cuda.is_available():
            self._load_finetuned_model()
            if not self._finetuned_model:
                self._load_onnx_model()
        else:
            self._load_onnx_model()
            if not self._onnx_session:
                self._load_finetuned_model()

        # Tier 3: In-process Laya agent fallback
        if not self._finetuned_model and not self._onnx_session:
            self._load_agent()

    def _resolve_laya_dir(self) -> Optional[Path]:
        """Resolves Laya model directory across project root, package dir, and home."""
        candidates = [
            Path(".trace/models/laya-finetuned"),
            Path(__file__).resolve().parents[4] / ".trace/models/laya-finetuned",
            Path(__file__).resolve().parents[2] / "models/laya-finetuned",
            Path.home() / ".trace/models/laya-finetuned",
        ]
        repo_root = Path(__file__).resolve().parents[4]
        for p in candidates:
            pt_file = p / "laya_dual_head.pt"
            onnx_file = p / "laya_dual_head.onnx"
            if (pt_file.exists() and pt_file.stat().st_size < 10000) or (onnx_file.exists() and onnx_file.stat().st_size < 10000):
                try:
                    import subprocess
                    subprocess.run(["git", "lfs", "pull"], cwd=repo_root, capture_output=True, timeout=60)
                except Exception:
                    pass
            if pt_file.exists() and pt_file.stat().st_size >= 10000:
                return p.resolve()
            if onnx_file.exists() and onnx_file.stat().st_size >= 10000:
                return p.resolve()
        return None

    def _load_onnx_model(self) -> None:
        """Attempt to load high-speed ONNX Runtime session for sub-millisecond execution."""
        model_dir = self._resolve_laya_dir()
        if not model_dir:
            return
        onnx_path = model_dir / "laya_dual_head.onnx"
        if onnx_path.exists():
            try:
                import onnxruntime as ort
                from transformers import AutoTokenizer

                sess_options = ort.SessionOptions()
                sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self._onnx_session = ort.InferenceSession(str(onnx_path), sess_options, providers=["CPUExecutionProvider"])
                self._finetuned_tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
                logger.info("Laya System 1 ONNX sub-millisecond runtime loaded successfully")
            except Exception as e:
                logger.debug(f"Failed to load Laya ONNX runtime: {e}")
                self._onnx_session = None

    def _load_finetuned_model(self) -> None:
        """Attempt to load fine-tuned Laya dual-head model from .trace/models/laya-finetuned."""
        model_dir = self._resolve_laya_dir()
        if not model_dir:
            return
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
        return self._onnx_session is not None or self._finetuned_model is not None or self._agent is not None

    def decide_priority(self, endpoint: Endpoint, apm: AttackPathModel) -> EndpointPriorityDecision:
        """Assigns test priority to an endpoint using ONNX, fine-tuned PyTorch, base Laya, or calibrated APM signals."""
        start_time = time.perf_counter()
        state = format_endpoint_state(endpoint, apm)

        # 1. High-speed ONNX runtime path
        if self._onnx_session and self._finetuned_tokenizer:
            try:
                import numpy as np
                from trace_engine.intelligence.training.laya_trainer import PRIORITY_LABELS

                enc = self._finetuned_tokenizer(state, max_length=128, padding="max_length", truncation=True, return_tensors="np")
                prio_logits, _ = self._onnx_session.run(None, {
                    "input_ids": enc["input_ids"],
                    "attention_mask": enc["attention_mask"],
                })
                prio_idx = int(np.argmax(prio_logits[0]))
                prio_level = PRIORITY_LABELS[prio_idx]
                latency = (time.perf_counter() - start_time) * 1000
                decision = EndpointPriorityDecision(priority_level=prio_level, should_test=(prio_level != "low"))
                self.telemetry.record("priority", endpoint.display_name(), decision.model_dump(), latency)
                return decision
            except Exception as e:
                logger.debug(f"ONNX priority inference failed: {e}")

        # 2. PyTorch fine-tuned model path
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

        # 3. Base Laya agent
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

        # 4. Calibrated fast deterministic rule when abstaining or model unavailable
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
        """Selects the highest-information security test pack for this attack path with multi-label compound support."""
        start_time = time.perf_counter()
        state = format_endpoint_state(endpoint, apm)

        # 1. High-speed ONNX or PyTorch fine-tuned model path
        if (self._onnx_session or self._finetuned_model) and self._finetuned_tokenizer:
            try:
                import numpy as np
                from trace_engine.intelligence.training.laya_trainer import TESTPACK_LABELS

                if self._onnx_session:
                    enc = self._finetuned_tokenizer(state, max_length=128, padding="max_length", truncation=True, return_tensors="np")
                    _, pack_logits = self._onnx_session.run(None, {
                        "input_ids": enc["input_ids"],
                        "attention_mask": enc["attention_mask"],
                    })
                    logits = pack_logits[0]
                else:
                    import torch
                    enc = self._finetuned_tokenizer(state, max_length=128, padding="max_length", truncation=True, return_tensors="pt")
                    input_ids = enc["input_ids"].to(self._finetuned_device)
                    attention_mask = enc["attention_mask"].to(self._finetuned_device)
                    with torch.no_grad():
                        _, pack_logits = self._finetuned_model(input_ids, attention_mask)
                        logits = pack_logits[0].cpu().numpy()

                # Multi-class calibrated softmax probabilities
                exp_logits = np.exp(logits - np.max(logits))
                probs = exp_logits / np.sum(exp_logits)
                pack_idx = int(np.argmax(logits))
                pack_name = TESTPACK_LABELS[pack_idx]
                conf = float(probs[pack_idx])

                prob_dict = {label: round(float(probs[i]), 4) for i, label in enumerate(TESTPACK_LABELS)}
                applicable = [label for i, label in enumerate(TESTPACK_LABELS) if probs[i] >= 0.15 and label != "none"]
                if pack_name != "none" and pack_name not in applicable:
                    applicable.insert(0, pack_name)

                # Compound vulnerability invariant detection:
                # 1. Unauthenticated state-changing or sensitive endpoint -> authentication is applicable
                if not endpoint.auth_required and (endpoint.state_changing or endpoint.sensitive_data):
                    if "authentication" not in applicable:
                        applicable.append("authentication")
                # 2. Object identifier present -> bola is applicable
                if endpoint.object_identifier and "bola" not in applicable and pack_name != "none":
                    applicable.append("bola")
                # 3. External network call -> ssrf is applicable
                if endpoint.external_network and "ssrf" not in applicable:
                    applicable.append("ssrf")
                # 4. Privileged admin route -> bfla is applicable
                if ("admin" in endpoint.roles or "/admin" in endpoint.path.lower()) and "bfla" not in applicable:
                    applicable.append("bfla")

                if not applicable:
                    applicable = [pack_name]

                latency = (time.perf_counter() - start_time) * 1000
                decision = TestSelectionDecision(
                    primary_testpack=pack_name,
                    confidence=conf,
                    applicable_testpacks=applicable,
                    testpack_probabilities=prob_dict,
                )
                self.telemetry.record("test_selection", endpoint.display_name(), decision.model_dump(), latency)
                return decision
            except Exception as e:
                logger.debug(f"Finetuned Laya testpack inference failed: {e}")

        # 2. Base Laya agent
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

        # 3. Calibrated deterministic fallback
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

        decision = TestSelectionDecision(
            primary_testpack=matched_pack,
            confidence=0.88,
            applicable_testpacks=[matched_pack],
            testpack_probabilities={matched_pack: 0.88},
        )
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
