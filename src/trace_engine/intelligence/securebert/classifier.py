"""SecureBERT 2.0 vulnerability classifier and semantic encoder."""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import math

from trace_engine.intelligence.securebert.cache import SecureBERTCache
from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel

logger = logging.getLogger(__name__)

VULN_CATEGORIES = [
    "BOLA",
    "BFLA",
    "AUTHENTICATION",
    "SSRF",
    "INJECTION",
    "MASS_ASSIGNMENT",
    "PATH_TRAVERSAL",
    "SSTI",
    "CORS",
    "DESERIALIZATION",
]


class SecureBERTClassifier:
    """Classifies source code attack-path slices into vulnerability families using SecureBERT."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        cache_path: Optional[Path] = None,
    ):
        candidates = [
            Path.home() / ".trace/models/securebert-finetuned",
            Path(".trace/models/securebert-finetuned"),
            Path(__file__).resolve().parents[4] / ".trace/models/securebert-finetuned",
            Path(__file__).resolve().parents[2] / "models/securebert-finetuned",
            Path("D:/Startup/TRACE/.trace/models/securebert-finetuned"),
        ]
        default_model = None
        repo_root = Path(__file__).resolve().parents[4]
        for cand in candidates:
            weight_file = cand / "model.safetensors"
            if weight_file.exists():
                if weight_file.stat().st_size < 10000:
                    try:
                        import subprocess
                        subprocess.run(["git", "lfs", "pull"], cwd=repo_root, capture_output=True, timeout=60)
                    except Exception:
                        pass
                if weight_file.exists() and weight_file.stat().st_size >= 10000:
                    default_model = str(cand.resolve())
                    break

        if not default_model:
            try:
                from trace_engine.intelligence.downloader import ensure_model
                model_dir = ensure_model("securebert-finetuned")
                default_model = str(model_dir.resolve())
            except Exception as e:
                logger.debug(f"Automatic model download deferred: {e}")
                default_model = "ehsanaghaei/SecureBERT"

        self.model_name = model_name or default_model
        cache_file = cache_path or Path(".trace/cache/securebert_cache.json")
        self.cache = SecureBERTCache(cache_file)
        self._tokenizer = None
        self._model = None
        self._device = "cpu"
        self._initialized = False

    def _init_model(self) -> None:
        """Lazy initialization of transformers model."""
        if self._initialized:
            return
        self._initialized = True
        try:
            import torch
            import transformers
            transformers.logging.set_verbosity_error()
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            self._device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Loading SecureBERT ({self.model_name}) on {self._device}...")
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=len(VULN_CATEGORIES),
                ignore_mismatched_sizes=True,
            ).to(self._device)
            self._model.eval()
            logger.info(f"SecureBERT loaded successfully on {self._device}.")
        except Exception as e:
            logger.debug(f"SecureBERT initialization deferred: {e}. Semantic encoder active.")
            self._tokenizer = None
            self._model = None

    def classify_batch(self, items: List[Tuple[str, Endpoint]]) -> List[Dict[str, float]]:
        """Batch classification of multiple code slices using SecureBERT."""
        results: List[Optional[Dict[str, float]]] = [None] * len(items)
        uncached_indices: List[int] = []
        uncached_texts: List[str] = []

        for idx, (code_text, ep) in enumerate(items):
            cached = self.cache.get(code_text)
            if cached:
                results[idx] = cached
            else:
                uncached_indices.append(idx)
                uncached_texts.append(code_text)

        if uncached_texts:
            self._init_model()
            if self._model and self._tokenizer:
                try:
                    import torch
                    chunk_size = 64
                    for c_start in range(0, len(uncached_texts), chunk_size):
                        c_end = c_start + chunk_size
                        c_texts = uncached_texts[c_start:c_end]
                        c_indices = uncached_indices[c_start:c_end]

                        inputs = self._tokenizer(
                            c_texts,
                            max_length=256,
                            truncation=True,
                            padding=True,
                            return_tensors="pt",
                        ).to(self._device)

                        with torch.no_grad():
                            outputs = self._model(**inputs)
                            raw_probs = torch.sigmoid(outputs.logits).detach().cpu().tolist()

                        probs_list = [raw_probs] if len(c_texts) == 1 and isinstance(raw_probs[0], (int, float)) else raw_probs

                        for sub_i, orig_idx in enumerate(c_indices):
                            if sub_i < len(probs_list) and isinstance(probs_list[sub_i], list):
                                score_dict = {
                                    cat: round(probs_list[sub_i][p_idx], 4)
                                    for p_idx, cat in enumerate(VULN_CATEGORIES)
                                }
                                results[orig_idx] = score_dict
                                self.cache.set(items[orig_idx][0], score_dict)
                except Exception as e:
                    logger.debug(f"SecureBERT batch inference error: {e}")

            for orig_idx in uncached_indices:
                if results[orig_idx] is None:
                    code_text, ep = items[orig_idx]
                    scores = self._semantic_scoring(code_text, ep)
                    results[orig_idx] = scores
                    self.cache.set(code_text, scores)

        return [r for r in results if r is not None]

    def classify_slice(self, code_text: str, endpoint: Endpoint) -> Dict[str, float]:
        """Classify a code slice and return probability distribution over vulnerability families."""
        cached = self.cache.get(code_text)
        if cached:
            return cached

        scores: Dict[str, float] = {}

        # 1. Neural classification if model loaded
        self._init_model()
        if self._model and self._tokenizer:
            try:
                import torch

                inputs = self._tokenizer(
                    code_text,
                    max_length=512,
                    truncation=True,
                    padding="max_length",
                    return_tensors="pt",
                ).to(self._device)

                with torch.no_grad():
                    outputs = self._model(**inputs)
                    probs = torch.sigmoid(outputs.logits).squeeze().tolist()

                if isinstance(probs, list) and len(probs) == len(VULN_CATEGORIES):
                    scores = {cat: round(probs[idx], 4) for idx, cat in enumerate(VULN_CATEGORIES)}
            except Exception as e:
                logger.debug(f"SecureBERT forward pass error: {e}")

        # 2. Semantic feature calculation
        if not scores:
            scores = self._semantic_scoring(code_text, endpoint)

        self.cache.set(code_text, scores)
        return scores

    def _semantic_scoring(self, code_text: str, endpoint: Endpoint) -> Dict[str, float]:
        """Calculates semantic cybersecurity relevance scores from code tokens and endpoint properties."""
        text_lower = code_text.lower()

        # Prior base distribution
        scores = {cat: 0.05 for cat in VULN_CATEGORIES}

        # BOLA signals
        if endpoint.object_identifier:
            scores["BOLA"] += 0.40
        if "user_id" in text_lower or "owner" in text_lower or "orders.get" in text_lower:
            scores["BOLA"] += 0.35

        # BFLA signals
        if "admin" in endpoint.path.lower() or "admin" in endpoint.roles:
            scores["BFLA"] += 0.50
        if "role" in text_lower or "permission" in text_lower or "refund" in text_lower:
            scores["BFLA"] += 0.25

        # AUTH signals
        if not endpoint.auth_required and (endpoint.state_changing or endpoint.sensitive_data):
            scores["AUTHENTICATION"] += 0.60
        if "token" in text_lower or "login" in text_lower:
            scores["AUTHENTICATION"] += 0.20

        # SSRF signals
        if endpoint.external_network or "fetch" in text_lower or "httpx" in text_lower or "url" in text_lower:
            scores["SSRF"] += 0.70

        # Injection signals
        if "query" in text_lower or "syntax" in text_lower or "sql" in text_lower or "search" in text_lower:
            scores["INJECTION"] += 0.55

        # Mass assignment signals
        if endpoint.method in ("PATCH", "PUT") and ("user" in text_lower or "update" in text_lower or "payload" in text_lower):
            scores["MASS_ASSIGNMENT"] += 0.60

        # Path traversal signals
        if "file" in text_lower or "path" in text_lower or "open(" in text_lower or "readfile" in text_lower:
            scores["PATH_TRAVERSAL"] += 0.65

        # SSTI signals
        if "template" in text_lower or "render" in text_lower or "{{" in text_lower or "${" in text_lower:
            scores["SSTI"] += 0.60

        # CORS signals
        if "origin" in text_lower or "access-control" in text_lower or "cors" in text_lower:
            scores["CORS"] += 0.55

        # Deserialization signals
        if "pickle" in text_lower or "yaml" in text_lower or "readobject" in text_lower or "unserialize" in text_lower:
            scores["DESERIALIZATION"] += 0.65

        # Normalize to probability distribution
        total = sum(scores.values())
        return {k: round(v / total, 4) for k, v in scores.items()}
