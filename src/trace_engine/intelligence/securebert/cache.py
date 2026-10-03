"""On-disk cache for SecureBERT embeddings and classification scores."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from trace_engine.ingest.hashing import hash_content


class SecureBERTCache:
    """Caches SecureBERT inferences by hash of input code/attack-path text."""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self._cache: Dict[str, Dict[str, float]] = {}
        self._load()

    def _load(self) -> None:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def get(self, text: str) -> Optional[Dict[str, float]]:
        key = hash_content(text)
        return self._cache.get(key)

    def set(self, text: str, scores: Dict[str, float]) -> None:
        key = hash_content(text)
        self._cache[key] = scores
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass
