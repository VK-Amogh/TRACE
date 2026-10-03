"""Ollama local AI provider."""

import httpx
from typing import Optional
from trace_engine.ai.base import AIProvider


class OllamaProvider(AIProvider):
    """Integrates with local Ollama runtime for offline model execution."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5-coder:latest",
        temperature: float = 0.1,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.temperature = temperature

    @property
    def name(self) -> str:
        return f"Ollama ({self.model})"

    def is_available(self) -> bool:
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(f"{self.endpoint}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": self.temperature},
            }
            if system_prompt:
                payload["system"] = system_prompt

            with httpx.Client(timeout=30.0) as client:
                res = client.post(f"{self.endpoint}/api/generate", json=payload)
                if res.status_code == 200:
                    return res.json().get("response")
        except Exception:
            pass
        return None
