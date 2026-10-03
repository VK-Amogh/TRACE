"""Base interfaces for local AI providers."""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class AIProvider(ABC):
    """Abstract interface for local LLM engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if local inference engine is reachable."""
        pass

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Generate a response using the local model."""
        pass
