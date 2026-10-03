"""AI and deterministic test planner for orchestrating security validation."""

from typing import List, Optional
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.ai.base import AIProvider
from trace_engine.ai.ollama import OllamaProvider


class TestPlanner:
    """Orchestrates test selection using deterministic signals and optional local AI reasoning."""

    def __init__(self, ai_provider: Optional[AIProvider] = None):
        self.ai_provider = ai_provider or OllamaProvider()

    def prioritize_hypotheses(
        self, hypotheses: List[SecurityHypothesis]
    ) -> List[SecurityHypothesis]:
        """Orders hypotheses by severity prior and attack surface criticality."""
        return sorted(hypotheses, key=lambda h: h.confidence_prior, reverse=True)

    def explain_finding_with_ai(
        self, title: str, category: str, attack_path: List[str], evidence: List[str]
    ) -> str:
        """Uses local AI if available to explain root cause and exploitability in plain language."""
        if self.ai_provider and self.ai_provider.is_available():
            prompt = (
                f"Explain the security vulnerability '{title}' in category {category}.\n"
                f"Attack path hops: {' -> '.join(attack_path)}\n"
                f"Evidence: {'; '.join(evidence)}\n"
                f"Provide a concise, 2-3 sentence technical explanation of the exploit risk and fix."
            )
            response = self.ai_provider.generate(prompt)
            if response:
                return response.strip()

        # Fallback explanation
        return (
            f"The attack path violates security invariant {category}. "
            f"Static code flow reaches sensitive sink without boundary enforcement."
        )
