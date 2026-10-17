"""Base interfaces and context for TRACE test packs."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.security.hypotheses import SecurityHypothesis


class UserIdentity(BaseModel):
    """Synthetic test identity credentials."""
    username: str
    password: str
    token: Optional[str] = None
    role: str = "user"


class TestContext(BaseModel):
    """Context provided to a test pack execution."""
    __test__ = False
    target_base_url: str
    identities: Dict[str, UserIdentity] = Field(default_factory=dict)
    active_tokens: Dict[str, str] = Field(default_factory=dict)
    # Ready-made request headers per identity (bearer, api key, cookie, basic).
    # Takes precedence over ``active_tokens`` so real credentials never need
    # to be re-shaped into bearer tokens.
    auth_headers: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    # Opt-in: allow packs to create and delete their own test data.
    stateful: bool = False
    # Hints from an API description, e.g. ``{"POST /things": {"body": {...}}}``.
    api_hints: Dict[str, Any] = Field(default_factory=dict)

    def headers_for(self, name: str) -> Dict[str, str]:
        """Authentication headers for identity ``name`` (empty when unknown)."""
        if name in self.auth_headers:
            return dict(self.auth_headers[name])
        token = self.active_tokens.get(name, "")
        return {"Authorization": f"Bearer {token}"} if token else {}


class TestExecutionResult(BaseModel):
    """Outcome of running a test pack against a hypothesis."""
    __test__ = False
    testpack_name: str
    hypothesis_id: str
    confirmed: bool
    confidence: float
    summary: str
    observations: List[RuntimeObservation] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)


class TestPack(ABC):
    """Abstract base class for all security test packs."""
    __test__ = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the test pack (e.g., 'bola', 'ssrf')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what this pack validates."""
        pass

    @abstractmethod
    def execute(
        self,
        hypothesis: SecurityHypothesis,
        client: ScopedHttpClient,
        context: TestContext,
    ) -> TestExecutionResult:
        """Run the test pack against the given hypothesis using the scoped client."""
        pass
