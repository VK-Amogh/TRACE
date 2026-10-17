"""Configuration settings for TRACE using Pydantic."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ProjectSettings(BaseModel):
    name: str = "default-project"
    version: str = "1.0.0"
    mode: str = "local"


class AISettings(BaseModel):
    provider: str = "ollama"
    model: str = "qwen2.5-coder:latest"
    temperature: float = 0.1
    endpoint: str = "http://127.0.0.1:11434"


class TargetSettings(BaseModel):
    url: str = "http://127.0.0.1:8000"
    scope_mode: str = "local"
    allowed_hosts: List[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    )
    allowed_ports: List[int] = Field(
        default_factory=lambda: [80, 443, 3000, 5000, 8000, 8080, 18080]
    )


class RuntimeSettings(BaseModel):
    max_requests: int = 1000
    concurrency: int = 2
    rate_limit_per_second: int = 5
    timeout_seconds: float = 8.0
    max_redirects: int = 3
    destructive_tests: bool = False


class AnalysisSettings(BaseModel):
    max_graph_hops: int = 3
    max_source_context_lines: int = 120
    enable_tree_sitter: bool = True


class TestsSettings(BaseModel):
    enabled: List[str] = Field(
        default_factory=lambda: [
            "bola",
            "bfla",
            "authentication",
            "ssrf",
            "injection",
            "mass_assignment",
        ]
    )


class ToolsSettings(BaseModel):
    enabled: List[str] = Field(
        default_factory=lambda: ["schemathesis", "nuclei", "zap", "trufflehog"]
    )


class IdentityConfig(BaseModel):
    """One test identity. Secrets may be ``${ENV_VAR}`` references."""

    kind: str = "bearer"  # bearer | api_key | cookie | basic | header
    token: Optional[str] = None
    header: Optional[str] = None  # api_key / header kinds (default X-API-Key)
    cookie: Optional[str] = None  # cookie kind (default "session")
    username: Optional[str] = None
    password: Optional[str] = None


class TraceConfig(BaseModel):
    project: ProjectSettings = Field(default_factory=ProjectSettings)
    ai: AISettings = Field(default_factory=AISettings)
    target: TargetSettings = Field(default_factory=TargetSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    tests: TestsSettings = Field(default_factory=TestsSettings)
    tools: ToolsSettings = Field(default_factory=ToolsSettings)
    identities: Dict[str, IdentityConfig] = Field(default_factory=dict)
