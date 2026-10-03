"""Decision schemas for Laya System 1 fast decision engine."""

from typing import Literal, Optional, List
from pydantic import BaseModel, Field


class EndpointPriorityDecision(BaseModel):
    """Laya decision for assigning audit priority to an endpoint."""
    priority_level: Literal["critical", "high", "medium", "low"] = Field(
        description="Calculated audit priority based on attack surface exposure"
    )
    should_test: bool = Field(
        description="Whether this endpoint requires active runtime security testing"
    )


class TestSelectionDecision(BaseModel):
    """Laya decision for selecting the primary test pack."""
    primary_testpack: Literal[
        "bola", "bfla", "authentication", "ssrf", "injection", "mass_assignment", "none"
    ] = Field(description="Most informative security test pack for this attack path")
    confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Model confidence in test pack selection",
    )


class EvidenceStrengthDecision(BaseModel):
    """Laya decision for evaluating runtime observation evidence strength."""
    strength: Literal["weak", "moderate", "strong"] = Field(
        description="Calibrated strength of observed security anomaly"
    )
    confirmed_vulnerability: bool = Field(
        description="Whether the anomaly provides sufficient proof of exploitability"
    )


class ContinueTestingDecision(BaseModel):
    """Laya decision on whether to continue probing or stop."""
    should_continue: bool = Field(
        description="Whether additional test probes are required"
    )
    stop_reason: Literal["sufficient_proof", "not_vulnerable", "budget_exceeded", "scope_boundary"] = Field(
        default="sufficient_proof",
        description="Reason for concluding test sequence",
    )
