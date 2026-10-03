"""Threshold and confidence gating for Laya decisions."""

from pydantic import BaseModel


class LayaThresholds(BaseModel):
    """Calibrated thresholds for Laya System 1 decision engine."""
    min_confidence: float = 0.82
    high_priority_cutoff: float = 0.75
    evidence_strong_cutoff: float = 0.80
    max_probes_per_endpoint: int = 5
    abstain_on_low_confidence: bool = True
