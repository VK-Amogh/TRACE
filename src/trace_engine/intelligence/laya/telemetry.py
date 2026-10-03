"""Telemetry and decision logging for Laya."""

import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class DecisionLog(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    decision_type: str
    endpoint: str
    decision_data: Dict[str, Any]
    latency_ms: float
    abstained: bool = False


class LayaTelemetry:
    """Records Laya System 1 decisions for auditability and calibration."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path
        self.logs: List[DecisionLog] = []

    def record(
        self,
        decision_type: str,
        endpoint: str,
        decision_data: Dict[str, Any],
        latency_ms: float,
        abstained: bool = False,
    ) -> None:
        entry = DecisionLog(
            decision_type=decision_type,
            endpoint=endpoint,
            decision_data=decision_data,
            latency_ms=latency_ms,
            abstained=abstained,
        )
        self.logs.append(entry)
        if self.log_path:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry.model_dump()) + "\n")
            except Exception:
                pass
