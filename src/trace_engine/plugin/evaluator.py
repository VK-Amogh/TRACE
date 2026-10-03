"""Evaluation oracle for the TRACE Agent Harness Plugin."""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from trace_engine.verify import VerificationEngine, VerificationResult
from trace_engine.harness.patcher import TransactionalPatcher, PatchOperationResult

logger = logging.getLogger("trace_plugin_evaluator")


class EvaluationResult(BaseModel):
    """Evaluation result for an agent-generated patch."""
    task_id: str
    finding_id: str
    passed: bool
    verified_resolved: bool
    reproduced_exploit_blocked: bool
    regressions_detected: bool
    confidence_score: float
    output_message: str
    verification_details: Dict[str, Any] = Field(default_factory=dict)
    patch_applied: bool = False


class HarnessEvaluator:
    """Evaluates patches produced by external AI agent harnesses against TRACE ground-truth test packs."""

    def __init__(self, repo_path: Path, target_url: str = "http://127.0.0.1:18080"):
        self.repo_path = repo_path.resolve()
        self.target_url = target_url
        self.patcher = TransactionalPatcher(self.repo_path)
        self.verifier = VerificationEngine(repo_path=self.repo_path, target_url=self.target_url)

    def evaluate_patch(
        self,
        finding_id: str,
        patch_content: Optional[str] = None,
        target_file: Optional[str] = None,
        rollback_after: bool = False,
    ) -> EvaluationResult:
        """Applies an agent patch, runs the TRACE verification oracle, and returns grading results."""
        patch_res: Optional[PatchOperationResult] = None

        if patch_content and target_file:
            # External patch provided as raw code or diff
            patch_res = self.patcher.apply_full_content(
                finding_id=finding_id,
                rel_path=target_file,
                new_content=patch_content,
            )
            if not patch_res.success:
                return EvaluationResult(
                    task_id=f"task_{finding_id}",
                    finding_id=finding_id,
                    passed=False,
                    verified_resolved=False,
                    reproduced_exploit_blocked=False,
                    regressions_detected=False,
                    confidence_score=0.0,
                    output_message=f"Failed to apply patch: {patch_res.error}",
                    patch_applied=False,
                )

        # Run verification engine against live runtime / APM
        try:
            ver_res: VerificationResult = self.verifier.verify(finding_id)
            is_resolved = (ver_res.status.value == "FIXED") or ver_res.remediation_verified
            exploit_blocked = is_resolved

            passed = is_resolved
            msg = f"Verification {ver_res.status.value}: {ver_res.summary}"

            result = EvaluationResult(
                task_id=f"task_{finding_id}",
                finding_id=finding_id,
                passed=passed,
                verified_resolved=is_resolved,
                reproduced_exploit_blocked=exploit_blocked,
                regressions_detected=False,
                confidence_score=1.0 if passed else 0.0,
                output_message=msg,
                verification_details=ver_res.model_dump(),
                patch_applied=patch_res.success if patch_res else True,
            )
        except Exception as e:
            logger.exception("Error executing verification oracle")
            result = EvaluationResult(
                task_id=f"task_{finding_id}",
                finding_id=finding_id,
                passed=False,
                verified_resolved=False,
                reproduced_exploit_blocked=False,
                regressions_detected=False,
                confidence_score=0.0,
                output_message=f"Verification exception: {e}",
                patch_applied=patch_res.success if patch_res else False,
            )

        if rollback_after and patch_res and patch_res.backup_file and target_file:
            self.patcher.rollback(target_file, Path(patch_res.backup_file))

        return result
