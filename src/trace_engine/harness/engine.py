"""Core Agent Harness execution engine for autonomous security auditing and self-healing."""

import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from trace_engine.findings.model import Finding, Severity
from trace_engine.findings.store import FindingStore
from trace_engine.verify import VerificationEngine, VerificationResult, VerificationStatus
from trace_engine.harness.context import (
    AgentRemediationPackage,
    PatchResult,
    HarnessExecutionReport,
)
from trace_engine.harness.patcher import SafePatcher
from trace_engine.harness.remediators import AutonomousRemediator


class AgentHarness:
    """The TRACE Agent Harness provides an autonomous execution and verification environment

    for AI coding models to inspect, patch, and mathematically prove security remediations.
    """

    def __init__(self, repo_path: Path, target_url: str = "http://127.0.0.1:18080"):
        self.repo_path = repo_path.resolve()
        self.target_url = target_url
        self.trace_dir = self.repo_path / ".trace"
        self.store = FindingStore(self.trace_dir)
        self.patcher = SafePatcher(self.repo_path)
        self.verifier = VerificationEngine(self.repo_path, target_url=target_url)

    def get_findings(self) -> List[Finding]:
        """Load currently stored findings ordered strictly by priority."""
        raw_findings = self.store.load_findings()
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(raw_findings, key=lambda f: severity_order.get(f.severity, 5))

    def calculate_posture_score(self, findings: List[Finding]) -> int:
        """Calculates 0-100 security health posture score."""
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        return max(0, 100 - (crit * 20 + high * 10 + med * 3))

    def build_remediation_package(self, finding: Finding, rank: int = 1) -> AgentRemediationPackage:
        """Packages rich context, surrounding AST lines, and exploit proof for an AI agent."""
        file_path = self.repo_path / finding.source_location.file
        if not file_path.exists():
            for sub in self.repo_path.iterdir():
                if sub.is_dir() and (sub / finding.source_location.file).exists():
                    file_path = sub / finding.source_location.file
                    break

        code_snippet = ""
        if file_path.exists():
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, finding.source_location.line_start - 5)
            end = min(len(lines), finding.source_location.line_end + 10)
            code_snippet = "\n".join(lines[start:end])

        return AgentRemediationPackage(
            finding_id=finding.id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity.value,
            priority_rank=rank,
            endpoint=finding.endpoint,
            source_file=finding.source_location.file,
            line_start=finding.source_location.line_start,
            line_end=finding.source_location.line_end,
            code_snippet=code_snippet,
            attack_path_hops=finding.attack_path,
            runtime_exploit_proof=finding.runtime_evidence,
            remediation_guidance=finding.remediation,
            reproduction_steps=finding.reproduction_steps,
            verification_criteria=(
                f"Neutralize exploit so re-executing {finding.endpoint} receives HTTP 401/403 "
                "or validates tenant/object authorization boundaries."
            ),
        )

    def get_next_target(self) -> Optional[AgentRemediationPackage]:
        """Returns the highest priority unmitigated finding packaged for agent consumption."""
        findings = self.get_findings()
        if not findings:
            return None
        return self.build_remediation_package(findings[0], rank=1)

    def apply_patch(
        self,
        finding_id: str,
        rel_path: str,
        target_content: str,
        replacement_content: str,
    ) -> PatchResult:
        """Applies patch with transactional backup."""
        return self.patcher.apply_replacement(
            finding_id=finding_id,
            rel_path=rel_path,
            target_content=target_content,
            replacement_content=replacement_content,
        )

    def verify_patch(self, finding_id: str) -> VerificationResult:
        """Verifies patch via AST re-indexing and live runtime test pack replay."""
        return self.verifier.verify(finding_id)

    def run_self_healing_loop(self) -> HarnessExecutionReport:
        """Autonomous self-healing execution loop:

        Iterates through prioritized findings, synthesizes defensive patches,
        applies them transactionally, and verifies runtime neutralization.
        """
        t0 = time.perf_counter()
        initial_findings = self.get_findings()
        baseline_score = self.calculate_posture_score(initial_findings)

        verified_patches = []
        unresolved = []

        for idx, finding in enumerate(initial_findings, 1):
            pkg = self.build_remediation_package(finding, rank=idx)
            synth_patch = AutonomousRemediator.generate_patch(pkg)

            if not synth_patch:
                unresolved.append(finding.id)
                continue

            target_block, replacement_block = synth_patch
            patch_res = self.apply_patch(
                finding_id=finding.id,
                rel_path=finding.source_location.file,
                target_content=target_block,
                replacement_content=replacement_block,
            )

            if not patch_res.success:
                unresolved.append(finding.id)
                continue

            # Verify differential impact with verification oracle
            v_res = self.verify_patch(finding.id)
            if v_res.status == VerificationStatus.FIXED:
                verified_patches.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "file": finding.source_location.file,
                    "diff": patch_res.diff,
                    "verification": v_res.model_dump(),
                })
            else:
                # Verification failed or broke runtime tests: cleanly roll back patch
                if patch_res.backup_file:
                    self.patcher.rollback(finding.source_location.file, Path(patch_res.backup_file))
                unresolved.append(finding.id)

        remaining_count = len(unresolved)
        fixed_count = len(verified_patches)
        total_count = len(initial_findings)
        
        # New score calculation based on neutralized findings
        final_score = min(100, baseline_score + (fixed_count * 15))
        if fixed_count == total_count and total_count > 0:
            final_score = 100

        elapsed = time.perf_counter() - t0

        return HarnessExecutionReport(
            project_name=self.repo_path.name,
            baseline_score=baseline_score,
            final_score=final_score,
            score_delta=final_score - baseline_score,
            total_findings=total_count,
            fixed_findings=fixed_count,
            remaining_findings=remaining_count,
            fix_rate_percent=round((fixed_count / total_count * 100), 1) if total_count else 100.0,
            verified_patches=verified_patches,
            unresolved_findings=unresolved,
            execution_time_seconds=round(elapsed, 2),
        )
