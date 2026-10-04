"""TRACE Agent Harness Plugin - Core Interface.

Allows any AI coding agent harness (SWE-bench, Antigravity, OpenHands, Aider, Claude Code)
to plug in TRACE for autonomous vulnerability benchmark generation, attack-path modeling,
and deterministic verification.
"""

import os
import shutil
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

from trace_engine.findings.store import FindingStore
from trace_engine.plugin.task import HarnessTaskSpec
from trace_engine.plugin.swebench_adapter import build_harness_task, export_swebench_jsonl
from trace_engine.plugin.evaluator import HarnessEvaluator, EvaluationResult

logger = logging.getLogger("trace_harness_plugin")


class TraceHarnessPlugin:
    """Agent Harness Plugin interface for TRACE security evaluation and verification."""

    PLUGIN_NAME = "trace-security"
    VERSION = "2.0.0"

    def __init__(self, repo_path: Optional[Path] = None, target_url: str = "http://127.0.0.1:18080"):
        self.repo_path = Path(repo_path or ".").resolve()
        self.target_url = target_url
        self.finding_store = FindingStore(self.repo_path / ".trace")
        self.evaluator = HarnessEvaluator(self.repo_path, target_url=self.target_url)

    def list_tasks(self) -> List[HarnessTaskSpec]:
        """Generate benchmark task instances for all correlated vulnerabilities found in the repo."""
        findings = self.finding_store.load_findings()
        tasks: List[HarnessTaskSpec] = []
        for f in findings:
            task = build_harness_task(f, self.repo_path)
            tasks.append(task)
        return tasks

    def get_task(self, identifier: str) -> Optional[HarnessTaskSpec]:
        """Retrieve task by instance ID or finding ID."""
        for t in self.list_tasks():
            if t.instance_id == identifier or t.finding_id == identifier:
                return t
        return None

    def evaluate_patch(
        self,
        finding_id: str,
        patch_content: Optional[str] = None,
        target_file: Optional[str] = None,
        rollback_after: bool = False,
    ) -> EvaluationResult:
        """Evaluate a patch produced by an external agent against the ground-truth verification oracle."""
        return self.evaluator.evaluate_patch(
            finding_id=finding_id,
            patch_content=patch_content,
            target_file=target_file,
            rollback_after=rollback_after,
        )

    def export_dataset(self, output_path: Optional[Path] = None) -> Path:
        """Export all benchmark tasks to standard SWE-bench JSONL format."""
        out = output_path or (self.repo_path / "trace_bench_tasks.jsonl")
        tasks = self.list_tasks()
        export_swebench_jsonl(tasks, out)
        return out

    @staticmethod
    def get_plugin_template_dir() -> Path:
        """Locate the plugin template directory bundled with TRACE."""
        # Check workspace first, then module directory
        module_plugin = Path(__file__).resolve().parent / "bundle"
        return module_plugin

    def install(self, workspace_mode: bool = True, global_mode: bool = False) -> Dict[str, Path]:
        """Installs the TRACE plugin into workspace .agents/plugins/ or global ~/.gemini/config/plugins/."""
        installed_locations: Dict[str, Path] = {}

        bundle_dir = self.get_plugin_template_dir()
        if not bundle_dir.exists():
            raise FileNotFoundError(f"Plugin template directory not found at {bundle_dir}")

        if workspace_mode:
            ws_dest = self.repo_path / ".agents" / "plugins" / self.PLUGIN_NAME
            ws_dest.mkdir(parents=True, exist_ok=True)
            self._copy_bundle(bundle_dir, ws_dest)
            installed_locations["workspace"] = ws_dest

            # Direct agent skill directory (.agents/skills/trace-security-harness/)
            skill_src = bundle_dir / "skills" / "trace-security-harness"
            if skill_src.exists():
                skill_dest = self.repo_path / ".agents" / "skills" / "trace-security-harness"
                skill_dest.mkdir(parents=True, exist_ok=True)
                self._copy_bundle(skill_src, skill_dest)
                installed_locations["agent_skill"] = skill_dest

            # Claude Code skill integration (.claude/skills/trace-security/)
            claude_skill_dest = self.repo_path / ".claude" / "skills" / "trace-security"
            if skill_src.exists():
                claude_skill_dest.mkdir(parents=True, exist_ok=True)
                self._copy_bundle(skill_src, claude_skill_dest)
                installed_locations["claude_skill"] = claude_skill_dest

            # Generate or update .mcp.json for Claude Code and Cursor
            from trace_engine.mcp.config import generate_mcp_json
            try:
                mcp_file = generate_mcp_json(self.repo_path)
                installed_locations["mcp"] = mcp_file
                # Cursor MCP configuration (.cursor/mcp.json)
                cursor_mcp = self.repo_path / ".cursor" / "mcp.json"
                cursor_mcp.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(mcp_file, cursor_mcp)
                installed_locations["cursor_mcp"] = cursor_mcp
            except Exception:
                pass

        if global_mode:
            home = Path.home()
            global_dest = home / ".gemini" / "config" / "plugins" / self.PLUGIN_NAME
            global_dest.mkdir(parents=True, exist_ok=True)
            self._copy_bundle(bundle_dir, global_dest)
            installed_locations["global"] = global_dest

            # Global Claude configuration (~/.claude/skills/trace-security/)
            global_claude = home / ".claude" / "skills" / "trace-security"
            skill_src = bundle_dir / "skills" / "trace-security-harness"
            if skill_src.exists():
                global_claude.mkdir(parents=True, exist_ok=True)
                self._copy_bundle(skill_src, global_claude)
                installed_locations["global_claude"] = global_claude

        return installed_locations

    def _copy_bundle(self, src: Path, dest: Path) -> None:
        """Copy all files from plugin bundle into destination."""
        for item in src.rglob("*"):
            rel = item.relative_to(src)
            target = dest / rel
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)


__all__ = [
    "TraceHarnessPlugin",
    "HarnessTaskSpec",
    "HarnessEvaluator",
    "EvaluationResult",
    "build_harness_task",
    "export_swebench_jsonl",
]
