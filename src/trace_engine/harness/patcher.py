"""Safe code patching and rollback engine for the TRACE Agent Harness."""

import difflib
import shutil
import time
from pathlib import Path
from typing import Optional, Tuple
from trace_engine.harness.context import PatchResult


class SafePatcher:
    """Manages transactional file edits, backups, and rollback for AI coding agents."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.backup_dir = self.workspace_root / ".trace" / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_within_workspace(self, rel_path: str) -> Path:
        """Resolve a relative path, refusing escapes outside the workspace."""
        candidate = (self.workspace_root / rel_path).resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError:
            raise ValueError(f"Refusing path outside workspace: {rel_path}")
        return candidate

    def backup(self, rel_path: str) -> Path:
        """Create timestamped backup of the target file."""
        target = self._resolve_within_workspace(rel_path)
        if not target.exists():
            raise FileNotFoundError(f"Target file {rel_path} does not exist in workspace.")

        timestamp = int(time.time() * 1000)
        safe_name = rel_path.replace("/", "_").replace("\\", "_")
        backup_path = self.backup_dir / f"{safe_name}.{timestamp}.bak"
        shutil.copy2(target, backup_path)
        return backup_path

    def apply_replacement(
        self,
        finding_id: str,
        rel_path: str,
        target_content: str,
        replacement_content: str,
    ) -> PatchResult:
        """Replace target string block with replacement content, creating a rollback backup."""
        try:
            file_path = self._resolve_within_workspace(rel_path)
        except ValueError as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=str(e),
            )
        if not file_path.exists():
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=f"File not found: {rel_path}",
            )

        try:
            original = file_path.read_text(encoding="utf-8")
            if target_content not in original:
                return PatchResult(
                    finding_id=finding_id,
                    target_file=rel_path,
                    success=False,
                    error="Target content block not found in file.",
                )

            backup_file = self.backup(rel_path)
            new_content = original.replace(target_content, replacement_content, 1)
            file_path.write_text(new_content, encoding="utf-8")

            # Generate unified diff
            diff_lines = list(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                )
            )
            diff_str = "".join(diff_lines)

            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=True,
                backup_file=str(backup_file),
                diff=diff_str,
            )
        except Exception as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=str(e),
            )

    def apply_full_content(
        self,
        finding_id: str,
        rel_path: str,
        new_content: str,
    ) -> PatchResult:
        """Write entire new file content, creating a rollback backup."""
        try:
            file_path = self._resolve_within_workspace(rel_path)
        except ValueError as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=str(e),
            )
        if not file_path.exists():
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=f"File not found: {rel_path}",
            )

        try:
            original = file_path.read_text(encoding="utf-8")
            backup_file = self.backup(rel_path)
            file_path.write_text(new_content, encoding="utf-8")

            diff_lines = list(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                )
            )
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=True,
                backup_file=str(backup_file),
                diff="".join(diff_lines),
            )
        except Exception as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=str(e),
            )

    def rollback(self, rel_path: str, backup_path: Path) -> bool:
        """Restore file from backup (both paths must stay in the workspace)."""
        try:
            target = self._resolve_within_workspace(rel_path)
            backup_resolved = Path(backup_path).resolve()
            backup_resolved.relative_to(self.backup_dir)
        except (ValueError, OSError):
            return False
        if backup_resolved.exists():
            shutil.copy2(backup_resolved, target)
            return True
        return False


TransactionalPatcher = SafePatcher
PatchOperationResult = PatchResult

