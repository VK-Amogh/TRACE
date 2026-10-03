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

    def backup(self, rel_path: str) -> Path:
        """Create timestamped backup of the target file."""
        target = self.workspace_root / rel_path
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
        file_path = self.workspace_root / rel_path
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
        file_path = self.workspace_root / rel_path
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
        """Restore file from backup."""
        target = self.workspace_root / rel_path
        if backup_path.exists():
            shutil.copy2(backup_path, target)
            return True
        return False


TransactionalPatcher = SafePatcher
PatchOperationResult = PatchResult

