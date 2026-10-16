"""Safe code patching and rollback engine for the TRACE Agent Harness."""

import difflib
import re
import shutil
import time
from pathlib import Path, PureWindowsPath
from typing import Optional, Tuple
from trace_engine.harness.context import PatchResult


class WorkspaceBoundaryError(ValueError):
    """Raised when a patch path escapes the workspace root."""


_ABSOLUTE_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC_PREFIXES = ("\\\\", "//")


def _looks_like_absolute_or_unc(rel_path: str) -> bool:
    """Detect absolute/UNC/drive-letter shapes on any platform.

    Windows-only ``Path.is_absolute()`` is insufficient when a Windows-style
    path is evaluated on POSIX (and vice versa), so check PureWindowsPath
    semantics explicitly plus UNC prefixes in either separator style.
    """
    if not rel_path:
        return True
    if "\x00" in rel_path:
        return True
    text = rel_path.replace("/", "\\")
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        return True
    if text.startswith("\\\\"):
        return True
    if _ABSOLUTE_WIN_DRIVE.match(rel_path):
        return True
    try:
        if PureWindowsPath(rel_path).is_absolute():
            return True
    except Exception:
        return True
    try:
        if Path(rel_path).is_absolute():
            return True
    except Exception:
        return True
    return False


class SafePatcher:
    """Manages transactional file edits, backups, and rollback for AI coding agents."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.backup_dir = self.workspace_root / ".trace" / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_contained(self, rel_path: str) -> Path:
        """Resolve *rel_path* strictly inside the workspace root.

        Rejects absolute paths, Windows drive-letter paths, UNC paths,
        null bytes, ``..`` escapes, and symlinks/junctions that resolve
        outside the workspace. Returns the resolved absolute target so
        callers operate on the validated destination (no reconstruction).
        """
        if not isinstance(rel_path, str) or not rel_path:
            raise WorkspaceBoundaryError("Empty patch path is not allowed.")
        if _looks_like_absolute_or_unc(rel_path):
            raise WorkspaceBoundaryError(
                f"Absolute path is not allowed in workspace: {rel_path!r}"
            )
        candidate = self.workspace_root / rel_path
        try:
            resolved = candidate.resolve()
        except Exception as e:
            raise WorkspaceBoundaryError(f"Unresolvable patch path {rel_path!r}: {e}")
        try:
            contained = resolved.is_relative_to(self.workspace_root)
        except Exception:
            contained = False
        if not contained:
            raise WorkspaceBoundaryError(
                f"Path escapes workspace root: {rel_path!r}"
            )
        return resolved

    def _resolve_backup_file(self, backup_path: Path) -> Path:
        """Resolve a rollback source strictly inside this patcher's backup dir."""
        try:
            resolved = Path(backup_path).resolve()
        except Exception as e:
            raise WorkspaceBoundaryError(f"Unresolvable backup path: {e}")
        try:
            contained = resolved.is_relative_to(self.backup_dir.resolve())
        except Exception:
            contained = False
        if not contained:
            raise WorkspaceBoundaryError(
                "Backup file is outside the workspace backup directory."
            )
        return resolved

    def backup(self, rel_path: str) -> Path:
        """Create timestamped backup of the target file."""
        target = self._resolve_contained(rel_path)
        if not target.exists() or not target.is_file():
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
            file_path = self._resolve_contained(rel_path)
        except WorkspaceBoundaryError as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=f"Workspace boundary violation: {e}",
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
            file_path = self._resolve_contained(rel_path)
        except WorkspaceBoundaryError as e:
            return PatchResult(
                finding_id=finding_id,
                target_file=rel_path,
                success=False,
                error=f"Workspace boundary violation: {e}",
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
        """Restore file from backup."""
        try:
            target = self._resolve_contained(rel_path)
            source = self._resolve_backup_file(backup_path)
        except WorkspaceBoundaryError:
            return False
        if source.exists() and source.is_file():
            shutil.copy2(source, target)
            return True
        return False


TransactionalPatcher = SafePatcher
PatchOperationResult = PatchResult

