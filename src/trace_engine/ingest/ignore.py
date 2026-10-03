"""Ignore pattern matching for repository ingestion."""

from pathlib import Path
from typing import List, Set
import fnmatch


DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    ".trace",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".next",
    ".nuxt",
    "target",
    "vendor",
    ".idea",
    ".vscode",
}

DEFAULT_IGNORE_PATTERNS: List[str] = [
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    "*.log",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.svg",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.zip",
    "*.tar.gz",
    "*.exe",
    "*.bin",
]


class IgnoreFilter:
    """Filters files based on default ignore sets and custom .traceignore rules."""

    def __init__(self, repo_root: Path, custom_patterns: List[str] = None):
        self.repo_root = repo_root.resolve()
        self.patterns = list(DEFAULT_IGNORE_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self._load_traceignore()

    def _load_traceignore(self) -> None:
        traceignore = self.repo_root / ".traceignore"
        if traceignore.exists():
            try:
                for line in traceignore.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line.rstrip("/"))
            except Exception:
                pass

    def should_ignore(self, path: Path) -> bool:
        """Return True if path should be ignored."""
        try:
            rel = path.relative_to(self.repo_root)
        except ValueError:
            rel = path

        parts = rel.parts
        # Check directory names
        for part in parts[:-1]:
            if part in DEFAULT_IGNORE_DIRS:
                return True

        if path.is_dir() and path.name in DEFAULT_IGNORE_DIRS:
            return True

        # Check glob patterns
        filename = path.name
        rel_str = str(rel).replace("\\", "/")
        
        for pat in self.patterns:
            clean_pat = pat.replace("\\", "/").rstrip("/")
            if fnmatch.fnmatch(filename, clean_pat) or fnmatch.fnmatch(rel_str, clean_pat):
                return True
            if any(fnmatch.fnmatch(part, clean_pat) for part in parts):
                return True

        return False
