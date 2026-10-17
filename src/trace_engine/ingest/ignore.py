"""Ignore pattern matching for repository ingestion."""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Set
import fnmatch


@lru_cache(maxsize=131072)
def _cached_fnmatch(name: str, pattern: str) -> bool:
    """Memoized ``fnmatch.fnmatch`` (pure function; path parts repeat heavily)."""
    return fnmatch.fnmatch(name, pattern)


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
    ".react-router",
    ".vercel",
    ".output",
    ".turbo",
    ".cache",
    "target",
    "vendor",
    ".idea",
    ".vscode",
    # Tool caches, package stores and VCS metadata: never application code.
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    ".eggs",
    ".gradle",
    ".dart_tool",
    ".svn",
    ".hg",
    "Pods",
    "bower_components",
    "site-packages",
    "__MACOSX",
}

DEFAULT_IGNORE_PATTERNS: List[str] = [
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.chunk.js",
    "*.d.ts",
    "*.egg-info",
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
        self._clean_patterns = [pat.replace("\\", "/").rstrip("/") for pat in self.patterns]

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

    def should_ignore(self, path: Path, is_dir: Optional[bool] = None) -> bool:
        """Return True if path should be ignored.

        ``is_dir`` lets callers that already know the entry type (e.g. the
        directory walk) skip a stat syscall per path; when omitted the type
        is detected with ``path.is_dir()``.
        """
        try:
            rel = path.relative_to(self.repo_root)
        except ValueError:
            rel = path

        parts = rel.parts
        # Check directory names
        for part in parts[:-1]:
            if part in DEFAULT_IGNORE_DIRS:
                return True

        if is_dir is None:
            is_dir = path.is_dir()
        if is_dir and path.name in DEFAULT_IGNORE_DIRS:
            return True

        # Check glob patterns
        filename = path.name
        rel_str = str(rel).replace("\\", "/")
        
        for clean_pat in self._clean_patterns:
            if _cached_fnmatch(filename, clean_pat) or _cached_fnmatch(rel_str, clean_pat):
                return True
            if any(_cached_fnmatch(part, clean_pat) for part in parts):
                return True

        return False
