"""File representation and language detection."""

from pathlib import Path
from typing import Optional
from pydantic import BaseModel


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".dart": "dart",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".java": "java",
    ".go": "go",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c_cpp",
    ".cpp": "c_cpp",
    ".cc": "c_cpp",
    ".cxx": "c_cpp",
    ".h": "c_cpp",
    ".hpp": "c_cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".sql": "sql",
}


class SourceFile(BaseModel):
    """Represents an ingested source code file."""
    path: str
    absolute_path: str
    language: str
    size_bytes: int
    line_count: int
    sha256: str


def detect_language(path: Path) -> Optional[str]:
    """Detect language based on extension and filename."""
    suffix = path.suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(suffix)
