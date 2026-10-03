"""Hashing utilities for TRACE repository ingestion."""

import hashlib
from pathlib import Path


def hash_file(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""


def hash_content(content: str) -> str:
    """Compute SHA-256 hash of text content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
