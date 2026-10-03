"""Repository ingestion and file management."""

from trace_engine.ingest.files import SourceFile, detect_language
from trace_engine.ingest.ignore import IgnoreFilter
from trace_engine.ingest.hashing import hash_file, hash_content
from trace_engine.ingest.repository import RepositoryScanner

__all__ = [
    "SourceFile",
    "detect_language",
    "IgnoreFilter",
    "hash_file",
    "hash_content",
    "RepositoryScanner",
]
