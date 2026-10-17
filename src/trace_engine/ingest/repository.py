"""Repository scanner and ingestion manager."""

import hashlib
import os
from collections import Counter
from pathlib import Path
from typing import Collection, List, Dict, Optional
from trace_engine.ingest.ignore import IgnoreFilter
from trace_engine.ingest.files import (
    ANALYZED_LANGUAGES,
    SourceFile,
    detect_language_by_name,
)


class RepositoryScanner:
    """Discovers and catalogs source code files across a project directory.

    Only languages that a parser or adapter can use are ingested
    (``ANALYZED_LANGUAGES``). Markup, styles, data/config files and similar
    formats are skipped before they are opened, so they cost no I/O, hashing
    or graph nodes. Pass ``languages`` to widen or narrow the set.
    """

    def __init__(
        self,
        repo_path: Path,
        exclude_patterns: List[str] = None,
        languages: Optional[Collection[str]] = None,
    ):
        self.repo_path = repo_path.resolve()
        self.ignore_filter = IgnoreFilter(self.repo_path, custom_patterns=exclude_patterns)
        self.languages = frozenset(languages) if languages is not None else ANALYZED_LANGUAGES
        #: Known-but-not-analyzed files skipped by the last scan, keyed by language.
        self.skipped_by_language: Counter = Counter()

    def scan(self) -> List[SourceFile]:
        """Scans the repository and returns discovered source files."""
        source_files: List[SourceFile] = []
        self.skipped_by_language = Counter()
        if not self.repo_path.exists():
            return source_files

        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            root = Path(dirpath)
            # Prune ignored directories up front instead of stat-ing and
            # matching every file inside them (vendored/dataset trees can
            # hold hundreds of thousands of files).
            dirnames[:] = [
                d for d in dirnames
                if not self.ignore_filter.should_ignore(root / d, is_dir=True)
            ]
            for filename in filenames:
                lang = detect_language_by_name(filename)
                if lang is None or lang == "unknown":
                    continue
                if lang not in self.languages:
                    self.skipped_by_language[lang] += 1
                    continue
                item = root / filename
                if self.ignore_filter.should_ignore(item, is_dir=False):
                    continue
                try:
                    stat = item.stat()
                    # Avoid huge files (> 2MB)
                    if stat.st_size > 2 * 1024 * 1024:
                        continue

                    raw = item.read_bytes()
                    content = raw.decode("utf-8", errors="replace")
                    line_count = len(content.splitlines())
                    rel_path = str(item.relative_to(self.repo_path)).replace("\\", "/")

                    source_files.append(
                        SourceFile(
                            path=rel_path,
                            absolute_path=str(item.resolve()),
                            language=lang,
                            size_bytes=stat.st_size,
                            line_count=line_count,
                            sha256=hashlib.sha256(raw).hexdigest(),
                        )
                    )
                except Exception:
                    continue

        return sorted(source_files, key=lambda f: f.path)
