"""Repository scanner and ingestion manager."""

from pathlib import Path
from typing import List, Dict, Optional
from trace_engine.ingest.ignore import IgnoreFilter
from trace_engine.ingest.files import SourceFile, detect_language
from trace_engine.ingest.hashing import hash_file


class RepositoryScanner:
    """Discovers and catalogs source code files across a project directory."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()
        self.ignore_filter = IgnoreFilter(self.repo_path)

    def scan(self) -> List[SourceFile]:
        """Scans the repository and returns discovered source files."""
        source_files: List[SourceFile] = []
        if not self.repo_path.exists():
            return source_files

        for item in self.repo_path.rglob("*"):
            if item.is_file() and not self.ignore_filter.should_ignore(item):
                lang = detect_language(item)
                if lang in ("python", "javascript", "typescript", "go"):
                    try:
                        stat = item.stat()
                        # Avoid huge files (> 2MB)
                        if stat.st_size > 2 * 1024 * 1024:
                            continue

                        content = item.read_text(encoding="utf-8", errors="replace")
                        line_count = len(content.splitlines())
                        rel_path = str(item.relative_to(self.repo_path)).replace("\\", "/")

                        source_files.append(
                            SourceFile(
                                path=rel_path,
                                absolute_path=str(item.resolve()),
                                language=lang,
                                size_bytes=stat.st_size,
                                line_count=line_count,
                                sha256=hash_file(item),
                            )
                        )
                    except Exception:
                        continue

        return sorted(source_files, key=lambda f: f.path)
