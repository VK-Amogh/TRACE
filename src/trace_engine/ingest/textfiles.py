"""Walk text files for opt-in analyzers (secrets, dependencies, IaC).

The default scan reads only analyzable source languages. These analyzers need
configuration and manifest files too, so they use this separate, explicit walk
(honoring the same ignore rules, size cap and binary detection).
"""

import os
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

from trace_engine.ingest.ignore import IgnoreFilter

MAX_BYTES = 1_000_000


def iter_text_files(
    repo: Path,
    accept: Callable[[str], bool],
    *,
    exclude_patterns: Optional[list] = None,
) -> Iterator[Tuple[str, Path, str]]:
    """Yield ``(relative_posix_path, absolute_path, text)`` for accepted files."""
    root = Path(repo).resolve()
    ignore = IgnoreFilter(root, custom_patterns=exclude_patterns)
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not ignore.should_ignore(base / d, is_dir=True)]
        for name in filenames:
            if not accept(name):
                continue
            path = base / name
            if ignore.should_ignore(path, is_dir=False):
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:1024]:
                continue
            rel = path.relative_to(root).as_posix()
            yield rel, path, raw.decode("utf-8", errors="replace")
