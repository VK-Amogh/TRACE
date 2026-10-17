"""Explicit scan-scope policy: separate application code from fixtures.

Lives in ``ingest`` (not top-level) to avoid confusion with the network
target :class:`~trace_engine.policy.scope.ScopeGuard`.

Profiles (explicit user choice; nothing is hidden silently):

- ``full`` (default): scan everything the ingestion filter accepts. This
  reproduces the original repository-wide scan byte-for-byte.
- ``app``: exclude common fixture/test directory patterns so a self-scan
  reports TRACE's own implementation rather than bundled vulnerable sample
  apps and benchmark fixtures. Excluded top-level directories and the
  reason for each are always reported.
- ``fixtures``: scan ONLY fixture/test directories, for reproducing
  benchmark detections separately.

The patterns are generic directory names (not TRACE-specific paths), so the
same profiles work for any repository. Users who want test code analyzed
pick ``full`` or ``fixtures``; users with custom layouts extend
``.traceignore`` (honored in every profile) or pass extra patterns.
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


#: Generic fixture/test directory patterns (matched against each path part).
FIXTURE_DIR_PATTERNS: List[str] = [
    "labs",
    "test",
    "tests",
    "testing",
    "test_*",
    "testing_*",
    "*_test",
    "*_tests",
    "fixtures",
    "fixture",
    "benchmarks",
    "benchmark",
    "e2e",
    "examples",
    "example",
    "__tests__",
    "testbed*",
    "test-*",
    "*-test",
]

VALID_PROFILES = ("full", "app", "fixtures")


@dataclass
class ScanScopeResult:
    """Resolved scope for one scan run."""

    profile: str
    exclude_patterns: List[str] = field(default_factory=list)
    only_top_dirs: Optional[List[str]] = None
    included_top_dirs: List[str] = field(default_factory=list)
    excluded_top_dirs: Dict[str, str] = field(default_factory=dict)
    note: str = ""

    def summary_lines(self) -> List[str]:
        lines = [f"Scan scope profile: {self.profile}"]
        if self.note:
            lines.append(self.note)
        if self.excluded_top_dirs:
            lines.append("Excluded directories (fixture/test scope):")
            for d, reason in sorted(self.excluded_top_dirs.items()):
                lines.append(f"  - {d}/ ({reason})")
        else:
            lines.append("Excluded directories: none (full repository scan)")
        if self.included_top_dirs:
            lines.append(f"Included top-level entries: {len(self.included_top_dirs)}")
        return lines

    def to_dict(self) -> Dict[str, object]:
        return {
            "profile": self.profile,
            "included_top_dirs": self.included_top_dirs,
            "excluded_top_dirs": self.excluded_top_dirs,
            "note": self.note,
        }


def _matches_any(name: str, patterns: List[str]) -> bool:
    lowered = name.lower()
    return any(fnmatch.fnmatch(lowered, pat.lower()) for pat in patterns)


def scoped_scanner(repo_path: Path, scope: str = "full"):
    """Build a scope-configured ``RepositoryScanner`` plus its scope result.

    Import is deferred so ``scan_scope`` stays dependency-light. The
    ``fixtures`` profile filters per file (any depth), so nested fixture
    trees are included while application code is excluded.
    """
    from trace_engine.ingest.repository import RepositoryScanner

    result = resolve_scope(repo_path, scope)
    scanner = RepositoryScanner(
        repo_path,
        exclude_patterns=result.exclude_patterns or None,
    )
    if scope == "fixtures" and result.only_top_dirs:
        base_scan = scanner.scan

        def _fixtures_only():
            return [sf for sf in base_scan() if is_fixture_path(sf.path)]

        scanner.scan = _fixtures_only  # type: ignore[method-assign]
    return scanner, result


def print_scope_summary(console, scope_result: ScanScopeResult) -> None:
    """Render the scope summary (included/excluded + reasons) to a console."""
    for line in scope_result.summary_lines():
        console.print(f"  [dim]{line}[/dim]")


def resolve_scope(repo_path: Path, profile: str = "full") -> ScanScopeResult:
    """Resolve *profile* against *repo_path* without scanning file contents."""
    if profile not in VALID_PROFILES:
        raise ValueError(f"Unknown scan scope profile: {profile!r}. Choose from {VALID_PROFILES}.")

    repo = repo_path.resolve()
    top_dirs: List[str] = []
    if repo.exists():
        top_dirs = sorted(p.name for p in repo.iterdir() if p.is_dir() and not p.name.startswith("."))
    fixture_top = [d for d in top_dirs if _matches_any(d, FIXTURE_DIR_PATTERNS)]

    if profile == "full":
        return ScanScopeResult(
            profile="full",
            included_top_dirs=top_dirs,
        )
    if profile == "app":
        excluded = {d: "fixture/test directory pattern" for d in fixture_top}
        return ScanScopeResult(
            profile="app",
            exclude_patterns=list(FIXTURE_DIR_PATTERNS),
            included_top_dirs=[d for d in top_dirs if d not in excluded],
            excluded_top_dirs=excluded,
        )
    # fixtures-only. If the target itself has no fixture-named top-level
    # directories (e.g. scanning a benchmark fixture repo directly), the
    # whole target is treated as the fixture set instead of returning a
    # misleading empty scan.
    if not fixture_top:
        return ScanScopeResult(
            profile="fixtures",
            included_top_dirs=top_dirs,
            note="Target has no fixture-named directories; fixtures profile scans the whole target.",
        )
    return ScanScopeResult(
        profile="fixtures",
        only_top_dirs=fixture_top,
        included_top_dirs=fixture_top,
        excluded_top_dirs={d: "non-fixture directory (fixtures-only profile)" for d in top_dirs if d not in fixture_top},
    )


def is_fixture_path(file_path: str) -> bool:
    """Return True if any path segment matches fixture/test directory patterns."""
    if not file_path:
        return False
    parts = Path(file_path).parts
    for part in parts:
        lowered = part.lower()
        if any(fnmatch.fnmatch(lowered, pat.lower()) for pat in FIXTURE_DIR_PATTERNS):
            return True
    return False


def get_path_provenance(file_path: str) -> str:
    """Classify file provenance as 'fixture/test' or 'application'."""
    return "fixture/test" if is_fixture_path(file_path) else "application"

