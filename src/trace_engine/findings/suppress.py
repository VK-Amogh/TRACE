"""Finding suppression: a committed, reviewable allowlist of accepted risk.

``.trace-suppress.toml`` at the repository root::

    [[suppress]]
    fingerprint = "1a2b3c4d5e6f7a8b"      # from `trace findings` / JSON output
    reason = "accepted risk, tracked in JIRA-1234"
    owner = "platform-team"                # optional
    expires = "2026-12-31"                 # optional; not applied afterwards

    [[suppress]]
    category = "CORS"
    path = "examples/**"                   # glob over the finding's source file
    reason = "demo code, never deployed"

Every entry needs a ``reason`` and at least one selector (``fingerprint``,
``category``, ``path`` or ``endpoint``). Overly broad globs are rejected so a
suppression can never silently blind the scanner.
"""

import fnmatch
import re
import tomllib
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from trace_engine.findings.model import Finding

SUPPRESS_FILE = ".trace-suppress.toml"
_MATCH_ALL = {"*", "**", "**/*", "*/**", "/**", ""}


class SuppressionRule(BaseModel):
    fingerprint: Optional[str] = None
    category: Optional[str] = None
    path: Optional[str] = None
    endpoint: Optional[str] = None
    reason: str = ""
    owner: Optional[str] = None
    expires: Optional[date] = None


class SuppressionResult(BaseModel):
    active: List[Finding] = Field(default_factory=list)
    suppressed: List[Finding] = Field(default_factory=list)
    reasons: Dict[str, str] = Field(default_factory=dict)  # fingerprint -> reason
    warnings: List[str] = Field(default_factory=list)


def _glob_to_regex(pattern: str) -> "re.Pattern[str]":
    out, i = "", 0
    pat = pattern.replace("\\", "/")
    while i < len(pat):
        ch = pat[i]
        if pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pat.startswith("**", i):
            out += ".*"
            i += 2
        elif ch == "*":
            out += "[^/]*"
            i += 1
        elif ch == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(ch)
            i += 1
    return re.compile(out + r"\Z", re.IGNORECASE)


def _path_matches(pattern: str, file: str, root: Optional[Path]) -> bool:
    posix = (file or "").replace("\\", "/")
    candidates = [posix]
    if root is not None:
        try:
            candidates.append(Path(file).resolve().relative_to(root.resolve()).as_posix())
        except (ValueError, OSError):
            pass
    rx = _glob_to_regex(pattern)
    for cand in candidates:
        if rx.match(cand):
            return True
        # Allow a pattern anchored at any directory depth of an absolute path.
        parts = cand.split("/")
        for i in range(1, len(parts)):
            if rx.match("/".join(parts[i:])):
                return True
    return False


def load_rules(repo: Path) -> Tuple[List[SuppressionRule], List[str]]:
    """Read and validate the suppression file. Returns ``(rules, warnings)``."""
    path = Path(repo) / SUPPRESS_FILE
    if not path.is_file():
        return [], []
    warnings: List[str] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        return [], [f"{SUPPRESS_FILE}: unreadable ({e}); no suppressions applied"]
    rules: List[SuppressionRule] = []
    for i, raw in enumerate(data.get("suppress", []), start=1):
        try:
            rule = SuppressionRule(**raw)
        except Exception as e:  # noqa: BLE001 - report any bad entry, keep going
            warnings.append(f"{SUPPRESS_FILE} entry {i}: invalid ({e}); ignored")
            continue
        if not rule.reason.strip():
            warnings.append(f"{SUPPRESS_FILE} entry {i}: missing reason; ignored")
            continue
        if not (rule.fingerprint or rule.category or rule.path or rule.endpoint):
            warnings.append(f"{SUPPRESS_FILE} entry {i}: no selector; ignored")
            continue
        if rule.path and rule.path.strip() in _MATCH_ALL:
            warnings.append(f"{SUPPRESS_FILE} entry {i}: path matches everything; ignored")
            continue
        if rule.fingerprint and len(rule.fingerprint) < 8:
            warnings.append(f"{SUPPRESS_FILE} entry {i}: fingerprint prefix under 8 chars; ignored")
            continue
        rules.append(rule)
    return rules, warnings


def _matches(rule: SuppressionRule, f: Finding, root: Optional[Path]) -> bool:
    if rule.fingerprint and not f.fingerprint.startswith(rule.fingerprint.lower()):
        return False
    if rule.category and rule.category.upper() != f.category.upper():
        return False
    if rule.endpoint and not fnmatch.fnmatch(f.endpoint.lower(), rule.endpoint.lower()):
        return False
    if rule.path:
        file = f.source_location.file if f.source_location else ""
        if not file or not _path_matches(rule.path, file, root):
            return False
    return True


def apply_suppressions(
    findings: List[Finding],
    rules: List[SuppressionRule],
    *,
    today: Optional[date] = None,
    root: Optional[Path] = None,
) -> SuppressionResult:
    """Split findings into active and suppressed according to ``rules``."""
    today = today or date.today()
    result = SuppressionResult()
    live: List[SuppressionRule] = []
    for rule in rules:
        if rule.expires and rule.expires < today:
            result.warnings.append(
                f"suppression expired {rule.expires} ({rule.reason[:40]}); finding is active again"
            )
        else:
            live.append(rule)
    for f in findings:
        hit = next((r for r in live if _matches(r, f, root)), None)
        if hit:
            result.suppressed.append(f)
            result.reasons[f.fingerprint] = hit.reason
        else:
            result.active.append(f)
    return result
