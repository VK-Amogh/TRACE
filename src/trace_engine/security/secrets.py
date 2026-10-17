"""Hardcoded secret detection (opt-in: ``--secrets``).

Pattern rules for well-known credential formats plus an entropy-gated generic
rule for ``password = "..."`` style assignments. Secret values are never
stored: evidence shows a short prefix and the length, and the finding is
identified by a truncated hash so line moves do not create "new" findings.
"""

import hashlib
import math
import re
from pathlib import Path
from typing import Callable, List, Optional, Pattern, Tuple

from trace_engine.findings.factory import make_finding
from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.ingest.textfiles import iter_text_files

MAX_FINDINGS = 200
MAX_PER_FILE = 20

_TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb", ".php", ".cs",
    ".rs", ".dart", ".swift", ".sh", ".bash", ".zsh", ".ps1", ".env", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".tf", ".tfvars", ".gradle", ".txt", ".pem", ".key",
}
_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "composer.lock", "Pipfile.lock", "go.sum"}
_PLACEHOLDER_HINTS = (
    "changeme", "change_me", "example", "your_", "your-", "yourapi", "xxxx", "<", ">", "${", "{{", "placeholder",
    "dummy", "sample", "todo", "fixme", "here", "****", "....", "process.env", "os.environ", "getenv",
    "secret_key", "insert", "replace", "redacted", "not-a-real", "notreal", "fake", "test1234", "password123",
)


class Rule:
    def __init__(self, name: str, rx: str, severity: Severity, confidence: FindingConfidence, group: int = 0,
                 min_entropy: Optional[float] = None):
        self.name = name
        self.rx: Pattern[str] = re.compile(rx)
        self.severity = severity
        self.confidence = confidence
        self.group = group
        self.min_entropy = min_entropy


RULES: List[Rule] = [
    Rule("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Severity.HIGH, FindingConfidence.HIGH),
    Rule("AWS secret access key", r"(?i)aws.{0,30}(?:secret|sk).{0,12}[=:]\s*[\"']([A-Za-z0-9/+=]{40})[\"']",
         Severity.HIGH, FindingConfidence.HIGH, group=1),
    Rule("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Severity.HIGH, FindingConfidence.HIGH),
    Rule("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", Severity.HIGH, FindingConfidence.HIGH),
    Rule("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", Severity.HIGH, FindingConfidence.HIGH),
    Rule("Stripe live key", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b", Severity.CRITICAL, FindingConfidence.HIGH),
    Rule("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", Severity.HIGH, FindingConfidence.HIGH),
    Rule("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
         Severity.CRITICAL, FindingConfidence.HIGH),
    Rule("Database URL with password",
         r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@\"']+:([^\s@/\"']{4,})@",
         Severity.HIGH, FindingConfidence.HIGH, group=1),
    Rule("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
         Severity.MEDIUM, FindingConfidence.MEDIUM),
    Rule("Hardcoded credential assignment",
         r"(?i)\b[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"
         r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']",
         Severity.MEDIUM, FindingConfidence.MEDIUM, group=1, min_entropy=3.0),
]


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in _PLACEHOLDER_HINTS) or len(set(value)) <= 3


def _accept(name: str) -> bool:
    if name in _LOCKFILES or name.endswith((".min.js", ".lock")):
        return False
    low = name.lower()
    return (
        low == ".env" or low.startswith(".env.") or low in {"dockerfile", "credentials", "config"}
        or Path(low).suffix in _TEXT_SUFFIXES
    )


def scan_text(rel: str, text: str) -> List[Tuple[Rule, int, str]]:
    """``(rule, line_number, matched_value)`` for each secret in ``text``."""
    hits: List[Tuple[Rule, int, str]] = []
    seen = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:
            continue
        for rule in RULES:
            for m in rule.rx.finditer(line):
                value = m.group(rule.group) if rule.group else m.group(0)
                if rule.name == "Private key block":
                    value = line.strip()
                if rule.min_entropy is not None and (entropy(value) < rule.min_entropy or is_placeholder(value)):
                    continue
                if rule.group and rule.name != "Hardcoded credential assignment" and is_placeholder(value):
                    continue
                key = (rule.name, hashlib.sha256(value.encode("utf-8")).hexdigest())
                if key in seen:
                    continue
                seen.add(key)
                hits.append((rule, lineno, value))
    return hits


def scan_secrets(repo: Path, redact: Callable[[str], str] = None) -> Tuple[List[Finding], List[str]]:
    """Scan ``repo`` for hardcoded secrets. Returns ``(findings, notes)``."""
    findings: List[Finding] = []
    notes: List[str] = []
    for rel, _path, text in iter_text_files(repo, _accept):
        count = 0
        for rule, line, value in scan_text(rel, text):
            if len(findings) >= MAX_FINDINGS:
                notes.append(f"secrets: stopped after {MAX_FINDINGS} findings; narrow the scan or rotate and rescan")
                return findings, notes
            if count >= MAX_PER_FILE:
                notes.append(f"secrets: {rel} has more than {MAX_PER_FILE} hits; remaining ones skipped")
                break
            count += 1
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:6]
            preview = f"{value[:4]}... ({len(value)} chars)"
            findings.append(
                make_finding(
                    finding_id=f"TR-SEC-{len(findings) + 1:03d}",
                    category="SECRETS",
                    title=f"Hardcoded secret: {rule.name}",
                    endpoint=f"{rel}#{digest}",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence=[
                        f"{rule.name} at {rel}:{line}",
                        f"Value begins with '{preview}'; the full value is intentionally not stored or printed",
                        f"Entropy {entropy(value):.1f} bits/char",
                    ],
                    file=rel,
                    line=line,
                    notes="Detected by pattern and entropy analysis of repository files; rotate the credential.",
                )
            )
    return findings, notes
