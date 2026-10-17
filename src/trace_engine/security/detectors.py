"""Additional static detectors (opt-in: ``--detectors``).

Weak JWT handling, disabled TLS verification, debug flags and GraphQL
exposure from source patterns, plus open redirects from the taint analyzer.
Findings carry the exact line and a one-line fix.
"""

import os
import re
from typing import Dict, List, Tuple

from trace_engine.findings.factory import make_finding
from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.framework.base import Endpoint
from trace_engine.ingest.files import SourceFile
from trace_engine.security.hypotheses import HypothesisEngine

# (category, title, regex, severity, confidence, evidence, only_files_matching)
_RULES: List[Tuple[str, str, "re.Pattern[str]", Severity, FindingConfidence, str, str]] = [
    ("JWT", "JWT signature verification disabled",
     re.compile(r"verify_signature[\"']?\s*[:=]\s*False|jwt\.decode\([^)]*verify\s*=\s*False"),
     Severity.HIGH, FindingConfidence.HIGH, "Tokens are accepted without checking the signature; verify and pin the algorithm", ""),
    ("JWT", "JWT accepts the 'none' algorithm",
     re.compile(r"algorithms?\s*[:=]\s*\[\s*[\"']none[\"']", re.I),
     Severity.CRITICAL, FindingConfidence.HIGH, "Attackers can forge tokens; list only strong algorithms", ""),
    ("JWT", "JWT signed with a short literal secret",
     re.compile(r"jwt\.(?:sign|encode)\([^,]+,\s*[\"']([^\"']{1,24})[\"']"),
     Severity.HIGH, FindingConfidence.MEDIUM, "A short hardcoded secret is guessable; use a long random key from the environment", ""),
    ("MISCONFIG", "TLS certificate verification disabled",
     re.compile(r"(?:requests|httpx|session|client)\.\w+\([^)]*verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
                r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|ssl\._create_unverified_context|InsecureSkipVerify\s*:\s*true|"
                r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)"),
     Severity.MEDIUM, FindingConfidence.HIGH, "Outbound TLS is not verified, enabling interception; keep verification on", ""),
    ("MISCONFIG", "Debug mode enabled",
     re.compile(r"app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|FLASK_DEBUG\s*=\s*[\"']?1"),
     Severity.MEDIUM, FindingConfidence.MEDIUM, "Debug mode exposes interactive consoles and stack traces; disable it in production", ""),
    ("MISCONFIG", "GraphQL introspection or playground enabled",
     re.compile(r"introspection\s*[:=]\s*(?:true|True)|playground\s*:\s*true|graphiql\s*[:=]\s*(?:true|True)"),
     Severity.LOW, FindingConfidence.MEDIUM, "Schema discovery tools are reachable; disable them in production", ""),
]


def scan_detectors(
    source_files: List[SourceFile], endpoints: List[Endpoint]
) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    seen = set()
    texts: Dict[str, str] = {}
    for sf in source_files:
        try:
            with open(sf.absolute_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        texts[sf.absolute_path] = text
        for category, title, rx, severity, confidence, evidence, _ in _RULES:
            for lineno, line in enumerate(text.splitlines(), start=1):
                if len(line) > 1000 or not rx.search(line):
                    continue
                key = (sf.path, title)
                if key in seen:
                    break
                seen.add(key)
                findings.append(
                    make_finding(
                        finding_id=f"TR-DET-{len(findings) + 1:03d}",
                        category=category,
                        title=title,
                        endpoint=sf.path,
                        severity=severity,
                        confidence=confidence,
                        evidence=[f"{sf.path}:{lineno}: {evidence}"],
                        file=sf.path,
                        line=lineno,
                        notes="Detected by a static source pattern.",
                    )
                )
                break

    # Open redirects: request data flowing into a redirect call (taint analyzer).
    cache: Dict[str, list] = {}
    for ep in endpoints:
        if not ep.registered or not ep.source or not ep.source.file:
            continue
        src = texts.get(ep.source.file)
        if src is None:
            try:
                with open(ep.source.file, "r", encoding="utf-8", errors="replace") as f:
                    src = texts[ep.source.file] = f.read()
            except OSError:
                continue
        for flow in HypothesisEngine._flows_for(ep, src, cache):
            if flow.kind != "redirect":
                continue
            key = (ep.display_name(), "redirect")
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                make_finding(
                    finding_id=f"TR-DET-{len(findings) + 1:03d}",
                    category="OPEN_REDIRECT",
                    title="Open redirect",
                    endpoint=ep.display_name(),
                    severity=Severity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    evidence=[
                        f"{flow.source} (line {flow.source_line}) flows into {flow.sink} (line {flow.sink_line}) "
                        f"without an allow-list"
                    ],
                    file=ep.source.file,
                    line=flow.sink_line,
                    notes="Detected by taint analysis of the handler.",
                )
            )
    return findings, []
