"""Ingest SARIF produced by other analyzers (Semgrep, CodeQL, ...).

External static results become TRACE findings anchored to the endpoint whose
handler contains the flagged line, so they sit in the same ranked list as
TRACE's own evidence. Results that duplicate an existing TRACE finding
(same category and endpoint) raise that finding's confidence instead of being
listed twice. TRACE never runs these tools; it only reads their output.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from trace_engine.findings.factory import make_finding
from trace_engine.findings.model import CONFIDENCE_ORDER, Finding, FindingConfidence, Severity
from trace_engine.framework.base import Endpoint

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.I)
_CWE_TO_CATEGORY = {
    "89": "INJECTION", "564": "INJECTION", "78": "INJECTION", "77": "INJECTION", "94": "INJECTION",
    "95": "INJECTION", "943": "INJECTION", "918": "SSRF", "22": "PATH_TRAVERSAL", "23": "PATH_TRAVERSAL",
    "36": "PATH_TRAVERSAL", "639": "BOLA", "285": "BFLA", "862": "BFLA", "863": "BFLA", "306": "AUTHENTICATION",
    "287": "AUTHENTICATION", "915": "MASS_ASSIGNMENT", "942": "CORS", "502": "DESERIALIZATION",
    "1336": "SSTI", "347": "JWT", "601": "OPEN_REDIRECT", "798": "SECRETS", "259": "SECRETS", "321": "SECRETS",
    "16": "MISCONFIG", "295": "MISCONFIG", "489": "MISCONFIG",
}
_LEVEL_TO_SEVERITY = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}
_HANDLER_SPAN = 80  # lines after a route registration treated as its handler body


class ExternalResult:
    def __init__(self, tool: str, rule: str, message: str, file: str, line: int, level: str, cwes: List[str]):
        self.tool, self.rule, self.message = tool, rule, message
        self.file, self.line, self.level, self.cwes = file, line, level, cwes


def load_sarif(path: Path) -> List[ExternalResult]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    out: List[ExternalResult] = []
    for run in doc.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = str(driver.get("name", "external"))
        rules = {r.get("id"): r for r in driver.get("rules", []) or [] if isinstance(r, dict)}
        for res in run.get("results", []) or []:
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = (locs[0].get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
            line = int(((phys.get("region") or {}).get("startLine")) or 1)
            rule_id = str(res.get("ruleId", "unknown"))
            rule = rules.get(rule_id, {})
            haystack = " ".join(
                [json.dumps(rule.get("properties", {})), json.dumps(rule.get("tags", [])), rule_id]
                + [json.dumps(r.get("properties", {})) for r in [res]]
            )
            cwes = sorted({m.group(1) for m in _CWE_RE.finditer(haystack)})
            out.append(
                ExternalResult(
                    tool=tool,
                    rule=rule_id,
                    message=str((res.get("message") or {}).get("text", ""))[:300],
                    file=uri.replace("\\", "/").removeprefix("file:///").removeprefix("./"),
                    line=line,
                    level=str(res.get("level", "warning")),
                    cwes=cwes,
                )
            )
    return out


def _endpoint_for(result: ExternalResult, endpoints: List[Endpoint]) -> Optional[Endpoint]:
    rfile = result.file.lower()
    best: Optional[Endpoint] = None
    for ep in endpoints:
        efile = (ep.source.file or "").replace("\\", "/").lower()
        if not efile or not (efile.endswith(rfile) or rfile.endswith(efile)):
            continue
        start = ep.source.line_start
        if start - 2 <= result.line <= start + _HANDLER_SPAN:
            if best is None or start > best.source.line_start:
                best = ep
    return best


def ingest_sarif(
    paths: List[Path], endpoints: List[Endpoint], existing: List[Finding]
) -> Tuple[List[Finding], List[str]]:
    """New findings from external results; boosts matching existing findings in place."""
    new: List[Finding] = []
    notes: List[str] = []
    index: Dict[Tuple[str, str], Finding] = {(f.category, f.endpoint): f for f in existing}
    for path in paths:
        try:
            results = load_sarif(path)
        except (ValueError, OSError) as e:
            notes.append(f"sarif-in: could not read {path}: {e}")
            continue
        for r in results:
            category = next((_CWE_TO_CATEGORY[c] for c in r.cwes if c in _CWE_TO_CATEGORY), "EXTERNAL")
            ep = _endpoint_for(r, endpoints)
            endpoint = ep.display_name() if ep else f"{r.file}"
            evidence = f"{r.tool} rule {r.rule}: {r.message}".strip()
            twin = index.get((category, endpoint))
            if twin is not None:
                if evidence not in twin.static_evidence:
                    twin.static_evidence.append(evidence)
                order = CONFIDENCE_ORDER.index(twin.confidence.value)
                if order < CONFIDENCE_ORDER.index("HIGH"):
                    twin.confidence = FindingConfidence.HIGH
                continue
            finding = make_finding(
                finding_id=f"TR-EXT-{len(new) + 1:03d}",
                category=category,
                title=f"{r.tool}: {r.rule}",
                endpoint=endpoint,
                severity=_LEVEL_TO_SEVERITY.get(r.level, Severity.MEDIUM),
                confidence=FindingConfidence.MEDIUM,
                evidence=[evidence] + ([f"CWE-{c}" for c in r.cwes[:3]]),
                file=ep.source.file if ep else r.file,
                line=r.line,
                notes=f"Reported by {r.tool} and ingested from SARIF; not independently verified by TRACE.",
            )
            new.append(finding)
            index[(category, endpoint)] = finding
    return new, notes
