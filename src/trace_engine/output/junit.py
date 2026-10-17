"""JUnit XML report: one test case per finding, failures for gating findings."""

from typing import Iterable, List, Optional
from xml.sax.saxutils import escape, quoteattr

from trace_engine.findings.model import Finding


def generate_junit_report(
    findings: List[Finding],
    *,
    project_name: str = "application",
    blocking: Optional[Iterable[Finding]] = None,
) -> str:
    """Render findings as JUnit XML.

    Findings in ``blocking`` (default: all) are ``<failure>`` elements; the
    rest are passing cases tagged with their severity in ``system-out``.
    """
    block_fps = {f.fingerprint for f in (findings if blocking is None else blocking)}
    failures = sum(1 for f in findings if f.fingerprint in block_fps)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="TRACE" tests="{len(findings)}" failures="{failures}">',
        f'  <testsuite name={quoteattr("trace." + project_name)} tests="{len(findings)}" failures="{failures}">',
    ]
    for f in findings:
        name = f"{f.id} {f.title}"
        lines.append(f"    <testcase classname={quoteattr(f.category)} name={quoteattr(name)}>")
        detail = (
            f"{f.severity.value}/{f.confidence.value} at {f.endpoint}"
            f" ({f.source_location})" if f.source_location else
            f"{f.severity.value}/{f.confidence.value} at {f.endpoint}"
        )
        if f.fingerprint in block_fps:
            body = escape(
                f"{detail}\nfingerprint: {f.fingerprint}\ncwe: {f.cwe or '-'}\n"
                f"remediation: {f.short_action or f.remediation}"
            )
            lines.append(
                f"      <failure type={quoteattr(f.severity.value)} message={quoteattr(f.title)}>{body}</failure>"
            )
        else:
            lines.append(f"      <system-out>{escape(detail)}</system-out>")
        lines.append("    </testcase>")
    lines.extend(["  </testsuite>", "</testsuites>", ""])
    return "\n".join(lines)
