"""Output and rendering module."""

from trace_engine.output.terminal import (
    print_banner,
    print_security_notes,
    print_endpoints_table,
    print_hypotheses_table,
    print_findings_table,
    print_finding_detail,
    print_doctor_report,
)
from trace_engine.output.markdown import generate_markdown_report
from trace_engine.output.html import generate_html_report

__all__ = [
    "print_banner",
    "print_security_notes",
    "print_endpoints_table",
    "print_hypotheses_table",
    "print_findings_table",
    "print_finding_detail",
    "print_doctor_report",
    "generate_markdown_report",
    "generate_html_report",
]
