"""Standalone dark-themed HTML report generator with green accents."""

import html
from typing import List
from trace_engine.findings.model import Finding


def generate_html_report(findings: List[Finding], project_name: str = "Application") -> str:
    cards = []
    for f in findings:
        sev_color = {
            "CRITICAL": "#ff4d4d",
            "HIGH": "#ff7733",
            "MEDIUM": "#ffcc00",
            "LOW": "#33ccff",
        }.get(f.severity.value, "#888888")

        cards.append(f"""
        <div class="card">
            <div class="card-header">
                <span class="finding-id">{html.escape(f.id)}</span>
                <span class="badge" style="background: {sev_color}; color: #000;">{f.severity.value}</span>
                <span class="badge badge-conf">{f.confidence.value}</span>
                <span class="category">{html.escape(f.category)}</span>
            </div>
            <h3 class="card-title">{html.escape(f.title)}</h3>
            <p class="endpoint"><code>{html.escape(f.endpoint)}</code></p>
            <div class="section-title">Static Code Evidence</div>
            <ul>{"".join(f"<li>{html.escape(e)}</li>" for e in f.static_evidence)}</ul>
            <div class="section-title">Runtime Behavioral Evidence</div>
            <ul>{"".join(f"<li>{html.escape(e)}</li>" for e in f.runtime_evidence)}</ul>
            <div class="section-title">Remediation</div>
            <p class="remediation">{html.escape(f.remediation)}</p>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TRACE Report — {html.escape(project_name)}</title>
    <style>
        body {{
            background-color: #0c0d0e;
            color: #e6edf3;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            margin: 0;
            padding: 30px;
        }}
        .header {{
            border-bottom: 1px solid #21262d;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #00FF66;
            margin: 0 0 8px 0;
            font-size: 28px;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            color: #8b949e;
            font-size: 14px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .card-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }}
        .finding-id {{
            font-family: monospace;
            font-weight: bold;
            color: #00FF66;
        }}
        .badge {{
            font-size: 11px;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-conf {{
            background: #00FF66;
            color: #000;
        }}
        .category {{
            color: #8b949e;
            font-size: 12px;
        }}
        .card-title {{
            margin: 0 0 10px 0;
            font-size: 18px;
        }}
        code {{
            background: #0d1117;
            padding: 4px 8px;
            border-radius: 4px;
            color: #00FF66;
        }}
        .section-title {{
            font-size: 12px;
            font-weight: bold;
            color: #8b949e;
            text-transform: uppercase;
            margin-top: 15px;
            margin-bottom: 5px;
        }}
        ul {{
            margin: 0 0 10px 0;
            padding-left: 20px;
            color: #c9d1d9;
            font-size: 14px;
        }}
        .remediation {{
            background: #0d1117;
            border-left: 3px solid #00FF66;
            padding: 10px 14px;
            font-size: 13px;
            color: #8b949e;
            margin: 5px 0 0 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TRACE Security Assessment</h1>
        <div class="subtitle">Threat Reconnaissance & Attack-path Correlation Engine • {html.escape(project_name)}</div>
    </div>
    <div class="findings-container">
        {"".join(cards) if cards else "<p>No correlated vulnerabilities detected.</p>"}
    </div>
</body>
</html>
"""
