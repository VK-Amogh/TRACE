"""OASIS SARIF v2.1.0 report generator for CI/CD pipelines (GitHub Code Scanning, GitLab, SonarQube)."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from trace_engine.findings.model import Finding, Severity, FindingConfidence


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map TRACE severity to SARIF result level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    else:
        return "note"


def _category_to_cwe(category: str) -> Optional[str]:
    """Map common TRACE categories to primary CWE IDs."""
    cat_lower = category.lower()
    if "sqli" in cat_lower or "sql injection" in cat_lower:
        return "CWE-89"
    elif "cmd_injection" in cat_lower or "command" in cat_lower:
        return "CWE-78"
    elif "bola" in cat_lower or "idor" in cat_lower:
        return "CWE-639"
    elif "bfla" in cat_lower or "privilege" in cat_lower:
        return "CWE-285"
    elif "ssrf" in cat_lower:
        return "CWE-918"
    elif "path_traversal" in cat_lower or "traversal" in cat_lower:
        return "CWE-22"
    elif "xss" in cat_lower:
        return "CWE-79"
    elif "cors" in cat_lower:
        return "CWE-942"
    elif "auth" in cat_lower:
        return "CWE-306"
    return None


def generate_sarif_report(
    findings: List[Finding],
    project_name: str = "TRACE Application",
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate an OASIS SARIF v2.1.0 compliant dictionary from findings."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = f"TRACE-{f.category.upper().replace(' ', '-')}"
        cwe = _category_to_cwe(f.category)

        if rule_id not in rules_dict:
            rule_def: Dict[str, Any] = {
                "id": rule_id,
                "name": f.category.replace("-", " ").title(),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f"Vulnerability in {f.category} detected by TRACE neuro-symbolic engine."},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity),
                },
                "properties": {
                    "tags": ["security", "trace-engine", f.category],
                    "precision": "very-high" if f.confidence == FindingConfidence.CONFIRMED else "high",
                },
            }
            if cwe:
                rule_def["properties"]["cwe"] = [cwe]
                rule_def["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
            rules_dict[rule_id] = rule_def

        # Build physical location
        locations: List[Dict[str, Any]] = []
        if f.source_location and f.source_location.file:
            file_path = f.source_location.file
            if workspace_root:
                try:
                    file_path = str(Path(file_path).relative_to(workspace_root)).replace("\\", "/")
                except ValueError:
                    file_path = file_path.replace("\\", "/")
            else:
                file_path = file_path.replace("\\", "/")

            start_line = max(1, f.source_location.line_start or 1)
            end_line = max(start_line, f.source_location.line_end or start_line)

            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                        "startColumn": max(1, f.source_location.column_start or 1),
                        "endColumn": max(1, f.source_location.column_end or 1),
                    },
                },
                "message": {
                    "text": f"Vulnerable code slice at {f.endpoint}",
                },
            })

        # Build code flows / attack path if present
        code_flows: List[Dict[str, Any]] = []
        if f.attack_path:
            thread_flow_locations = []
            for hop in f.attack_path:
                thread_flow_locations.append({
                    "location": {
                        "message": {"text": f"Attack hop: {hop}"},
                    }
                })
            code_flows.append({
                "threadFlows": [{
                    "locations": thread_flow_locations
                }]
            })

        result_obj: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {
                "text": f"{f.title}: {f.correlation_notes}",
            },
            "locations": locations,
            "properties": {
                "trace_finding_id": f.id,
                "endpoint": f.endpoint,
                "confidence": f.confidence.value,
                "severity": f.severity.value,
                "remediation": f.remediation,
                "staticEvidence": f.static_evidence,
                "runtimeEvidence": f.runtime_evidence,
            },
        }

        if code_flows:
            result_obj["codeFlows"] = code_flows

        results.append(result_obj)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TRACE Security Engine",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/VK-Amogh/TRACE",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_doc


def export_sarif_json(
    findings: List[Finding],
    output_path: str,
    project_name: str = "TRACE Application",
    workspace_root: Optional[str] = None,
) -> str:
    """Serialize findings to a SARIF v2.1.0 JSON file."""
    sarif = generate_sarif_report(findings, project_name=project_name, workspace_root=workspace_root)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return str(out.resolve())
