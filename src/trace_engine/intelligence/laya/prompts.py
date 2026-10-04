"""Decision prompts and state formatters for Laya."""

from typing import Dict, Any, List
from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel


def format_endpoint_state(endpoint: Endpoint, apm: AttackPathModel) -> str:
    """Format an endpoint and its APM context into a concise state representation for Laya."""
    paths = apm.find_paths_to_sinks(endpoint.id) if apm else []
    if paths:
        sink_labels = []
        for p in paths:
            if p and p[-1] in apm.nodes_data:
                node = apm.nodes_data[p[-1]]
                op = node.properties.get("operation", "")
                risk = node.properties.get("risk", "")
                detail = f"{node.label} {op or risk}".strip()
                sink_labels.append(detail)
        sink_detail_str = f" ({', '.join(sink_labels[:2])})" if sink_labels else ""
        sink_summary = f"Sinks: {len(paths)} detected{sink_detail_str}"
    elif "admin" in endpoint.roles or "/admin" in endpoint.path.lower():
        sink_summary = "Sinks: 1 detected (PrivilegedOperation)"
    elif not endpoint.auth_required and endpoint.state_changing and endpoint.sensitive_data:
        sink_summary = "Sinks: 1 detected (StateModification)"
    elif endpoint.database_access:
        if endpoint.method in ("PUT", "PATCH"):
            op = "update"
        elif endpoint.object_identifier:
            op = "lookup"
        else:
            op = "query"
        sink_summary = f"Sinks: 1 detected (DatabaseAccess {op})"
    elif endpoint.external_network:
        sink_summary = "Sinks: 1 detected (OutboundHTTPClient SSRF)"
    else:
        sink_summary = "No direct sensitive sink"

    return (
        f"Endpoint: {endpoint.method} {endpoint.path}\n"
        f"Auth Required: {endpoint.auth_required}, Roles: {endpoint.roles}\n"
        f"Parameters: {[p.name for p in endpoint.parameters]}\n"
        f"Database Access: {endpoint.database_access}, Outbound Network: {endpoint.external_network}\n"
        f"State Changing: {endpoint.state_changing}, Sensitive Data: {endpoint.sensitive_data}\n"
        f"APM Path Context: {sink_summary}"
    )


def format_observation_state(endpoint: Endpoint, observation_summary: str, response_status: int) -> str:
    """Format a runtime observation into a state representation for evidence calibration."""
    return (
        f"Endpoint: {endpoint.method} {endpoint.path}\n"
        f"Response Status: {response_status}\n"
        f"Observation: {observation_summary}\n"
        f"Auth Required in Code: {endpoint.auth_required}"
    )
