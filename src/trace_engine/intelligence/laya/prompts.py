"""Decision prompts and state formatters for Laya."""

from typing import Dict, Any, List
from trace_engine.framework.base import Endpoint
from trace_engine.apm.model import AttackPathModel


def format_endpoint_state(endpoint: Endpoint, apm: AttackPathModel) -> str:
    """Format an endpoint and its APM context into a concise state representation for Laya."""
    paths = apm.find_paths_to_sinks(endpoint.id)
    sink_summary = f"Sinks: {len(paths)} detected" if paths else "No direct sensitive sink"
    
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
