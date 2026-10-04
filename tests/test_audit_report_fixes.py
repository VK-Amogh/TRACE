"""Tests verifying all fixes for the issues identified in Reportofthereport.md."""

from pathlib import Path
import pytest
from trace_engine.security.hypotheses import VulnerabilityCategory, HypothesisEngine, Severity
from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation
from trace_engine.apm.model import AttackPathModel
from trace_engine.findings.correlate import EvidenceCorrelator


def test_deserialization_false_positives_eliminated():
    """Ensure standard JSON session endpoints are NOT falsely labeled as Insecure Deserialization."""
    engine = HypothesisEngine()
    apm = AttackPathModel()
    src = SourceLocation(file="backend/main.py", line_start=500, line_end=600)

    session_endpoints = [
        Endpoint(
            id="ep-session-start",
            method="POST",
            path="/api/session/start",
            handler_name="start_session",
            parameters=[EndpointParameter(name="target_score", location="body")],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-session-reset",
            method="POST",
            path="/api/session/reset",
            handler_name="reset_session",
            parameters=[],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-session-shots",
            method="POST",
            path="/api/session/{session_id}/shots",
            handler_name="record_shot",
            parameters=[EndpointParameter(name="session_id", location="path")],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-session-shots-bulk",
            method="POST",
            path="/api/session/{session_id}/shots/bulk",
            handler_name="bulk_record_shots",
            parameters=[EndpointParameter(name="session_id", location="path")],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, session_endpoints)
    categories = [h.category for h in hypotheses]

    # Insecure Deserialization must be 0 for these endpoints
    assert VulnerabilityCategory.DESERIALIZATION not in categories


def test_mass_assignment_false_positives_eliminated_and_role_reclassified():
    """Ensure single-field DTOs are not flagged as Mass Assignment, and role param is BFLA."""
    engine = HypothesisEngine()
    apm = AttackPathModel()
    src = SourceLocation(file="backend/main.py", line_start=500, line_end=600)

    endpoints = [
        Endpoint(
            id="ep-assign-coach",
            method="POST",
            path="/api/athlete/{athlete_id}/coach",
            handler_name="assign_coach",
            parameters=[EndpointParameter(name="coach_id", location="body")],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-reset-pw",
            method="POST",
            path="/api/athlete/{athlete_id}/reset-password",
            handler_name="reset_password",
            parameters=[EndpointParameter(name="new_password", location="body")],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-create-user",
            method="POST",
            path="/api/admin/users/create",
            handler_name="create_user",
            parameters=[
                EndpointParameter(name="username", location="body"),
                EndpointParameter(name="password", location="body"),
                EndpointParameter(name="role", location="body"),
            ],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, endpoints)

    # 1. Single field endpoints must NOT have MASS_ASSIGNMENT
    mass_hyps = [h for h in hypotheses if h.category == VulnerabilityCategory.MASS_ASSIGNMENT]
    assert len(mass_hyps) == 0

    # 2. create_user must have BFLA Privilege Escalation via Unvalidated Role Assignment
    role_hyps = [h for h in hypotheses if "Role Assignment" in h.title]
    assert len(role_hyps) == 1
    assert role_hyps[0].category == VulnerabilityCategory.BFLA
    assert role_hyps[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_admin_bfla_and_auth_deduplication():
    """Ensure administrative endpoints do not produce duplicate BFLA and AUTH pairs."""
    engine = HypothesisEngine()
    apm = AttackPathModel()
    src = SourceLocation(file="backend/main.py", line_start=490, line_end=560)

    admin_endpoints = [
        Endpoint(
            id="ep-admin-users",
            method="GET",
            path="/api/admin/users",
            handler_name="get_users",
            parameters=[],
            auth_required=False,
            roles=["admin"],
            state_changing=False,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-admin-delete",
            method="DELETE",
            path="/api/admin/users/{user_id}",
            handler_name="delete_user",
            parameters=[EndpointParameter(name="user_id", location="path")],
            auth_required=False,
            roles=["admin"],
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-admin-reset-db",
            method="POST",
            path="/api/admin/reset-db",
            handler_name="reset_db",
            parameters=[],
            auth_required=False,
            roles=["admin"],
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, admin_endpoints)

    # For each admin endpoint, there should be BFLA, and NO duplicate AUTH
    for ep in admin_endpoints:
        ep_hyps = [h for h in hypotheses if h.endpoint_id == ep.id]
        categories = [h.category for h in ep_hyps]
        assert VulnerabilityCategory.BFLA in categories
        assert VulnerabilityCategory.AUTHENTICATION not in categories


def test_contextual_severity_calibration():
    """Ensure severity is calibrated to true business impact."""
    engine = HypothesisEngine()
    apm = AttackPathModel()
    correlator = EvidenceCorrelator()
    src = SourceLocation(file="backend/main.py", line_start=100, line_end=200)

    test_endpoints = [
        Endpoint(
            id="ep-scatt",
            method="POST",
            path="/api/scatt-analysis",
            handler_name="analyze_scatt",
            parameters=[],
            auth_required=False,
            state_changing=False,
            sensitive_data=False,
            database_access=False,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-user-get",
            method="GET",
            path="/api/user/{user_id}",
            handler_name="get_user",
            parameters=[EndpointParameter(name="user_id", location="path")],
            auth_required=False,
            state_changing=False,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-session-reset-blast",
            method="POST",
            path="/api/session/reset",
            handler_name="reset_session",
            parameters=[],
            auth_required=False,
            state_changing=True,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, test_endpoints)

    # 1. Stateless scatt-analysis must be LOW
    scatt_hyp = next(h for h in hypotheses if h.endpoint_id == "ep-scatt")
    scatt_finding = correlator.correlate(scatt_hyp, None, apm)
    assert scatt_finding.severity == Severity.LOW

    # 2. Read-only user get must be MEDIUM
    user_hyp = next(h for h in hypotheses if h.endpoint_id == "ep-user-get" and h.category == VulnerabilityCategory.AUTHENTICATION)
    user_finding = correlator.correlate(user_hyp, None, apm)
    assert user_finding.severity == Severity.MEDIUM

    # 3. Global session reset blast radius must be CRITICAL
    reset_hyp = next(h for h in hypotheses if h.endpoint_id == "ep-session-reset-blast" and h.category == VulnerabilityCategory.AUTHENTICATION)
    reset_finding = correlator.correlate(reset_hyp, None, apm)
    assert reset_finding.severity == Severity.CRITICAL


def test_missed_vulnerabilities_detected(tmp_path):
    """Ensure static files mounts, websockets, caller-controlled ownership, CORS and broken crypto are detected."""
    # Create mock backend file with the vulnerable patterns
    mock_main = tmp_path / "main.py"
    mock_main.write_text("""
from fastapi import FastAPI, Depends, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import hashlib

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def hash_password(password: str) -> str:
    salt = "snyptr_secure_salt_2026"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if hashed_password == plain_password:
        return True
    return hash_password(plain_password) == hashed_password

app.mount("/session_videos", StaticFiles(directory="session_videos"), name="session_videos")

@app.websocket("/ws/feedback")
async def ws_feedback(websocket):
    await websocket.accept()

def assert_coach_owns_athlete(coach_id, athlete_id):
    pass

@app.get("/api/story/{user_id}/{date}")
def get_match_story(user_id: int, date: str, coach_id: int = Query(None)):
    if coach_id is not None:
        assert_coach_owns_athlete(coach_id, user_id)
    return {"story": "data"}
""", encoding="utf-8")

    src = SourceLocation(file=str(mock_main), line_start=1, line_end=40)
    engine = HypothesisEngine()
    apm = AttackPathModel()

    endpoints = [
        Endpoint(
            id="ep-mount-videos",
            method="GET",
            path="/session_videos/{filepath}",
            handler_name="StaticFiles(session_videos)",
            parameters=[EndpointParameter(name="filepath", location="path")],
            auth_required=False,
            state_changing=False,
            sensitive_data=True,
            database_access=False,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-ws-feedback",
            method="WEBSOCKET",
            path="/ws/feedback",
            handler_name="ws_feedback",
            parameters=[],
            auth_required=False,
            state_changing=False,
            sensitive_data=False,
            database_access=False,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-story",
            method="GET",
            path="/api/story/{user_id}/{date}",
            handler_name="get_match_story",
            parameters=[
                EndpointParameter(name="user_id", location="path"),
                EndpointParameter(name="coach_id", location="query"),
            ],
            auth_required=False,
            object_identifier=True,
            state_changing=False,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, endpoints)
    titles = [h.title for h in hypotheses]

    # 1. StaticFiles mount detected
    assert any("StaticFiles Mount" in t for t in titles)

    # 2. Unauthenticated WebSocket detected
    assert any("Unauthenticated WebSocket" in t for t in titles)

    # 3. Caller-Controlled Ownership Bypass detected
    assert any("Caller-Controlled Ownership Bypass" in t for t in titles)

    # 4. Insecure CORS wildcard with credentials detected
    assert any("Insecure CORS Wildcard with Credentials" in t for t in titles)

    # 5. Broken password hashing detected
    assert any("Broken Password Hashing" in t for t in titles)
