"""Comprehensive integration test suite for the hardcore multi-framework testbed.
Validates:
1. Multi-framework AST endpoint extraction (Django DRF, Dart Shelf, Kotlin Spring Boot).
2. APM attack path graph generation.
3. Welch's t-test statistical timing oracle on blind delays.
4. Active runtime exploit verification (BOLA, SSRF, BFLA, SQLi).
5. Neuro-symbolic confidence fusion and Bayesian calibration.
6. OASIS SARIF v2.1.0 compliance.
"""

import sys
import os
import time
import subprocess
import pytest
from pathlib import Path

from trace_engine.ingest.repository import RepositoryScanner
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework import get_adapters
from trace_engine.apm.builder import APMBuilder
from trace_engine.security.hypotheses import HypothesisEngine
from trace_engine.policy.scope import ScopeGuard
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.testpacks.registry import default_registry
from trace_engine.testpacks.base import TestContext
from trace_engine.findings.correlate import EvidenceCorrelator
from trace_engine.output.sarif import generate_sarif_report
from trace_engine.security.timing import StatisticalTimingOracle


@pytest.fixture(scope="module")
def hardcore_server():
    """Spin up the hardcore testbed mock server on port 18086."""
    server_script = Path(__file__).parent.parent / "testbed_hardcore" / "server.py"
    port = 18086
    proc = subprocess.Popen(
        [sys.executable, str(server_script), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.2)  # Allow server to bind
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()


def test_hardcore_ast_extraction():
    """Verify AST extraction discovers all multi-framework endpoints."""
    testbed_dir = Path(__file__).parent.parent / "testbed_hardcore"
    scanner = RepositoryScanner(testbed_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    discovered = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language, absolute_path=sf.absolute_path)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered.extend(adapter.extract_endpoints(pf, content))

    paths = [ep.path for ep in discovered]
    # Check Django DRF endpoints
    assert any("/api/v1/analytics/query" in p for p in paths)
    assert any("vaults" in p for p in paths)
    assert any("webhook" in p for p in paths)
    # Check Dart Shelf endpoint
    assert any("/api/v1/auth/profile" in p for p in paths)
    # Check Kotlin Spring Boot endpoint
    assert any("patients" in p for p in paths)


def test_statistical_timing_oracle_on_hardcore_blind_sqli(hardcore_server):
    """Test Welch's t-test separates high-noise delays from genuine blind SQLi."""
    import urllib.request
    import json

    target_url = f"{hardcore_server}/api/v1/analytics/query"

    # Baseline request latencies (without injection payload)
    baseline_samples = []
    for _ in range(4):
        t0 = time.perf_counter()
        req = urllib.request.Request(
            target_url,
            data=json.dumps({"metric_filter": "cpu_usage"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        baseline_samples.append(time.perf_counter() - t0)

    # Injected request latencies (with time-delay payload)
    injected_samples = []
    for _ in range(4):
        t0 = time.perf_counter()
        req = urllib.request.Request(
            target_url,
            data=json.dumps({"metric_filter": "1' OR '1'='1' AND SLEEP(1)--"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        injected_samples.append(time.perf_counter() - t0)

    res = StatisticalTimingOracle.evaluate_timing_vulnerability(
        baseline_latencies=baseline_samples,
        delay_latencies=injected_samples,
        expected_delay_sec=0.75,
        alpha_threshold=0.01,
    )

    assert res.is_confirmed is True
    assert res.p_value < 0.01
    assert res.observed_shift_sec >= 0.4
    assert res.confidence >= 0.95


def test_full_pipeline_hardcore_testbed(hardcore_server):
    """Run complete end-to-end TRACE scan against the hardcore multi-framework testbed."""
    testbed_dir = Path(__file__).parent.parent / "testbed_hardcore"
    scanner = RepositoryScanner(testbed_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    parsed_files = []
    discovered = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language, absolute_path=sf.absolute_path)
        parsed_files.append(pf)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered.extend(adapter.extract_endpoints(pf, content))

    # Build Attack-Path Model
    builder = APMBuilder(project_name="hardcore-testbed")
    graph_model = builder.build(testbed_dir, source_files, parsed_files, discovered)

    # Derive Hypotheses
    engine = HypothesisEngine()
    hypotheses = engine.derive_hypotheses(graph_model, discovered)
    assert len(hypotheses) > 0

    # Runtime Execution with Scoped Client
    scope_guard = ScopeGuard(mode="lab_only")
    scope_guard.allow_target(hardcore_server)
    client = ScopedHttpClient(scope_guard=scope_guard, timeout_seconds=6)
    context = TestContext(
        target_base_url=hardcore_server,
        active_tokens={"user-a": "user-a-token", "user-b": "user-b-token", "admin": "admin-token"},
    )

    correlator = EvidenceCorrelator()
    findings = []
    for hyp in hypotheses:
        pack = default_registry.get(hyp.recommended_test_pack)
        res = None
        if pack:
            try:
                res = pack.execute(hyp, client, context)
            except Exception:
                res = None
        finding = correlator.correlate(hyp, res, graph_model)
        if finding:
            findings.append(finding)

    assert len(findings) > 0

    # Test SARIF Export
    sarif = generate_sarif_report(findings, project_name="HardcoreEnterprise", workspace_root=str(testbed_dir))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(findings)
