"""Tests for newly implemented vulnerability detectors, testpacks, and dataset normalizer."""

import pytest
from trace_engine.security.hypotheses import VulnerabilityCategory, HypothesisEngine, SecurityHypothesis
from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation
from trace_engine.apm.model import AttackPathModel
from trace_engine.testpacks.registry import default_registry
from trace_engine.intelligence.securebert.classifier import VULN_CATEGORIES, SecureBERTClassifier
from trace_engine.intelligence.training.dataset import normalize_code_slice, generate_cybersecurity_training_corpus


def test_new_vulnerability_categories_present():
    assert "PATH_TRAVERSAL" in [c.value for c in VulnerabilityCategory]
    assert "SSTI" in [c.value for c in VulnerabilityCategory]
    assert "CORS" in [c.value for c in VulnerabilityCategory]
    assert "DESERIALIZATION" in [c.value for c in VulnerabilityCategory]


def test_testpack_registry_contains_new_packs():
    for pack_name in ["path_traversal", "ssti", "cors", "deserialization", "ssrf", "injection", "bola", "bfla"]:
        pack = default_registry.get(pack_name)
        assert pack is not None, f"Expected {pack_name} to be registered"
        assert pack.name == pack_name


def test_hypothesis_engine_derives_new_categories():
    engine = HypothesisEngine()
    apm = AttackPathModel()
    src = SourceLocation(file="test.py", line_start=1, line_end=5)

    endpoints = [
        Endpoint(
            id="ep-trav",
            method="GET",
            path="/api/files/download",
            handler_name="download_file",
            parameters=[EndpointParameter(name="file", location="query")],
            auth_required=True,
            state_changing=False,
            sensitive_data=False,
            database_access=False,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-ssti",
            method="POST",
            path="/api/template/render",
            handler_name="render_template",
            parameters=[EndpointParameter(name="template", location="body")],
            auth_required=True,
            state_changing=True,
            sensitive_data=False,
            database_access=False,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-cors",
            method="GET",
            path="/api/user/private-data",
            handler_name="get_private_data",
            parameters=[],
            auth_required=True,
            state_changing=False,
            sensitive_data=True,
            database_access=True,
            external_network=False,
            source=src,
        ),
        Endpoint(
            id="ep-deser",
            method="POST",
            path="/api/session/restore",
            handler_name="restore_session",
            parameters=[EndpointParameter(name="data", location="body")],
            auth_required=True,
            state_changing=True,
            sensitive_data=False,
            database_access=False,
            external_network=False,
            source=src,
        ),
    ]

    hypotheses = engine.derive_hypotheses(apm, endpoints)
    categories = [h.category for h in hypotheses]

    assert VulnerabilityCategory.PATH_TRAVERSAL in categories
    assert VulnerabilityCategory.SSTI in categories
    assert VulnerabilityCategory.CORS in categories
    assert VulnerabilityCategory.DESERIALIZATION in categories


def test_code_slice_normalization():
    raw_code = """
    // User download handler
    def download_file(request):
        # Fetch file param from request
        filename = request.args.get('filename')
        return open('/var/www/' + filename).read()
    """
    normalized = normalize_code_slice(raw_code)
    assert "[SOURCE]" in normalized
    assert "[SINK]" in normalized
    assert "// User download handler" not in normalized


def test_training_corpus_generation():
    corpus = generate_cybersecurity_training_corpus(multiplier=2)
    assert len(corpus) > 20
    # Confirm coverage across categories
    all_labels = set(label for _, labels in corpus for label in labels)
    for cat in ["BOLA", "BFLA", "AUTHENTICATION", "SSRF", "INJECTION", "MASS_ASSIGNMENT", "PATH_TRAVERSAL", "SSTI", "CORS", "DESERIALIZATION"]:
        assert cat in all_labels
