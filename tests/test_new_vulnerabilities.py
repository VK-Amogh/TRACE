"""Tests for newly implemented vulnerability detectors, testpacks, and dataset normalizer."""

from pathlib import Path
import pytest
from trace_engine.security.hypotheses import VulnerabilityCategory, HypothesisEngine, SecurityHypothesis
from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation
from trace_engine.apm.model import AttackPathModel
from trace_engine.testpacks.registry import default_registry
from trace_engine.intelligence.securebert.classifier import VULN_CATEGORIES, SecureBERTClassifier
from trace_engine.intelligence.training.dataset import normalize_code_slice, generate_cybersecurity_training_corpus
from trace_engine.intelligence.training.slicer import slice_and_canonicalize, DataflowSliceExtractor
from trace_engine.intelligence.training.lora_system2 import System2LoRATrainer, LoRATrainingConfig
from trace_engine.intelligence.training.dataset_importers import JulietImporter, BigVulImporter, CVEfixesImporter, MoreFixesImporter


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
    all_labels = set(label for _, labels in corpus for label in labels)
    for cat in ["BOLA", "BFLA", "AUTHENTICATION", "SSRF", "INJECTION", "MASS_ASSIGNMENT", "PATH_TRAVERSAL", "SSTI", "CORS", "DESERIALIZATION"]:
        assert cat in all_labels


def test_dataflow_slice_and_canonicalize():
    code = """
    def fetch_user_data():
        user_param = request.args.get('id')
        sanitized = user_param.strip()
        return db.execute('SELECT * FROM users WHERE id=' + sanitized)
    """
    trace = slice_and_canonicalize(code)
    assert "[SOURCE:" in trace
    assert "[FLOW:" in trace
    assert "[SINK:" in trace


def test_system2_lora_trainer_init():
    trainer = System2LoRATrainer(LoRATrainingConfig(model_name="Qwen/Qwen2.5-Coder-1.5B-Instruct"))
    samples = trainer.build_synthetic_samples()
    assert len(samples) >= 3
    assert samples[0].cwe_id == "CWE-639"
    assert "--- a/" in samples[0].remediation_diff


def test_dataset_importers():
    juliet = JulietImporter()
    big_vul = BigVulImporter()
    cvefixes = CVEfixesImporter()
    morefixes = MoreFixesImporter()

    assert juliet.import_sarif(Path("non_existent.sarif")) == []
    assert big_vul.import_csv(Path("non_existent.csv")) == []
    assert cvefixes.import_jsonl(Path("non_existent.jsonl")) == []
    assert morefixes.import_patch_archive(Path("non_existent.zip")) == []
    assert morefixes.import_sql_dump_stream(Path("non_existent.sql")) == []


def test_morefixes_patch_import(tmp_path):
    import zipfile
    zip_path = tmp_path / "patches.zip"
    diff_content = """--- a/user_repo.py
+++ b/user_repo.py
@@ -10,3 +10,3 @@
-def get_user(uid):
-    return db.query(f"SELECT * FROM users WHERE id = '{uid}'")
+def get_user(uid):
+    return db.query("SELECT * FROM users WHERE id = :id", id=uid)
"""
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("CVE-2024-1234_patch.diff", diff_content)

    importer = MoreFixesImporter()
    samples = importer.import_patch_archive(
        zip_path,
        cwe_index={"CVE-2024-1234_patch.diff": "CWE-89"},
        limit=10,
        include_benign=True,
    )
    assert len(samples) == 2
    vuln_code, vuln_labels = samples[0]
    assert "SELECT * FROM users WHERE id =" in vuln_code
    assert vuln_labels == ["INJECTION"]
    fixed_code, fixed_labels = samples[1]
    assert "db.query" in fixed_code
    assert fixed_labels == []
