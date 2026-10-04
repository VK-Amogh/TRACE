"""Unit and integration tests for Laya fine-tuning and neural benchmarking."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from trace_engine.intelligence.training.laya_trainer import (
    LayaTrainingSample,
    generate_laya_training_corpus,
    LayaTrainer,
    PRIORITY_LABELS,
    TESTPACK_LABELS,
)
from trace_engine.intelligence.evaluation import run_intelligence_benchmark


def test_laya_training_corpus_generation():
    """Verify that synthetic and APM-derived Laya training data is well-formed."""
    corpus = generate_laya_training_corpus()
    assert len(corpus) >= 20

    for sample in corpus:
        assert isinstance(sample, LayaTrainingSample)
        assert sample.priority_level in PRIORITY_LABELS
        assert sample.primary_testpack in TESTPACK_LABELS
        assert len(sample.endpoint_state) > 10


def test_run_intelligence_benchmark():
    """Verify that head-to-head empirical benchmark executes cleanly."""
    res = run_intelligence_benchmark()
    assert "laya" in res
    assert "securebert" in res
    assert "ensemble" in res
    assert res["laya"]["latency_ms"] >= 0.0
    assert res["securebert"]["latency_ms"] >= 0.0
