"""Tests for Statistical Timing Oracle (Welch's t-test)."""

import pytest
from trace_engine.security.timing import StatisticalTimingOracle


def test_timing_oracle_positive_confirmation():
    # Baseline: fast responses (~0.05s with minor variance)
    baseline = [0.048, 0.052, 0.050, 0.055]
    # Injected delay: ~1.55s with minor variance
    injected = [1.545, 1.552, 1.540, 1.560]

    result = StatisticalTimingOracle.evaluate_timing_vulnerability(
        baseline_latencies=baseline,
        delay_latencies=injected,
        expected_delay_sec=1.5,
        alpha_threshold=0.01,
    )

    assert result.is_confirmed is True
    assert result.confidence >= 0.95
    assert result.observed_shift_sec > 1.4
    assert result.t_statistic > 10.0
    assert result.p_value < 0.001
    assert "CONFIRMED" in result.summary


def test_timing_oracle_rejects_noise():
    # Baseline with network jitter (0.10s - 0.25s)
    baseline = [0.12, 0.20, 0.15, 0.22]
    # Injected with similar network jitter without real delay
    injected = [0.18, 0.24, 0.16, 0.21]

    result = StatisticalTimingOracle.evaluate_timing_vulnerability(
        baseline_latencies=baseline,
        delay_latencies=injected,
        expected_delay_sec=1.5,
        alpha_threshold=0.01,
    )

    assert result.is_confirmed is False
    assert result.confidence <= 0.40
    assert "INCONCLUSIVE" in result.summary


def test_timing_oracle_insufficient_samples():
    result = StatisticalTimingOracle.evaluate_timing_vulnerability(
        baseline_latencies=[0.05],
        delay_latencies=[1.5],
        expected_delay_sec=1.5,
    )
    assert result.is_confirmed is False
    assert "Insufficient sample size" in result.summary
