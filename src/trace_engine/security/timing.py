"""Statistical Timing Oracle using Welch's t-test for bulletproof blind injection verification."""

import math
from typing import List, Tuple, Dict, Any, Optional
from pydantic import BaseModel, Field


class TimingVerificationResult(BaseModel):
    """Result of statistical timing hypothesis verification."""
    is_confirmed: bool = Field(..., description="True if delay is statistically proven beyond network noise")
    t_statistic: float = Field(..., description="Welch's t-statistic")
    p_value: float = Field(..., description="Two-tailed p-value (significance level)")
    degrees_of_freedom: float = Field(..., description="Welch-Satterthwaite degrees of freedom")
    mean_baseline_sec: float = Field(..., description="Mean baseline latency in seconds")
    mean_delay_sec: float = Field(..., description="Mean injected delay latency in seconds")
    observed_shift_sec: float = Field(..., description="Observed latency delta (mean_delay - mean_baseline)")
    confidence: float = Field(..., description="Bayesian probability score [0.0 - 1.0]")
    summary: str = Field(..., description="Detailed statistical rationale")


class StatisticalTimingOracle:
    """Rigorous statistical testing engine for blind SQL, Command, and Code injection verification.

    Applies Welch's two-sample t-test to eliminate false positives from network latency jitter and CPU throttling.
    """

    @staticmethod
    def calculate_stats(samples: List[float]) -> Tuple[float, float]:
        """Calculates sample mean and unbiased sample variance."""
        n = len(samples)
        if n < 2:
            return (samples[0] if n == 1 else 0.0, 0.0)
        mean = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
        return mean, max(variance, 1e-9)

    @classmethod
    def evaluate_timing_vulnerability(
        cls,
        baseline_latencies: List[float],
        delay_latencies: List[float],
        expected_delay_sec: float = 1.5,
        alpha_threshold: float = 0.01,
    ) -> TimingVerificationResult:
        """Evaluates whether delay latencies represent a statistically significant vulnerability reaction.

        Args:
            baseline_latencies: List of latency measurements (seconds) for non-delay probes.
            delay_latencies: List of latency measurements (seconds) for delay-injected probes.
            expected_delay_sec: Nominal delay programmed into probe payload (e.g. 1.5s).
            alpha_threshold: Significance level threshold (default 0.01 for 99% confidence).
        """
        n1 = len(baseline_latencies)
        n2 = len(delay_latencies)

        if n1 < 2 or n2 < 2:
            return TimingVerificationResult(
                is_confirmed=False,
                t_statistic=0.0,
                p_value=1.0,
                degrees_of_freedom=0.0,
                mean_baseline_sec=sum(baseline_latencies) / max(1, n1),
                mean_delay_sec=sum(delay_latencies) / max(1, n2),
                observed_shift_sec=0.0,
                confidence=0.1,
                summary="Insufficient sample size for statistical verification (minimum 2 samples required per group).",
            )

        mean1, var1 = cls.calculate_stats(baseline_latencies)
        mean2, var2 = cls.calculate_stats(delay_latencies)

        delta = mean2 - mean1
        se = math.sqrt((var1 / n1) + (var2 / n2))

        # Welch-Satterthwaite degrees of freedom
        numerator = ((var1 / n1) + (var2 / n2)) ** 2
        denominator = (((var1 / n1) ** 2) / (n1 - 1)) + (((var2 / n2) ** 2) / (n2 - 1))
        df = max(1.0, numerator / max(denominator, 1e-9))

        t_stat = delta / max(se, 1e-9)

        # Approximate p-value using standard normal / t-distribution tail
        # For large df, t approximates normal. For small df, Cornish-Fisher / Student approximation
        p_val = cls._approximate_p_value(t_stat, df)

        # Requirements for confirmation:
        # 1. Statistically significant difference (p < alpha_threshold)
        # 2. Positive direction (t > 0)
        # 3. Magnitude matches at least 70% of nominal programmed sleep time
        shift_ratio = delta / max(expected_delay_sec, 0.1)
        confirmed = (t_stat > 2.5) and (p_val < alpha_threshold) and (shift_ratio >= 0.70)

        confidence = 0.99 if confirmed else (0.40 if t_stat > 2.0 and delta > 0 else 0.10)

        if confirmed:
            summary = (
                f"Statistical Timing Oracle CONFIRMED blind injection: Mean latency shifted by +{delta:.2f}s "
                f"(nominal {expected_delay_sec:.1f}s) with Welch's t={t_stat:.2f} (df={df:.1f}, p={p_val:.2e} < {alpha_threshold}). "
                f"Null hypothesis (network jitter) rejected with >99% confidence."
            )
        else:
            summary = (
                f"Statistical Timing Oracle INCONCLUSIVE: Observed latency shift +{delta:.2f}s "
                f"(t={t_stat:.2f}, p={p_val:.4f}). Did not satisfy 70% expected delay shift ({expected_delay_sec:.1f}s) "
                f"or significance threshold ({alpha_threshold})."
            )

        return TimingVerificationResult(
            is_confirmed=confirmed,
            t_statistic=round(t_stat, 3),
            p_value=round(p_val, 6),
            degrees_of_freedom=round(df, 1),
            mean_baseline_sec=round(mean1, 3),
            mean_delay_sec=round(mean2, 3),
            observed_shift_sec=round(delta, 3),
            confidence=confidence,
            summary=summary,
        )

    @staticmethod
    def _approximate_p_value(t: float, df: float) -> float:
        """Approximates two-tailed p-value for Student's / Welch's t-distribution."""
        if t <= 0:
            return 1.0

        # Normal approximation with tail correction for degrees of freedom
        # Z = t * (1 - 1/(4*df))
        z = t * (1.0 - (1.0 / (4.0 * max(df, 1.0))))
        # Error function complementary approximation
        erf_arg = z / math.sqrt(2.0)
        p = math.erfc(erf_arg)
        return max(1e-12, min(1.0, p))
