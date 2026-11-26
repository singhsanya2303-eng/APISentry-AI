"""Tests for MW4-C P1 synthetic benchmark/evaluation harness.

Bounded, synthetic-only, no PostgreSQL, no network.
"""
from __future__ import annotations

from app.services.mw4_p1_evaluation import (
    DATASET_VERSION,
    generate_synthetic_dataset,
    run_benchmark,
    run_synthetic_evaluation,
)


def test_generate_synthetic_dataset_is_deterministic():
    a = generate_synthetic_dataset(seed=1337, n_per_category=2)
    b = generate_synthetic_dataset(seed=1337, n_per_category=2)
    assert a["dataset_version"] == DATASET_VERSION
    assert a["total_cases"] == 18
    assert a["dataset_sha256"] == b["dataset_sha256"]
    assert a["cases"] == b["cases"]
    # no real secrets/PII markers
    blob = str(a)
    assert "password" not in blob.lower()
    assert "Bearer " not in blob


def test_benchmark_runs_bounded_and_reports_errors():
    ds = generate_synthetic_dataset(seed=7, n_per_category=1)
    out = run_benchmark(ds, iterations=1, warmup=0)
    assert out["measurement_type"].startswith("in-process")
    assert out["config"]["cases"] == 9
    assert out["error_count"] == 0
    assert out["timings"]["total_ms"]["count"] == 9
    assert "limitations" in out


def test_synthetic_evaluation_reports_agreement_and_limitations():
    ds = generate_synthetic_dataset(seed=7, n_per_category=2)
    out = run_synthetic_evaluation(ds)
    assert out["evaluation_type"].startswith("synthetic-rule agreement")
    assert out["error_count"] == 0
    assert out["mw1_severity_agreement"]["evaluable_cases"] >= 1
    assert 0.0 <= out["mw1_severity_agreement"]["agreement_rate"] <= 1.0
    assert "limitations" in out
    assert out["missing_uncertain_handling"]["missing_signal_cases"] >= 1
