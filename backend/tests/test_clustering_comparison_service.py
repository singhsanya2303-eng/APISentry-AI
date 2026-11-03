
import numpy as np
import pytest

from app.services.clustering_comparison_service import (
    compare_clustering_detectors,
)


def make_vectors():
    return np.array(
        [
            [0.0, 0.0],
            [0.1, 0.2],
            [0.2, 0.1],
            [0.15, 0.15],
            [0.3, 0.2],
            [0.2, 0.3],
            [0.1, 0.1],
            [0.25, 0.15],
            [0.15, 0.25],
            [10.0, 10.0],
        ],
        dtype=float,
    )


def test_comparison_returns_both_detectors():
    result = compare_clustering_detectors(make_vectors())

    assert result["sample_count"] == 10
    assert result["feature_count"] == 2
    assert "kmeans" in result
    assert "lof" in result


def test_anomaly_flags_match_input_length():
    vectors = make_vectors()
    result = compare_clustering_detectors(vectors)

    assert len(result["kmeans"]["anomaly_flags"]) == len(vectors)
    assert len(result["lof"]["anomaly_flags"]) == len(vectors)
    assert len(result["kmeans"]["anomaly_scores"]) == len(vectors)
    assert len(result["lof"]["anomaly_scores"]) == len(vectors)


def test_scores_are_finite():
    result = compare_clustering_detectors(make_vectors())

    assert np.isfinite(result["kmeans"]["anomaly_scores"]).all()
    assert np.isfinite(result["lof"]["anomaly_scores"]).all()


def test_rejects_invalid_contamination():
    with pytest.raises(ValueError, match="contamination"):
        compare_clustering_detectors(make_vectors(), contamination=0)


def test_rejects_too_few_samples():
    with pytest.raises(ValueError, match="At least 3"):
        compare_clustering_detectors(np.array([[1.0], [2.0]]))


def test_rejects_non_finite_values():
    vectors = make_vectors()
    vectors[0, 0] = np.nan

    with pytest.raises(ValueError, match="finite"):
        compare_clustering_detectors(vectors)


def test_rejects_one_dimensional_input():
    with pytest.raises(ValueError, match="2D"):
        compare_clustering_detectors(np.array([1.0, 2.0, 3.0]))
