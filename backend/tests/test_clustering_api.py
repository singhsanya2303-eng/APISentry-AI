
import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

ENDPOINT = "/api/v1/security/clustering/analyze"

SAMPLE_VECTORS = [
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
]


def test_clustering_route_is_registered():
    assert ENDPOINT in app.openapi()["paths"]


def test_clustering_api_returns_both_detectors():
    response = client.post(
        ENDPOINT,
        json={"feature_vectors": SAMPLE_VECTORS},
    )

    assert response.status_code == 200

    result = response.json()
    assert result["sample_count"] == 10
    assert result["feature_count"] == 2
    assert "kmeans" in result
    assert "lof" in result
    assert len(result["kmeans"]["anomaly_flags"]) == 10
    assert len(result["lof"]["anomaly_flags"]) == 10


def test_clustering_api_rejects_too_few_samples():
    response = client.post(
        ENDPOINT,
        json={"feature_vectors": [[1.0], [2.0]]},
    )

    assert response.status_code == 422


def test_clustering_api_rejects_mismatched_dimensions():
    response = client.post(
        ENDPOINT,
        json={
            "feature_vectors": [
                [1.0, 2.0],
                [3.0],
                [4.0, 5.0],
            ]
        },
    )

    assert response.status_code == 422


def test_clustering_api_rejects_invalid_contamination():
    response = client.post(
        ENDPOINT,
        json={
            "feature_vectors": SAMPLE_VECTORS,
            "contamination": 0,
        },
    )

    assert response.status_code == 422


def test_clustering_api_rejects_non_finite_values():
    response = client.post(
        ENDPOINT,
        json={
            "feature_vectors": [
                [0.0, 0.0],
                [0.1, 0.2],
                ["NaN", 1.0],
            ]
        },
    )

    assert response.status_code == 422
