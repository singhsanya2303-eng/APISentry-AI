import pytest

import numpy as np
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.routes import token_classifier as token_classifier_route
from app.services.token_usage_classifier_service import (
    ABNORMAL_TOKEN_USAGE,
    NORMAL,
    TOKEN_HIJACKING,
    TokenUsageRandomForestClassifier,
)


def make_trained_model(path):
    features = np.array(
        [
            [1, 1, 0],
            [2, 1, 0],
            [1, 2, 0],
            [2, 2, 0],
            [1, 1, 1],
            [2, 1, 1],
            [8, 5, 4],
            [9, 6, 4],
            [8, 6, 5],
            [9, 5, 5],
            [4, 8, 2],
            [5, 9, 2],
            [4, 9, 3],
            [5, 8, 3],
            [3, 3, 1],
        ],
        dtype=float,
    )
    labels = [
        NORMAL, NORMAL, NORMAL, NORMAL, NORMAL,
        NORMAL, TOKEN_HIJACKING, TOKEN_HIJACKING,
        TOKEN_HIJACKING, TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE, ABNORMAL_TOKEN_USAGE,
        ABNORMAL_TOKEN_USAGE, ABNORMAL_TOKEN_USAGE, NORMAL,
    ]
    classifier = TokenUsageRandomForestClassifier(
        n_estimators=20,
        random_state=42,
    ).fit(
        features,
        labels,
        feature_names=[
            "request_count",
            "unique_paths",
            "unusual_events",
        ],
    )
    classifier.save(str(path))


def make_client():
    app = FastAPI()
    app.include_router(token_classifier_route.router, prefix="/api/v1")
    return TestClient(app)


def test_predict_returns_503_when_model_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        token_classifier_route,
        "MODEL_PATH",
        tmp_path / "missing.joblib",
    )
    client = make_client()

    response = client.post(
        "/api/v1/security/token-classifier/predict",
        json={"features": {
            "request_count": 2,
            "unique_paths": 1,
            "unusual_events": 0,
        }},
    )

    assert response.status_code == 503
    assert "not available" in response.json()["detail"]


def test_features_returns_saved_model_schema(tmp_path, monkeypatch):
    model_path = tmp_path / "classifier.joblib"
    make_trained_model(model_path)
    monkeypatch.setattr(token_classifier_route, "MODEL_PATH", model_path)
    client = make_client()

    response = client.get("/api/v1/security/token-classifier/features")

    assert response.status_code == 200
    assert response.json()["available"] is True
    assert response.json()["feature_names"] == [
        "request_count",
        "unique_paths",
        "unusual_events",
    ]


def test_predict_returns_422_for_missing_feature(tmp_path, monkeypatch):
    model_path = tmp_path / "classifier.joblib"
    make_trained_model(model_path)
    monkeypatch.setattr(token_classifier_route, "MODEL_PATH", model_path)
    client = make_client()

    response = client.post(
        "/api/v1/security/token-classifier/predict",
        json={"features": {
            "request_count": 2,
            "unique_paths": 1,
        }},
    )

    assert response.status_code == 422
    assert "missing_features" in response.json()["detail"]


def test_predict_returns_class_and_probabilities(tmp_path, monkeypatch):
    model_path = tmp_path / "classifier.joblib"
    make_trained_model(model_path)
    monkeypatch.setattr(token_classifier_route, "MODEL_PATH", model_path)
    client = make_client()

    response = client.post(
        "/api/v1/security/token-classifier/predict",
        json={"features": {
            "request_count": 2,
            "unique_paths": 1,
            "unusual_events": 0,
        }},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["predicted_label"] in {
        NORMAL,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
    }
    assert 0 <= body["confidence"] <= 1
    assert set(body["class_probabilities"]) == {
        NORMAL,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
    }
    assert sum(body["class_probabilities"].values()) == pytest.approx(1.0)


# --- Real shipped five-feature artifact (no monkeypatch, no retraining) -------
# These tests exercise the actual backend/models/token_usage_classifier.joblib
# through the real router MODEL_PATH. The artifact was trained on synthetic demo
# data, so these assertions verify loading, schema, and API plumbing only; they
# make no claim about real-world detection accuracy.


_EXPECTED_SHIPPED_FEATURES = [
    "requests_per_minute",
    "unique_ips",
    "failed_requests_ratio",
    "token_reuse_count",
    "geo_distance_km",
]


@pytest.fixture(scope="module")
def shipped_classifier():
    artifact_path = token_classifier_route.MODEL_PATH
    if not artifact_path.is_file():
        pytest.skip(f"Shipped token classifier artifact missing: {artifact_path}")
    try:
        return TokenUsageRandomForestClassifier.load(str(artifact_path))
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Shipped token classifier artifact could not be loaded: {exc}")


def test_shipped_artifact_features_endpoint_matches_artifact(shipped_classifier):
    assert shipped_classifier.feature_names == _EXPECTED_SHIPPED_FEATURES

    response = make_client().get("/api/v1/security/token-classifier/features")

    assert response.status_code == 200
    body = response.json()
    assert body["available"] is True
    assert body["feature_names"] == shipped_classifier.feature_names
    assert body["feature_names"] == _EXPECTED_SHIPPED_FEATURES


def test_shipped_artifact_predict_endpoint_accepts_five_features(shipped_classifier):
    response = make_client().post(
        "/api/v1/security/token-classifier/predict",
        json={
            "features": {
                "requests_per_minute": 12.0,
                "unique_ips": 2,
                "failed_requests_ratio": 0.02,
                "token_reuse_count": 1,
                "geo_distance_km": 10.0,
            }
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["predicted_label"] in {
        NORMAL,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
    }
    assert 0 <= body["confidence"] <= 1
    assert set(body["class_probabilities"]) == {
        NORMAL,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
    }
    assert sum(body["class_probabilities"].values()) == pytest.approx(1.0)
