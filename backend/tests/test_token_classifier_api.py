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
