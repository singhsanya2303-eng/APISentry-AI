"""Task 11 regression tests for absent HTTP payload classifier artifacts.

These tests never require the excluded research model bundle. They prove safe
degradation, distinguish 503 unavailability from 422 input errors, and use a
test-only deterministic double to confirm the supported response contract.
"""

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.main import app, create_app
from app.schemas.http_payload_classifier import FEATURE_MODE_TEXT
from app.services import http_payload_classifier_service as service

PREDICT_ENDPOINT = "/api/v1/security/payload-classifier/predict"
UNAVAILABLE_DETAIL = "Payload classifier model is not available."
INVALID_DETAIL = "Invalid request."

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_classifier_cache():
    service._reset_cache()
    try:
        yield
    finally:
        service._reset_cache()


def _use_missing_artifact(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path / "missing-artifact-dir")


def test_missing_artifact_does_not_crash_import_or_app_creation(monkeypatch, tmp_path):
    _use_missing_artifact(monkeypatch, tmp_path)

    local_app = create_app()

    response = TestClient(local_app).get("/api/v1/openapi.json")
    assert response.status_code == 200
    assert PREDICT_ENDPOINT in response.json()["paths"]


def test_missing_artifact_returns_explicit_unavailable_without_prediction(monkeypatch, tmp_path):
    _use_missing_artifact(monkeypatch, tmp_path)

    response = client.post(PREDICT_ENDPOINT, json={"payloads": ["admin"]})

    assert response.status_code == 503
    assert response.json() == {"detail": UNAVAILABLE_DETAIL}
    assert "results" not in response.json()
    for fabricated_marker in ("label", "decision_score", "anomalous", "benign"):
        assert fabricated_marker not in response.text.lower()


def test_missing_artifact_is_distinct_from_malformed_input(monkeypatch, tmp_path):
    _use_missing_artifact(monkeypatch, tmp_path)

    invalid = client.post(PREDICT_ENDPOINT, json={"payloads": []})

    assert invalid.status_code == 422
    assert invalid.json() == {"detail": INVALID_DETAIL}


def test_missing_artifact_direct_service_call_raises_safe_error(monkeypatch, tmp_path):
    _use_missing_artifact(monkeypatch, tmp_path)

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads(["admin"])

    assert str(exc_info.value) == UNAVAILABLE_DETAIL
    assert "missing-artifact-dir" not in str(exc_info.value)


def test_supported_prediction_contract_works_with_test_double(monkeypatch):
    """Test-only double; production never substitutes an untrained model."""
    fake_bundle = {
        "format_version": service.FORMAT_VERSION,
        "model": SimpleNamespace(
            decision_function=lambda features: np.asarray([2.5 for _ in features])
        ),
        "vectorizer": SimpleNamespace(transform=lambda values: list(values)),
        "feature_mode": FEATURE_MODE_TEXT,
        "selected_model_name": "tfidf_char_svm",
        "decision_threshold": 0.0,
        "labels": service._LABELS,
        "seed": 0,
        "dataset_sha256": "0" * 64,
        "scaler": SimpleNamespace(),
    }
    monkeypatch.setattr(service, "_get_cached_bundle", lambda: fake_bundle)

    response = client.post(PREDICT_ENDPOINT, json={"payloads": ["admin"]})

    assert response.status_code == 200
    body = response.json()
    assert body["model_name"] == "tfidf_char_svm"
    assert body["feature_mode"] == "text"
    assert body["advisory_only"] is True
    assert len(body["results"]) == 1
    result = body["results"][0]
    assert result["label"] == "anomalous"
    assert result["label_int"] == 1
    assert result["decision_score"] == pytest.approx(2.5)
    assert result["score_type"] == "decision_score"
