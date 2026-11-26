"""Task 12A classifier verification-contract tests that always run.

A tiny deterministic bundle is created in a temporary directory at test time.
It is never added to the contribution, is not a production model, and exists
only to exercise the real SHA-256 verification, joblib loading, bundle
validation, and inference code paths when the excluded research artifact is
absent. No fake prediction is injected into the application or service.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC

from app.main import app
from app.services import http_payload_classifier_service as service
import classifier_artifact_policy as policy

PREDICT_ENDPOINT = "/api/v1/security/payload-classifier/predict"
_FIXTURE_MODEL_NAME = "task12a-test-linear-svc"
client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_classifier_cache():
    service._reset_cache()
    try:
        yield
    finally:
        service._reset_cache()


def _build_fixture_bundle() -> dict:
    texts = [
        "<script>alert(1)</script>",
        "' OR 1=1 --",
        "hello world",
        "please show the daily report",
    ]
    labels = [1, 1, 0, 0]
    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2))
    features = vectorizer.fit_transform(texts)
    model = LinearSVC(C=1.0, max_iter=1000, random_state=0)
    model.fit(features, np.asarray(labels))
    return {
        "format_version": service.FORMAT_VERSION,
        "model": model,
        "vectorizer": vectorizer,
        "scaler": None,
        "feature_mode": service.FEATURE_MODE_TEXT,
        "selected_model_name": _FIXTURE_MODEL_NAME,
        "decision_threshold": service.DECISION_BOUNDARY,
        "labels": service._LABELS,
        "seed": 0,
        "dataset_sha256": "0" * 64,
    }


def _write_fixture_bundle(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / service._ARTIFACT_FILENAME
    joblib.dump(_build_fixture_bundle(), path)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _use_verified_fixture(monkeypatch, tmp_path: Path) -> str:
    _, digest = _write_fixture_bundle(tmp_path)
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path)
    monkeypatch.setattr(service, "ARTIFACT_SHA256", digest)
    return digest


def test_required_artifact_mode_fails_when_bundle_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(
        policy,
        "CLASSIFIER_ARTIFACT_PATH",
        tmp_path / "missing-classifier-bundle.joblib",
    )

    with pytest.raises(
        policy.ClassifierArtifactRequiredError,
        match="--require-classifier-artifact",
    ):
        policy.validate_required_classifier_artifact(True)

    # Ordinary artifact-free development remains non-fatal by default.
    policy.validate_required_classifier_artifact(False)


def test_generated_fixture_exercises_real_verified_loading_and_inference(monkeypatch, tmp_path):
    digest = _use_verified_fixture(monkeypatch, tmp_path)

    response = service.predict_payloads(
        ["<script>alert(1)</script>", "please show the daily report"]
    )

    assert response.artifact_sha256 == digest
    assert response.model_name == _FIXTURE_MODEL_NAME
    assert response.feature_mode == service.FEATURE_MODE_TEXT
    assert response.advisory_only is True
    assert len(response.results) == 2
    for index, result in enumerate(response.results):
        assert result.index == index
        assert service._LABELS[result.label_int] == result.label
        assert np.isfinite(result.decision_score)
        assert result.decision_threshold == service.DECISION_BOUNDARY
        assert result.score_type == service.SCORE_TYPE_DECISION


def test_generated_fixture_hash_mismatch_is_rejected(monkeypatch, tmp_path):
    path, digest = _write_fixture_bundle(tmp_path)
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path)
    monkeypatch.setattr(service, "ARTIFACT_SHA256", digest)
    path.write_bytes(path.read_bytes() + b"\n# tampered")

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads(["admin"])

    assert str(exc_info.value) == service._UNAVAILABLE_MESSAGE


def test_api_returns_prediction_with_generated_verified_fixture(monkeypatch, tmp_path):
    digest = _use_verified_fixture(monkeypatch, tmp_path)

    response = client.post(PREDICT_ENDPOINT, json={"payloads": ["hello world"]})

    assert response.status_code == 200
    body = response.json()
    assert body["artifact_sha256"] == digest
    assert body["advisory_only"] is True
    assert len(body["results"]) == 1
    assert body["results"][0]["index"] == 0


def test_generated_fixture_keeps_invalid_input_distinct_from_unavailable(monkeypatch, tmp_path):
    _use_verified_fixture(monkeypatch, tmp_path)

    response = client.post(PREDICT_ENDPOINT, json={"payloads": []})

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}
