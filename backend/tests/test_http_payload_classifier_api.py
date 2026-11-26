"""Focused API tests for the advisory HTTP payload classifier endpoints.

No PostgreSQL connection, real API-key secret, or enforcement behaviour is
involved. Authentication is exercised against in-memory SQLite where needed.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routes import http_payload_classifier as payload_route
from app.core.config import settings
from app.core.security import (
    create_access_token,
    require_analyst_or_api_key,
    require_api_key,
)
from app.main import app
from app.services import http_payload_classifier_service as payload_service
from app.services.http_payload_classifier_service import (
    HttpPayloadClassifierUnavailableError,
)
from classifier_artifact_policy import CLASSIFIER_ARTIFACT_SKIP_REASON

PREDICT_ENDPOINT = "/api/v1/security/payload-classifier/predict"
METADATA_ENDPOINT = "/api/v1/security/payload-classifier/metadata"
GENERIC_422 = "Invalid request."
GENERIC_503 = "Payload classifier model is not available."
SECRET = "api_key=SUPER_SECRET_VALUE_12345"
DATASET_SHA256 = "b67bbb66ac3e280584741c3ad234eb0c0f5ef6bd57017031afb295c7651fb7de"
_CLASSIFIER_ARTIFACT = (
    Path(__file__).resolve().parents[2]
    / "research"
    / "models"
    / "http_payload_classifier"
    / "v1"
    / "model_bundle.joblib"
)

# These tests exercise the supported artifact-backed behaviour. The
# missing-artifact contract is covered independently by
# test_task11_classifier_artifact_regression.py, which never assumes the
# excluded research artifact is present in a contribution.
pytestmark = pytest.mark.skipif(
    not _CLASSIFIER_ARTIFACT.is_file(),
    reason=CLASSIFIER_ARTIFACT_SKIP_REASON,
)
FORBIDDEN_FIELDS = {
    "confidence",
    "probability",
    "risk_score",
    "bot_risk_score",
    "severity",
}

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_request_logging(monkeypatch):
    """Keep request-logging middleware out of the configured database."""
    monkeypatch.setattr(
        "app.utils.middleware.save_traffic_log",
        lambda **kwargs: True,
    )


@pytest.fixture
def real_authentication():
    """Temporarily remove conftest auth overrides for real RBAC assertions."""
    dependencies = (require_api_key, require_analyst_or_api_key)
    previous = {
        dependency: app.dependency_overrides.get(dependency)
        for dependency in dependencies
    }
    for dependency in dependencies:
        app.dependency_overrides.pop(dependency, None)
    try:
        yield
    finally:
        for dependency, override in previous.items():
            if override is None:
                app.dependency_overrides.pop(dependency, None)
            else:
                app.dependency_overrides[dependency] = override


def _post(payloads, *, headers=None, **extra):
    return client.post(
        PREDICT_ENDPOINT,
        json={"payloads": payloads, **extra},
        headers=headers,
    )


def _assert_forbidden_fields_absent(node):
    if isinstance(node, dict):
        assert FORBIDDEN_FIELDS.isdisjoint(node)
        for value in node.values():
            _assert_forbidden_fields_absent(value)
    elif isinstance(node, list):
        for value in node:
            _assert_forbidden_fields_absent(value)


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------


def test_authorized_analyst_access(real_authentication, testing_session_factory):
    token = create_access_token(
        "payload-analyst@example.test", extra_claims={"role": "analyst"}
    )
    response = _post(["admin"], headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert len(response.json()["results"]) == 1


def test_authorized_admin_access(real_authentication, testing_session_factory):
    token = create_access_token(
        "payload-admin@example.test", extra_claims={"role": "admin"}
    )
    response = _post(["admin"], headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert len(response.json()["results"]) == 1


def test_api_key_access(real_authentication, testing_session_factory, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "payload-classifier-unit-test-key")

    response = _post(
        ["admin"], headers={"X-API-Key": "payload-classifier-unit-test-key"}
    )

    assert response.status_code == 200
    assert len(response.json()["results"]) == 1


def test_unauthenticated_access(real_authentication, testing_session_factory, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "payload-classifier-unit-test-key")

    missing = _post(["admin"])
    invalid_key = _post(["admin"], headers={"X-API-Key": "wrong-key"})
    invalid_token = _post(
        ["admin"], headers={"Authorization": "Bearer not-a-jwt"}
    )

    assert missing.status_code == 401
    assert invalid_key.status_code == 401
    assert invalid_token.status_code == 401


def test_viewer_access_is_forbidden(real_authentication, testing_session_factory):
    token = create_access_token(
        "payload-viewer@example.test", extra_claims={"role": "viewer"}
    )
    response = _post(["admin"], headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_missing_api_key_configuration_preserves_existing_behaviour(
    real_authentication, testing_session_factory, monkeypatch
):
    monkeypatch.setattr(settings, "API_KEY", "")

    response = _post(["admin"])

    assert response.status_code == 503
    assert response.json()["detail"] == "API authentication is not configured"


# ---------------------------------------------------------------------------
# Prediction behaviour
# ---------------------------------------------------------------------------


def test_valid_single_payload_prediction():
    response = _post(["admin"])

    assert response.status_code == 200
    body = response.json()
    assert body["model_name"] == "tfidf_char_svm"
    assert body["feature_mode"] == "text"
    assert body["artifact_sha256"] == payload_service.ARTIFACT_SHA256
    assert body["advisory_only"] is True
    assert isinstance(body["interpretation"], str)
    assert body["limitations"]
    assert len(body["results"]) == 1

    result = body["results"][0]
    assert result["index"] == 0
    assert result["label"] in {"benign", "anomalous"}
    assert result["label_int"] in {0, 1}
    assert isinstance(result["decision_score"], float)
    assert result["decision_threshold"] == 0.0
    assert result["score_type"] == "decision_score"
    assert result["payload_length"] == len("admin")
    assert result["low_margin"] is (abs(result["decision_score"]) < 1.0)


def test_valid_multi_payload_predictions_are_independent():
    payloads = ["admin", "falset", "union select password", "1' OR '1'='1"]

    response = _post(payloads)

    assert response.status_code == 200
    results = response.json()["results"]
    assert [result["index"] for result in results] == list(range(len(payloads)))
    for index, payload in enumerate(payloads):
        single = _post([payload]).json()["results"][0]
        assert results[index]["decision_score"] == single["decision_score"]
        assert results[index]["label"] == single["label"]
        assert results[index]["payload_length"] == len(payload)


def test_empty_batch_rejection():
    response = _post([])

    assert response.status_code == 422
    assert response.json() == {"detail": GENERIC_422}


def test_more_than_fifty_payloads_rejection():
    response = _post(["admin"] * 51)

    assert response.status_code == 422
    assert response.json() == {"detail": GENERIC_422}


def test_oversized_single_payload_rejection():
    response = _post(["x" * 10_001])

    assert response.status_code == 422
    assert response.json() == {"detail": GENERIC_422}


def test_oversized_total_batch_rejection():
    response = _post(["x" * 10_000] * 11)

    assert response.status_code == 422
    assert response.json() == {"detail": GENERIC_422}


@pytest.mark.parametrize(
    "raw_body",
    [
        b"",
        b"{",
        b"not json at all",
        b"[]",
        b'"admin"',
        b'{"payloads": "admin"}',
        b'{"payloads": [123]}',
        b'{"payloads": ["admin"], "unknown_field": 1}',
        b'{"payloads": ["admin"], "include_payload_echo": "maybe"}',
        b'{"payloads": ["admin"], "include_payload_echo": "yes"}',
        b'{"payloads": ["admin"], "include_payload_echo": "true"}',
        b'{"payloads": ["admin"], "include_payload_echo": "false"}',
    ],
)
def test_malformed_request_bodies_return_generic_422(raw_body):
    response = client.post(
        PREDICT_ENDPOINT,
        content=raw_body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": GENERIC_422}


def test_generic_422_never_leaks_payloads_or_validation_objects(caplog):
    with caplog.at_level(logging.DEBUG):
        response = _post([SECRET, 123])

    assert response.status_code == 422
    body = response.json()
    assert body == {"detail": GENERIC_422}
    assert SECRET not in response.text
    assert "api_key" not in response.text.lower()
    for raw_key in ("errors", "input", "loc", "traceback", "ctx"):
        assert raw_key not in body
    assert SECRET not in caplog.text


@pytest.mark.parametrize("echo_value", ["yes", "true", "false"])
def test_non_boolean_echo_values_return_generic_sanitized_422(echo_value, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            PREDICT_ENDPOINT,
            json={"payloads": [SECRET], "include_payload_echo": echo_value},
        )

    assert response.status_code == 422
    body = response.json()
    assert body == {"detail": GENERIC_422}
    assert SECRET not in response.text
    assert str(echo_value) not in response.text
    assert "api_key" not in response.text.lower()
    for raw_key in ("errors", "input", "loc", "traceback", "ctx"):
        assert raw_key not in body
    assert SECRET not in caplog.text


def test_model_unavailable_returns_generic_503(monkeypatch):
    def _unavailable(*args, **kwargs):
        raise HttpPayloadClassifierUnavailableError()

    monkeypatch.setattr(payload_route, "predict_payloads", _unavailable)

    response = _post(["admin"])

    assert response.status_code == 503
    assert response.json() == {"detail": GENERIC_503}
    assert "payload-classifier" not in response.text.lower()
    assert "Traceback" not in response.text


def test_unexpected_exception_returns_safe_response(monkeypatch):
    def _broken(*args, **kwargs):
        raise RuntimeError(f"C:\\internal\\path\\model.joblib {SECRET}")

    monkeypatch.setattr(payload_route, "predict_payloads", _broken)

    response = _post([SECRET])

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error."}
    for leaked in (SECRET, "internal", "model.joblib", "Traceback", "RuntimeError"):
        assert leaked not in response.text


def test_response_contains_no_forbidden_risk_or_probability_fields():
    response = _post(["admin"])

    assert response.status_code == 200
    _assert_forbidden_fields_absent(response.json())
    assert set(response.json()) == {
        "model_name",
        "feature_mode",
        "artifact_sha256",
        "advisory_only",
        "interpretation",
        "limitations",
        "results",
    }


def test_no_payload_echo_by_default_and_opt_in_echo_is_explicit():
    default_response = _post([SECRET])

    assert default_response.status_code == 200
    assert SECRET not in default_response.text
    assert all(
        result["payload_echo"] is None
        for result in default_response.json()["results"]
    )

    opted_in = _post([SECRET], include_payload_echo=True)
    assert opted_in.status_code == 200
    assert opted_in.json()["results"][0]["payload_echo"] == SECRET


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_metadata_endpoint_response():
    response = client.get(METADATA_ENDPOINT)

    assert response.status_code == 200
    body = response.json()
    assert body["model_name"] == "tfidf_char_svm"
    assert body["feature_mode"] == "text"
    assert body["artifact_sha256"] == payload_service.ARTIFACT_SHA256
    assert body["dataset"]
    assert re.fullmatch(r"[0-9a-f]{64}", body["dataset_sha256"])
    assert body["advisory_only"] is True
    assert isinstance(body["limitations"], list) and body["limitations"]


def test_metadata_does_not_expose_paths_or_secrets():
    response = client.get(METADATA_ENDPOINT)

    assert response.status_code == 200
    text = response.text
    for marker in (
        "C:\\",
        "\\research",
        "/research",
        "model_bundle",
        ".joblib",
        ".env",
        "postgres",
        "API_KEY",
        "password",
        "Traceback",
    ):
        assert marker.lower() not in text.lower()
    assert set(re.findall(r"\b[0-9a-f]{64}\b", text)) == {
        payload_service.ARTIFACT_SHA256,
        DATASET_SHA256,
    }


# ---------------------------------------------------------------------------
# Isolation from existing routes
# ---------------------------------------------------------------------------


def test_headers_query_parameters_and_logs_are_never_auto_classified():
    response = client.post(
        PREDICT_ENDPOINT,
        json={"payloads": ["admin"]},
        headers={"X-Payload": SECRET},
        params={"payload": SECRET},
    )

    assert response.status_code == 200
    assert SECRET not in response.text
    assert len(response.json()["results"]) == 1


def test_prediction_creates_no_decision_audit_or_traffic_records(
    testing_session_factory,
):
    from app.models.mitigation import MitigationAuditEvent, MitigationDecision
    from app.models.traffic import APITrafficLog

    def _counts():
        session = testing_session_factory()
        try:
            return (
                session.query(MitigationDecision).count(),
                session.query(MitigationAuditEvent).count(),
                session.query(APITrafficLog).count(),
            )
        finally:
            session.close()

    before = _counts()
    response = _post(["admin"])
    after = _counts()

    assert response.status_code == 200
    assert before == (0, 0, 0)
    assert after == before


def test_existing_bot_and_mitigation_endpoints_remain_unaffected(
    testing_session_factory,
):
    paths = client.get("/api/v1/openapi.json").json()["paths"]
    for endpoint in (
        PREDICT_ENDPOINT,
        METADATA_ENDPOINT,
        "/api/v1/security/bot/analyze",
        "/api/v1/security/mitigation/analyze",
    ):
        assert endpoint in paths

    bot_response = client.get("/api/v1/security/bot/analyze")
    assert bot_response.status_code == 200
    assert bot_response.json()["results"] == []
