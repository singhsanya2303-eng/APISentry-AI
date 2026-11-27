"""Focused regression tests for the Stage 1 bot detection API."""

import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import (
    create_access_token,
    require_analyst_or_api_key,
    require_api_key,
)
from app.main import app
from app.models.traffic import APITrafficLog

ENDPOINT = "/api/v1/security/bot/analyze"
FIXED_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)

OPAQUE_REQUEST_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def prevent_middleware_traffic_persistence(monkeypatch):
    """Keep API tests on isolated SQLite; do not write via middleware SessionLocal."""
    monkeypatch.setattr(
        "app.utils.middleware.save_traffic_log",
        lambda **kwargs: True,
    )


@pytest.fixture
def real_authentication():
    """Temporarily remove conftest auth overrides for auth/RBAC assertions."""
    dependencies = (require_api_key, require_analyst_or_api_key)
    previous = {dependency: app.dependency_overrides.get(dependency) for dependency in dependencies}
    for dependency in dependencies:
        app.dependency_overrides.pop(dependency, None)
    yield
    for dependency, override in previous.items():
        if override is None:
            app.dependency_overrides.pop(dependency, None)
        else:
            app.dependency_overrides[dependency] = override


def _log(
    request_id,
    client_ip,
    *,
    seconds_ago=0,
    method="GET",
    path="/api/v1/users",
    status_code=200,
    user_agent="Browser/1.0",
):
    return APITrafficLog(
        request_id=request_id,
        timestamp=FIXED_NOW - timedelta(seconds=seconds_ago),
        method=method,
        path=path,
        query_params={},
        client_ip=client_ip,
        user_agent=user_agent,
        status_code=status_code,
        response_time_ms=10.0,
    )


def _seed(session_factory, logs):
    session = session_factory()
    try:
        session.add_all(logs)
        session.commit()
    finally:
        session.close()


def _assert_no_secret_material(response):
    body = response.text.lower()
    for forbidden in ("bearer ", "authorization:", "password", "api_key", "secret"):
        assert forbidden not in body


def test_endpoint_exists_with_empty_traffic(testing_session_factory):
    response = client.get(ENDPOINT)

    assert response.status_code == 200
    data = response.json()
    assert data["results"] == []
    assert data["total_clients"] == 0
    assert data["total_events_analyzed"] == 0
    assert data["analysis_window_start"] is None
    assert data["limits"]["max_records"] == 1000
    assert data["summary"]["summary"]


def test_response_contains_structured_reasons_and_evidence(testing_session_factory):
    logs = [
        _log(
            f"api-auth-{index}",
            "198.51.100.10",
            seconds_ago=300 - (index * 30),
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
        )
        for index in range(6)
    ]
    logs.extend(
        _log(f"api-high-{index}", "198.51.100.20", seconds_ago=59 - index, path="/api/v1/orders")
        for index in range(60)
    )
    _seed(testing_session_factory, logs)

    response = client.get(ENDPOINT)
    assert response.status_code == 200
    _assert_no_secret_material(response)

    data = response.json()
    assert data["total_clients"] == 2
    assert data["total_events_analyzed"] == 66
    assert data["limits"]["records_analyzed"] == 66
    assert data["analysis_window_start"] is not None
    assert data["analysis_window_end"] is not None
    assert data["summary"]["suspicious_automation_candidates"] == 1
    assert data["summary"]["benign_automation_candidates"] == 1

    auth_result = next(
        result for result in data["results"] if result["client_ip"] == "198.51.100.10"
    )
    reason = next(
        item for item in auth_result["reasons"]
        if item["code"] == "REPEATED_AUTHENTICATION_FAILURES"
    )
    assert reason["category"] == "authentication"
    assert reason["severity"] == "high"
    assert reason["evidence_count"] >= 5
    assert reason["score_contribution"] > 0
    assert len(reason["request_ids"]) >= 5
    assert all(OPAQUE_REQUEST_ID_RE.fullmatch(value) for value in reason["request_ids"])
    assert "api-auth-0" not in reason["request_ids"]

    evidence = next(
        item for item in auth_result["evidence_references"]
        if item["source"] == "REPEATED_AUTHENTICATION_FAILURES"
    )
    assert evidence["request_id"] in reason["request_ids"]
    assert evidence["observed_at"] is not None

    assert 0.0 <= auth_result["bot_risk_score"] <= 100.0
    assert auth_result["classification"] == "automation_suspicious"
    assert "behavioral_risk" in auth_result
    assert auth_result["behavioral_risk"] is None


def test_behavioral_risk_context_is_separately_labelled(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log("ctx-1", "198.51.100.30", seconds_ago=60, path="/api/v1/users/1"),
            _log("ctx-2", "198.51.100.30", seconds_ago=30, path="/api/v1/users/2"),
            _log("ctx-3", "198.51.100.30", seconds_ago=10, path="/api/v1/users/3"),
        ],
    )

    response = client.get(ENDPOINT, params={"include_behavioral_risk": "true"})

    assert response.status_code == 200
    result = response.json()["results"][0]
    context = result["behavioral_risk"]
    assert context is not None
    assert context["label"] == "behavioral_risk_score"
    assert context["source"] == "behavior_analysis_service"
    assert 0.0 <= context["risk_score"] <= 100.0
    assert "bot_risk_score" not in context
    assert "not used to calculate bot_risk_score" in context["note"]


def test_query_validation_preserves_existing_conventions(testing_session_factory):
    bad_cases = [
        {"page": 0},
        {"page_size": 501},
        {"status_code": 700},
        {
            "start_time": "2026-01-15T13:00:00Z",
            "end_time": "2026-01-15T12:00:00Z",
        },
    ]
    for params in bad_cases:
        response = client.get(ENDPOINT, params=params)
        assert response.status_code == 422, params


def test_missing_and_invalid_api_keys_are_rejected(testing_session_factory, real_authentication, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "bot-unit-test-key")

    missing = client.get(ENDPOINT)
    invalid = client.get(ENDPOINT, headers={"X-API-Key": "wrong-key"})

    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_valid_api_key_is_accepted(testing_session_factory, real_authentication, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "bot-unit-test-key")

    response = client.get(ENDPOINT, headers={"X-API-Key": "bot-unit-test-key"})

    assert response.status_code == 200
    assert response.json()["results"] == []


def test_jwt_rbac_is_preserved(testing_session_factory, real_authentication):
    analyst_token = create_access_token(
        "bot-analyst@example.local", extra_claims={"role": "analyst"}
    )
    viewer_token = create_access_token(
        "bot-viewer@example.local", extra_claims={"role": "viewer"}
    )

    analyst_response = client.get(
        ENDPOINT, headers={"Authorization": f"Bearer {analyst_token}"}
    )
    viewer_response = client.get(
        ENDPOINT, headers={"Authorization": f"Bearer {viewer_token}"}
    )
    invalid_response = client.get(
        ENDPOINT, headers={"Authorization": "Bearer not-a-jwt"}
    )

    assert analyst_response.status_code == 200
    assert viewer_response.status_code == 403
    assert invalid_response.status_code == 401


def test_hostile_request_id_is_redacted(testing_session_factory):
    hostile_id = "api_key=secret"
    _seed(
        testing_session_factory,
        [
            _log(
                hostile_id if index == 0 else f"hostile-{index}",
                "198.51.100.40",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(6)
        ],
    )

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    _assert_no_secret_material(response)
    assert hostile_id not in response.text
    assert "api_key" not in response.text.lower()
    data = response.json()
    emitted_ids = [
        request_id
        for result in data["results"]
        for reason in result["reasons"]
        for request_id in reason["request_ids"]
    ]
    assert emitted_ids
    assert all(OPAQUE_REQUEST_ID_RE.fullmatch(request_id) for request_id in emitted_ids)


def test_brute_force_override_query_param_controls_classification(
    testing_session_factory,
):
    _seed(
        testing_session_factory,
        [
            _log(
                f"api-override-{index}",
                "198.51.100.50",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(6)
        ],
    )

    enabled = client.get(ENDPOINT)
    disabled = client.get(ENDPOINT, params={"brute_force_override_enabled": "false"})

    assert enabled.status_code == 200
    assert disabled.status_code == 200
    enabled_result = enabled.json()["results"][0]
    disabled_result = disabled.json()["results"][0]
    assert enabled_result["classification"] == "automation_suspicious"
    assert disabled_result["classification"] != "automation_suspicious"
    assert any(
        reason["code"] == "BRUTE_FORCE_OVERRIDE"
        for reason in enabled_result["reasons"]
    )
    assert all(
        reason["code"] != "BRUTE_FORCE_OVERRIDE"
        for reason in disabled_result["reasons"]
    )


def test_secret_like_request_ids_are_absent_from_api_response(testing_session_factory):
    originals = [
        "api_key:secret",
        "Bearer abc123",
        "password.secret",
        "123e4567-e89b-12d3-a456-426614174000",
    ]
    _seed(
        testing_session_factory,
        [
            _log(
                original,
                "198.51.100.60",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index, original in enumerate(originals)
        ],
    )

    params = {"brute_force_failure_threshold": "2"}
    first = client.get(ENDPOINT, params=params)
    second = client.get(ENDPOINT, params=params)

    assert first.status_code == 200
    assert second.status_code == 200
    for original in originals:
        assert original not in first.text
        assert original.lower() not in first.text.lower()

    def _brute_request_ids(response):
        return [
            request_id
            for result in response.json()["results"]
            for reason in result["reasons"]
            if reason["code"] == "REPEATED_AUTHENTICATION_FAILURES"
            for request_id in reason["request_ids"]
        ]

    emitted = _brute_request_ids(first)
    assert len(emitted) == len(originals)
    assert len(set(emitted)) == len(originals)
    assert all(OPAQUE_REQUEST_ID_RE.fullmatch(value) for value in emitted)
    assert _brute_request_ids(second) == emitted
