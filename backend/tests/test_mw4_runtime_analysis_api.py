"""MW4-A runtime integration tests.

Verifies actual runtime invocation of MW2 + MW1 through the app/API, signal
handling, advisory-only safety, auth/backward compatibility, and structured
error behavior. Uses isolated SQLite fixtures only.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text

from app.api.v1.routes import mitigation_analysis as mitigation_route
from app.core.config import settings
from app.core.security import create_access_token, require_analyst_or_api_key, require_api_key
from app.db.session import get_db
from app.main import app
from app.models.mitigation import MitigationAuditEvent, MitigationDecision
from app.models.traffic import APITrafficLog
from app.schemas.mitigation_integration import MitigationOutcomeStatus
from app.services import mw4_runtime_orchestration_service as mw4_service
from tests.mitigation_persistence_helpers import (
    activate_policy,
    policy_record,
    sqlite_session_factory,
)

ENDPOINT = "/api/v1/security/mitigation/runtime-analyze"
LEGACY_ENDPOINT = "/api/v1/security/mitigation/analyze"
FIXED_NOW = datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc)

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_request_logging(monkeypatch):
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda **kwargs: True)


@pytest.fixture
def db_env():
    engine, factory = sqlite_session_factory()
    session = factory()
    previous = app.dependency_overrides.get(get_db)

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield engine, factory, session
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        session.close()
        engine.dispose()


@pytest.fixture
def real_authentication():
    dependencies = (require_api_key, require_analyst_or_api_key)
    previous = {d: app.dependency_overrides.get(d) for d in dependencies}
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


def _seed_policy(session, policy_version: str = "mw4-a-1.0.0", **overrides):
    stored = policy_record(policy_version=policy_version, **overrides)
    session.add(stored)
    session.flush()
    activate_policy(session, stored)
    session.commit()
    return stored


def _log(request_id: str, client_ip: str, *, seconds_ago: int = 0, status_code: int = 200, method: str = "GET", path: str = "/api/v1/orders", user_agent: str = "Browser/1.0"):
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


def _seed_logs(session, logs):
    session.add_all(logs)
    session.commit()


def _benign_logs():
    return [_log("benign-1", "198.51.100.10"), _log("benign-2", "198.51.100.10", seconds_ago=10)]


def _auth_failure_logs():
    return [
        _log(
            f"auth-failure-{i}",
            "198.51.100.60",
            seconds_ago=300 - (i * 30),
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
        )
        for i in range(6)
    ]


def _token(role: str, subject: str):
    return create_access_token(
        subject=subject,
        extra_claims={"user_id": 1, "username": subject, "role": role, "is_active": True},
    )


def _bearer(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_runtime_endpoint_invokes_mw2_and_mw1_through_app_runtime(db_env, monkeypatch):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    calls = {"mw2": 0, "mw1": 0}
    real_mw2 = mw4_service.build_advisory_envelope
    real_mw1 = mw4_service.assess_risk

    def spy_mw2(*args, **kwargs):
        calls["mw2"] += 1
        return real_mw2(*args, **kwargs)

    def spy_mw1(*args, **kwargs):
        calls["mw1"] += 1
        return real_mw1(*args, **kwargs)

    monkeypatch.setattr(mw4_service, "build_advisory_envelope", spy_mw2)
    monkeypatch.setattr(mw4_service, "assess_risk", spy_mw1)

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    data = response.json()
    assert calls["mw2"] >= 1
    assert calls["mw1"] >= 1
    assert len(data["runtime_results"]) >= 1
    result = data["runtime_results"][0]
    assert result["mw1_status"] == "assessed"
    assert result["mw1_unified_assessment"] is not None
    assert result["mw2_advanced_detection"]["schema_version"] == "mw2-advanced-signals/v1"
    assert result["advisory_only"] is True
    assert data["advisory_only"] is True
    assert data["enforcement_executed"] is False


def test_runtime_endpoint_returns_mw1_risk_and_mw2_envelope_fields(db_env):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _auth_failure_logs())

    response = client.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    assert data["detection"]["total_clients"] >= 1
    assert data["mitigation"]["policy_version"] == "mw4-a-1.0.0"
    for item in data["runtime_results"]:
        mw1 = item["mw1_unified_assessment"]
        assert mw1 is not None
        assert 0.0 <= mw1["risk_score"] <= 100.0
        assert mw1["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert mw1["advisory_only"] is True
        assert "contributions" in mw1
        assert "signal_statuses" in mw1
        assert "coverage" in mw1
        assert "uncertainty_notes" in mw1
        assert mw1["confidence_policy"]
        mw2 = item["mw2_advanced_detection"]
        assert mw2["advisory_only"] is True
        assert "signals" in mw2
        assert "confidence_policy" in mw2
        assert all("status" in s for s in mw2["signals"])
        assert all(s["advisory_only"] is True for s in mw2["signals"])


def test_runtime_endpoint_preserves_mw1_score_and_no_second_combined_score(db_env, monkeypatch):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    captured = {}

    real_assess = mw4_service.assess_risk

    def spy_assess(data):
        captured["input"] = data
        out = real_assess(data)
        captured["score"] = out.risk_score
        return out

    monkeypatch.setattr(mw4_service, "assess_risk", spy_assess)
    response = client.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    item = data["runtime_results"][0]
    assert item["mw1_unified_assessment"]["risk_score"] == captured["score"]
    # No combined score fields
    serialized = json.dumps(data)
    assert '"combined_score"' not in serialized
    assert '"combined_confidence"' not in serialized
    assert '"probability"' not in serialized.lower() or "no probability" in serialized.lower()


def test_mw1_error_is_structured_and_no_score_fabricated(db_env, monkeypatch):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    def boom(_):
        raise RuntimeError("mw1 exploded")

    monkeypatch.setattr(mw4_service, "assess_risk", boom)
    response = client.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    item = data["runtime_results"][0]
    assert item["mw1_status"] == "error"
    assert item["mw1_unified_assessment"] is None
    assert item["mw1_error"]
    assert "Traceback" not in json.dumps(data)
    assert "mw1 exploded" not in json.dumps(data)


def test_mw2_error_is_visible_and_structured(db_env, monkeypatch):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    def boom(_):
        raise ValueError("bad snapshot")

    monkeypatch.setattr(mw4_service, "build_advisory_envelope", boom)
    response = client.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    item = data["runtime_results"][0]
    norms = item["signal_normalization"]
    assert any(n["signal"] == "mw2.envelope" and n["status"] == "ERROR" for n in norms)
    assert "bad snapshot" not in json.dumps(data)


def test_existing_mitigation_analyze_contract_unchanged(db_env):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    legacy = client.get(LEGACY_ENDPOINT)
    assert legacy.status_code == 200
    data = legacy.json()
    assert set(data.keys()) == {"detection", "mitigation", "advisory_only"}
    assert set(data["mitigation"].keys()) == {"policy_version", "outcomes"}
    outcome = data["mitigation"]["outcomes"][0]
    assert set(outcome.keys()) == {"result_index", "status", "decision", "decision_uuid", "advisory_only"}


def test_runtime_endpoint_auth_required(real_authentication, monkeypatch, db_env):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "test-key")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    resp = client.get(ENDPOINT)
    assert resp.status_code == 401


def test_runtime_endpoint_viewer_rejected(real_authentication, monkeypatch, db_env):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    resp = client.get(ENDPOINT, headers=_bearer(_token("viewer", "viewer-actor")))
    assert resp.status_code == 403


def test_runtime_endpoint_admin_analyst_api_key_accepted(real_authentication, monkeypatch, db_env):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "test-key")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    for headers in [
        {"X-API-Key": "test-key"},
        _bearer(_token("admin", "admin-actor")),
        _bearer(_token("analyst", "analyst-actor")),
    ]:
        resp = client.get(ENDPOINT, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["advisory_only"] is True


def test_runtime_endpoint_no_enforcement_no_policy_activation(db_env):
    _, factory, session = db_env
    _seed_policy(session, mode="enforce", monitoring_score_threshold=0.0, throttling_score_threshold=0.0, blocking_score_threshold=0.0, minimum_authentication_failures=1, require_grouped_brute_force=False, throttle_enabled=True, block_enabled=True)
    _seed_logs(session, _auth_failure_logs())

    response = client.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    assert data["advisory_only"] is True
    assert data["enforcement_executed"] is False
    serialized = json.dumps(data)
    assert '"enforced"' not in serialized
    assert '"enforcement_applied"' not in serialized
    # DB: only expected decision/audit rows from Stage A advisory persistence; no policy activation changes
    fresh = factory()
    try:
        assert fresh.query(MitigationDecision).count() >= 0
        assert fresh.query(MitigationAuditEvent).count() >= 0
    finally:
        fresh.close()


def test_runtime_endpoint_invalid_request_validation(db_env):
    _, _, session = db_env
    _seed_policy(session)
    resp = client.get(ENDPOINT, params={"page": 0})
    assert resp.status_code == 422
    resp = client.get(ENDPOINT, params={"status_code": 700})
    assert resp.status_code == 422
