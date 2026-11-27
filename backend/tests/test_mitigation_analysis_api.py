"""Stage 2C Phase 4 Stage B protected mitigation analysis API tests.

All database work is isolated in-memory SQLite. No PostgreSQL connection,
migration, or enforcement behavior is involved.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect as sa_inspect, text as sa_text

from app.api.v1.routes import mitigation_analysis as mitigation_route
from app.core.config import settings
from app.core.security import (
    create_access_token,
    require_analyst_or_api_key,
    require_api_key,
)
from app.db.session import get_db
from app.main import app
from app.models.mitigation import (
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicyMode as StoredPolicyMode,
)
from app.models.traffic import APITrafficLog
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationOutcomeStatus,
)
from app.services import mitigation_audit_integration_service as audit_service
from app.services import mitigation_integration_service as integration_service
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    DecisionPersistenceError,
)
from tests.mitigation_persistence_helpers import (
    activate_policy,
    policy_record,
    sqlite_session_factory,
    unique_uuid5,
)

ENDPOINT = "/api/v1/security/mitigation/analyze"
BOT_ENDPOINT = "/api/v1/security/bot/analyze"
FIXED_NOW = datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc)
AUDIT_FAILURE_SENTINELS = (
    "alice@example.test",
    "203.0.113.99",
    "Bearer raw-jwt-token",
    "api-key-secret",
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_request_logging(monkeypatch):
    """Keep middleware traffic logging out of the configured database."""
    monkeypatch.setattr(
        "app.utils.middleware.save_traffic_log",
        lambda **kwargs: True,
    )


@pytest.fixture
def db_env():
    """Provide one isolated SQLite session as both route and auth dependency DB."""
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


def _seed_policy(session, policy_version: str = "stage-a-b-1.0.0", **overrides):
    stored = policy_record(policy_version=policy_version, **overrides)
    session.add(stored)
    session.flush()
    activate_policy(session, stored)
    session.commit()
    return stored


def _log(
    request_id: str,
    client_ip: str,
    *,
    seconds_ago: int = 0,
    method: str = "GET",
    path: str = "/api/v1/orders",
    status_code: int = 200,
    user_agent: str = "Browser/1.0",
    query_params: dict | None = None,
):
    return APITrafficLog(
        request_id=request_id,
        timestamp=FIXED_NOW - timedelta(seconds=seconds_ago),
        method=method,
        path=path,
        query_params=query_params or {},
        client_ip=client_ip,
        user_agent=user_agent,
        status_code=status_code,
        response_time_ms=10.0,
    )


def _seed_logs(session, logs):
    session.add_all(logs)
    session.commit()


def _fresh_counts(factory):
    """Count committed rows using a new session, not the route's session."""
    session = factory()
    try:
        return (
            session.query(MitigationDecision).count(),
            session.query(MitigationAuditEvent).count(),
        )
    finally:
        session.close()


def _force_audit_insert_failure(session):
    """Force a real SQLite audit insert failure with sensitive-looking error text."""
    session.execute(
        sa_text(
            """
            CREATE TRIGGER c2_reject_audit_insert
            BEFORE INSERT ON mitigation_audit_events
            BEGIN
                SELECT RAISE(ABORT, 'alice@example.test 203.0.113.99 Bearer raw-jwt-token api-key-secret SELECT * FROM mitigation_audit_events Traceback');
            END
            """
        )
    )
    session.commit()


def _assert_no_sensitive_values_in_audit_columns(stored, sensitive_values):
    """Inspect real persisted audit column values, not ``repr(stored)``."""
    columns = {
        name: sa_inspect(stored).attrs[name].value
        for name in (
            "details",
            "event_hash",
            "entity_identifier",
            "actor_hash",
            "actor_role",
        )
    }
    for name, value in columns.items():
        rendered = (
            json.dumps(value, sort_keys=True)
            if isinstance(value, dict)
            else ("" if value is None else str(value))
        )
        for sensitive in sensitive_values:
            assert sensitive not in rendered, (name, sensitive)
    return columns


def _benign_logs():
    return [
        _log("benign-1", "198.51.100.10"),
        _log("benign-2", "198.51.100.10", seconds_ago=10),
    ]


def _auth_failure_logs():
    return [
        _log(
            f"auth-failure-{index}",
            "198.51.100.60",
            seconds_ago=300 - (index * 30),
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
        )
        for index in range(6)
    ]


def _token(role: str, subject: str):
    return create_access_token(
        subject=subject,
        extra_claims={
            "user_id": 1,
            "username": subject,
            "role": role,
            "is_active": True,
        },
    )


def _bearer(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_successful_request_returns_detection_and_advisory_outcomes(db_env):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    data = response.json()
    assert data["advisory_only"] is True
    assert "audit" not in data
    assert "enforcement" not in data
    assert data["detection"]["total_clients"] == 1
    assert data["mitigation"]["policy_version"] == "stage-a-b-1.0.0"
    outcomes = data["mitigation"]["outcomes"]
    assert len(outcomes) == len(data["detection"]["results"])
    assert outcomes[0]["status"] == MitigationOutcomeStatus.PERSISTED.value
    assert outcomes[0]["advisory_only"] is True
    assert outcomes[0]["decision"]["advisory_only"] is True
    assert outcomes[0]["decision_uuid"]

    stored = session.query(MitigationAuditEvent).one()
    assert stored.event_type == "decision_issued"
    assert stored.entity_identifier == outcomes[0]["decision_uuid"]
    assert stored.decision_id is not None


def test_valid_api_key_is_accepted(db_env, real_authentication, monkeypatch):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "stage-b-test-key")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    captured = {}
    original = mitigation_route.evaluate_and_persist_bot_detection

    def capture(db, detection, **kwargs):
        captured.update(kwargs)
        return original(db, detection, **kwargs)

    monkeypatch.setattr(mitigation_route, "evaluate_and_persist_bot_detection", capture)

    response = client.get(ENDPOINT, headers={"X-API-Key": "stage-b-test-key"})

    assert response.status_code == 200
    assert captured["authentication_mode"] == MitigationAuthenticationMode.API_KEY
    assert captured["verified_principal"] is None
    stored = session.query(MitigationAuditEvent).one()
    assert stored.actor_hash is None
    assert stored.actor_role is None


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_jwt_admin_and_analyst_requests_are_accepted(
    db_env, real_authentication, monkeypatch, role
):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    captured = {}
    original = mitigation_route.evaluate_and_persist_bot_detection

    def capture(db, detection, **kwargs):
        captured.update(kwargs)
        return original(db, detection, **kwargs)

    monkeypatch.setattr(mitigation_route, "evaluate_and_persist_bot_detection", capture)

    response = client.get(ENDPOINT, headers=_bearer(_token(role, f"{role}-actor")))

    assert response.status_code == 200
    principal = captured["verified_principal"]
    assert captured["authentication_mode"] == MitigationAuthenticationMode.JWT
    assert principal is not None
    assert principal.role == role
    assert principal.actor_key_hash.startswith("sha256:")
    decision = response.json()["mitigation"]["outcomes"][0]["decision"]
    assert decision["attribution_status"] == "verified_user"
    assert decision["verified_attribution"] is True
    stored = session.query(MitigationAuditEvent).one()
    assert stored.actor_hash == principal.actor_key_hash
    assert stored.actor_role == role


def test_viewer_jwt_is_rejected_with_403(db_env, real_authentication, monkeypatch):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    response = client.get(ENDPOINT, headers=_bearer(_token("viewer", "viewer-actor")))

    assert response.status_code == 403
    assert "Operation not permitted" in response.json()["detail"]
    assert session.query(MitigationAuditEvent).count() == 0


def test_missing_credentials_are_rejected_with_401(
    db_env, real_authentication, monkeypatch
):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "stage-b-test-key")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    response = client.get(ENDPOINT)

    assert response.status_code == 401
    assert session.query(MitigationAuditEvent).count() == 0


def test_existing_query_validation_and_422_behavior_are_preserved(db_env):
    _, _, session = db_env
    _seed_policy(session)

    invalid_page = client.get(ENDPOINT, params={"page": 0})
    assert invalid_page.status_code == 422

    invalid_status = client.get(ENDPOINT, params={"status_code": 700})
    assert invalid_status.status_code == 422

    invalid_window = client.get(
        ENDPOINT,
        params={
            "start_time": "2026-02-10T12:00:00Z",
            "end_time": "2026-02-10T11:00:00Z",
        },
    )
    assert invalid_window.status_code == 422
    assert invalid_window.json()["detail"] == (
        "start_time must be earlier than or equal to end_time"
    )


def test_policy_unavailable_still_returns_detection(
    db_env, monkeypatch, caplog
):
    _, _, session = db_env
    caplog.set_level(logging.ERROR)
    _seed_logs(session, _benign_logs())

    def unavailable(*args, **kwargs):
        raise ActivePolicyNotFoundError("missing policy")

    monkeypatch.setattr(integration_service, "load_active_policy", unavailable)

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    data = response.json()
    assert data["detection"]["total_clients"] == 1
    assert data["mitigation"]["policy_version"] is None
    assert [
        item["status"] for item in data["mitigation"]["outcomes"]
    ] == [MitigationOutcomeStatus.POLICY_UNAVAILABLE.value]
    assert session.query(MitigationAuditEvent).count() == 0


def test_decision_persistence_failure_returns_safe_status(
    db_env, monkeypatch, caplog
):
    _, _, session = db_env
    caplog.set_level(logging.ERROR)
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    def failing_persist(*args, **kwargs):
        raise DecisionPersistenceError("database unavailable")

    monkeypatch.setattr(
        integration_service, "persist_evaluated_decision", failing_persist
    )

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    outcome = response.json()["mitigation"]["outcomes"][0]
    assert outcome["status"] == MitigationOutcomeStatus.DECISION_NOT_PERSISTED.value
    assert outcome["decision"] is None
    assert session.query(MitigationAuditEvent).count() == 0
    assert "database unavailable" not in caplog.text
    assert "database unavailable" not in response.text


def test_api_key_attribution_remains_missing(
    db_env, real_authentication, monkeypatch
):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "stage-b-test-key")
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    response = client.get(
        ENDPOINT,
        headers={
            "X-API-Key": "stage-b-test-key",
            "X-User-ID": "spoofed-user",
            "X-Actor-ID": "spoofed-actor",
        },
        params={"actor_id": "spoofed-query-actor"},
    )

    assert response.status_code == 200
    outcome = response.json()["mitigation"]["outcomes"][0]
    assert outcome["decision"]["attribution_status"] == "missing"
    assert outcome["decision"]["verified_attribution"] is False
    assert outcome["decision"]["scope_type"] == "unattributed"
    stored = session.query(MitigationAuditEvent).one()
    assert stored.actor_hash is None
    assert stored.actor_role is None
    assert stored.details["attribution_status"] == "missing"
    assert stored.entity_identifier == outcome["decision_uuid"]


def test_no_sensitive_values_in_mitigation_response_or_logs(
    db_env, monkeypatch, caplog
):
    _, _, session = db_env
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(settings, "API_KEY", "stage-b-test-key")
    _seed_policy(session)
    raw_ip = "203.0.113.44"
    raw_request_id = "raw-secret-request-id"
    raw_user_agent = "UA-SECRET-AGENT"
    raw_token = "RAWQUERYTOKEN"
    _seed_logs(
        session,
        [
            _log(
                raw_request_id,
                raw_ip,
                user_agent=raw_user_agent,
                query_params={"token": raw_token},
            )
        ],
    )

    response = client.get(
        ENDPOINT,
        headers={"X-API-Key": "stage-b-test-key"},
        params={"token": raw_token, "path": "/secret"},
    )

    assert response.status_code == 200
    mitigation_text = json.dumps(response.json()["mitigation"])
    app_log_text = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("apisentry")
    )
    for raw_value in (raw_ip, raw_request_id, raw_user_agent, raw_token):
        assert raw_value not in mitigation_text
        assert raw_value not in app_log_text
    assert "stage-b-test-key" not in response.text
    assert "stage-b-test-key" not in app_log_text
    assert "***MASKED***" in app_log_text


def test_audit_fields_never_contain_raw_traffic_values(db_env, monkeypatch, caplog):
    _, _, session = db_env
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(settings, "API_KEY", "stage-b-test-key")
    _seed_policy(session)
    raw_ip = "203.0.113.44"
    raw_user_agent = "UA-SECRET-AGENT"
    raw_token = "RAWQUERYTOKEN"
    request_id = unique_uuid5()
    _seed_logs(
        session,
        [
            _log(
                request_id,
                raw_ip,
                user_agent=raw_user_agent,
                query_params={"token": raw_token},
            )
        ],
    )

    response = client.get(
        ENDPOINT,
        headers={"X-API-Key": "stage-b-test-key"},
        params={"token": raw_token},
    )

    assert response.status_code == 200
    assert (
        response.json()["mitigation"]["outcomes"][0]["status"]
        == MitigationOutcomeStatus.PERSISTED.value
    )
    stored = session.query(MitigationAuditEvent).one()
    columns = _assert_no_sensitive_values_in_audit_columns(
        stored, (raw_ip, raw_user_agent, raw_token, "stage-b-test-key", request_id)
    )
    assert columns["entity_identifier"] != request_id
    assert columns["actor_hash"] is None
    assert columns["actor_role"] is None
    app_log_text = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("apisentry")
    )
    for value in (raw_ip, raw_user_agent, raw_token, "stage-b-test-key"):
        assert value not in app_log_text
    assert "***MASKED***" in app_log_text


def test_route_commits_once_after_successful_orchestration(db_env):
    _, factory, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    commit_calls = []
    original_commit = session.commit

    def counted_commit():
        commit_calls.append(1)
        return original_commit()

    session.commit = counted_commit

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    assert len(commit_calls) == 1
    assert _fresh_counts(factory) == (1, 1)


def test_unexpected_failure_rolls_back_without_partial_commit(db_env, monkeypatch):
    _, factory, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    commit_calls = []
    rollback_calls = []
    original_commit = session.commit
    original_rollback = session.rollback

    def counted_commit():
        commit_calls.append(1)
        return original_commit()

    def counted_rollback():
        rollback_calls.append(1)
        return original_rollback()

    def unexpected(*args, **kwargs):
        raise RuntimeError("unexpected programming error")

    session.commit = counted_commit
    session.rollback = counted_rollback
    monkeypatch.setattr(
        mitigation_route, "evaluate_and_persist_bot_detection", unexpected
    )

    response = client.get(ENDPOINT)

    assert response.status_code == 500
    assert commit_calls == []
    assert len(rollback_calls) == 1
    assert "unexpected programming error" not in response.text
    assert "Traceback" not in response.text
    assert _fresh_counts(factory) == (0, 0)


def test_existing_stage1_endpoint_behavior_remains_unchanged(db_env):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    mitigation_response = client.get(ENDPOINT)
    bot_response = client.get(BOT_ENDPOINT)

    assert mitigation_response.status_code == 200
    assert bot_response.status_code == 200
    assert mitigation_response.json()["detection"] == bot_response.json()


def test_no_enforcement_even_with_throttle_block_policy(db_env, real_authentication, monkeypatch):
    _, _, session = db_env
    monkeypatch.setattr(settings, "API_KEY", "")
    _seed_policy(
        session,
        policy_version="stage-a-enforce-1.0.0",
        mode=StoredPolicyMode.ENFORCE,
        monitoring_score_threshold=0.0,
        throttling_score_threshold=0.0,
        blocking_score_threshold=0.0,
        minimum_authentication_failures=1,
        require_grouped_brute_force=False,
        throttle_enabled=True,
        block_enabled=True,
    )
    _seed_logs(session, _auth_failure_logs())

    response = client.get(
        ENDPOINT, headers=_bearer(_token("analyst", "enforcement-actor"))
    )

    assert response.status_code == 200
    data = response.json()
    assert data["advisory_only"] is True
    decisions = [
        item["decision"]
        for item in data["mitigation"]["outcomes"]
        if item["decision"] is not None
    ]
    assert decisions
    assert {item["decision"] for item in decisions} & {"throttle", "block"}
    assert all(item["advisory_only"] is True for item in decisions)
    for forbidden_key in ("enforced", "enforcement_applied", "blocked", "throttled"):
        assert forbidden_key not in data


def test_successful_request_commits_decision_and_audit_event_together(db_env):
    _, factory, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    response = client.get(ENDPOINT)

    assert response.status_code == 200
    assert _fresh_counts(factory) == (1, 1)
    decision = session.query(MitigationDecision).one()
    audit = session.query(MitigationAuditEvent).one()
    assert audit.event_type == "decision_issued"
    assert audit.decision_id == decision.id
    assert audit.entity_identifier == decision.decision_uuid
    assert session.query(MitigationAuditEvent).count() == 1


def test_audit_persistence_failure_rolls_back_and_returns_generic_500(
    db_env, monkeypatch, caplog
):
    _, factory, session = db_env
    caplog.set_level(logging.ERROR)
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    commit_calls = []
    rollback_calls = []
    original_commit = session.commit
    original_rollback = session.rollback

    def counted_commit():
        commit_calls.append(1)
        return original_commit()

    def counted_rollback():
        rollback_calls.append(1)
        return original_rollback()

    def failing_audit(*args, **kwargs):
        raise audit_service.MitigationAuditPersistenceFailure("audit write failed")

    session.commit = counted_commit
    session.rollback = counted_rollback
    monkeypatch.setattr(
        mitigation_route, "persist_decision_audit_events", failing_audit
    )

    response = client.get(ENDPOINT)

    assert response.status_code == 500
    assert response.json()["detail"] == "Bot detection analysis could not be completed."
    assert commit_calls == []
    assert len(rollback_calls) == 1
    assert _fresh_counts(factory) == (0, 0)
    assert "audit write failed" not in response.text
    assert "audit write failed" not in caplog.text
    assert "Traceback" not in response.text


def test_audit_failure_after_decision_persistence_leaves_no_committed_rows(
    db_env, caplog
):
    _, factory, session = db_env
    caplog.set_level(logging.ERROR)
    _seed_policy(session)
    _seed_logs(session, _benign_logs())
    _force_audit_insert_failure(session)

    response = client.get(ENDPOINT)

    assert response.status_code == 500
    assert _fresh_counts(factory) == (0, 0)
    for marker in AUDIT_FAILURE_SENTINELS + ("RAISE(ABORT", "mitigation_audit_events SELECT"):
        assert marker not in response.text
        assert marker not in caplog.text
    assert "Traceback" not in response.text


def test_failed_audit_retry_preserves_existing_decision_and_audit_rows(
    db_env, monkeypatch
):
    _, factory, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    first = client.get(ENDPOINT)
    assert first.status_code == 200
    fresh = factory()
    try:
        before_decision = fresh.query(MitigationDecision).one()
        before_audit = fresh.query(MitigationAuditEvent).one()
        snapshot = (
            before_decision.id,
            before_decision.decision_uuid,
            before_audit.id,
            before_audit.event_uuid,
            before_audit.event_hash,
            before_audit.details,
            before_audit.created_at,
        )
    finally:
        fresh.close()

    def failing_retry(*args, **kwargs):
        raise audit_service.MitigationAuditPersistenceFailure("retry failure")

    monkeypatch.setattr(
        mitigation_route, "persist_decision_audit_events", failing_retry
    )
    second = client.get(ENDPOINT)

    assert second.status_code == 500
    fresh = factory()
    try:
        after_decision = fresh.query(MitigationDecision).one()
        after_audit = fresh.query(MitigationAuditEvent).one()
        assert (
            after_decision.id,
            after_decision.decision_uuid,
            after_audit.id,
            after_audit.event_uuid,
            after_audit.event_hash,
            after_audit.details,
            after_audit.created_at,
        ) == snapshot
        assert fresh.query(MitigationDecision).count() == 1
        assert fresh.query(MitigationAuditEvent).count() == 1
    finally:
        fresh.close()


def test_repeated_equivalent_requests_reuse_audit_event_without_duplicates(db_env):
    _, factory, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    first = client.get(ENDPOINT)
    second = client.get(ENDPOINT)

    assert first.status_code == 200
    assert second.status_code == 200
    first_outcome = first.json()["mitigation"]["outcomes"][0]
    second_outcome = second.json()["mitigation"]["outcomes"][0]
    assert first_outcome["status"] == MitigationOutcomeStatus.PERSISTED.value
    assert second_outcome["status"] == MitigationOutcomeStatus.IDEMPOTENT_REUSE.value
    assert second_outcome["decision_uuid"] == first_outcome["decision_uuid"]

    assert _fresh_counts(factory) == (1, 1)
    fresh = factory()
    try:
        audit = fresh.query(MitigationAuditEvent).one()
        assert audit.entity_identifier == first_outcome["decision_uuid"]
    finally:
        fresh.close()


def test_response_contract_has_no_audit_fields(db_env):
    _, _, session = db_env
    _seed_policy(session)
    _seed_logs(session, _benign_logs())

    data = client.get(ENDPOINT).json()

    assert set(data) == {"detection", "mitigation", "advisory_only"}
    assert set(data["mitigation"]) == {"policy_version", "outcomes"}
    outcome = data["mitigation"]["outcomes"][0]
    assert set(outcome) == {
        "result_index",
        "status",
        "decision",
        "decision_uuid",
        "advisory_only",
    }
    assert set(outcome["decision"]) == {
        "decision",
        "scope_type",
        "scope_key_hash",
        "attribution_status",
        "verified_attribution",
        "reason_codes",
        "explanation",
        "policy_version",
        "evidence_references",
        "issued_at",
        "expires_at",
        "rate_limit",
        "rate_limit_window_seconds",
        "advisory_only",
    }
    serialized = json.dumps(data)
    for forbidden_key in (
        "audit",
        "audit_event",
        "audit_events",
        "audit_event_count",
        "event_uuid",
        "event_hash",
        "chain_id",
        "sequence_no",
        "enforcement",
    ):
        assert f'"{forbidden_key}"' not in serialized
