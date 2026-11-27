"""Focused authenticated API tests for MW3 Gate C.

All database access uses isolated in-memory SQLite. No PostgreSQL server,
configured database, or external credential is contacted.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routes import mitigation_policy_admin as policy_admin_module
from app.core.security import create_access_token
from app.db.session import get_db
from app.main import app
from app.models.mitigation import (
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
)
from app.schemas.bot_detection import BotAnalysisResult, BotClassification
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationPolicyConfig,
    MitigationRequestContext,
)
from app.schemas.mitigation_policy_lifecycle import (
    LifecycleActor,
    LifecycleErrorCode,
    LifecycleRole,
)
from app.services.mitigation_policy_lifecycle_persistence_service import (
    LifecyclePersistenceDatabaseError,
    persist_evaluation_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)
from tests.mitigation_persistence_helpers import sqlite_session_factory

client = TestClient(app)

FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
API = "/api/v1/security/mitigation"
POLICY = f"{API}/policies"


@pytest.fixture(autouse=True)
def _isolate_request_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.utils.middleware.save_traffic_log", lambda *args, **kwargs: None
    )


@pytest.fixture(autouse=True)
def _fresh_lifecycle_registry() -> Any:
    original = policy_admin_module._lifecycle_service
    policy_admin_module._lifecycle_service = MitigationPolicyLifecycleService()
    try:
        yield
    finally:
        policy_admin_module._lifecycle_service = original


@pytest.fixture()
def db_session() -> Any:
    engine, factory = sqlite_session_factory()
    session = factory()

    def _override_get_db() -> Any:
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield session
    finally:
        app.dependency_overrides.pop(get_db, None)
        session.close()
        engine.dispose()


def _token(role: str, subject: str) -> str:
    return create_access_token(
        subject=subject,
        extra_claims={
            "user_id": 1,
            "username": subject,
            "role": role,
            "is_active": True,
        },
    )


def _headers(role: str, subject: str | None = None) -> dict[str, str]:
    resolved = subject or f"{role}@example.test"
    return {"Authorization": f"Bearer {_token(role, resolved)}"}


def _config(version: str = "policy-1", **overrides: object) -> MitigationPolicyConfig:
    values: dict[str, object] = {"policy_version": version}
    values.update(overrides)
    return MitigationPolicyConfig(**values)  # type: ignore[arg-type]


def _proposal_payload(version: str = "policy-1", **overrides: object) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "config": _config(version).model_dump(mode="json"),
        "created_at": (FIXED_NOW - timedelta(days=1)).isoformat(),
    }
    payload.update(overrides)
    return payload


def _detection() -> BotAnalysisResult:
    return BotAnalysisResult(
        bot_risk_score=1.0,
        classification=BotClassification.HUMAN_LIKE,
        summary="Neutral advisory test input.",
    )


def _context() -> MitigationRequestContext:
    return MitigationRequestContext(
        evaluated_at=FIXED_NOW,
        attribution_status=MitigationAttributionStatus.MISSING,
    )


def _dry_run_payload(version: str = "policy-1", token: str = "dry-run-1") -> dict[str, Any]:
    return {
        "version": version,
        "at": FIXED_NOW.isoformat(),
        "detection_result": _detection().model_dump(mode="json"),
        "context": _context().model_dump(mode="json"),
        "dry_run": True,
        "idempotency_token": token,
    }


def _activate_policy(version: str = "policy-1") -> None:
    admin = _headers("admin")
    proposed = client.post(POLICY, headers=admin, json=_proposal_payload(version))
    assert proposed.status_code == 201, proposed.text
    validated = client.post(
        f"{POLICY}/{version}/validate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat()},
    )
    assert validated.status_code == 200, validated.text
    activated = client.post(
        f"{POLICY}/{version}/activate",
        headers=admin,
        json={
            "at": FIXED_NOW.isoformat(),
            "reason_code": "initial_activation",
        },
    )
    assert activated.status_code == 200, activated.text


def test_authentication_and_role_gates(db_session: Any) -> None:
    analyst_reads = [
        ("GET", POLICY),
        ("GET", f"{POLICY}/active"),
        ("GET", f"{API}/decisions"),
        ("GET", f"{API}/audit-events"),
        ("GET", f"{API}/enforcement/status"),
    ]
    for method, path in analyst_reads:
        assert client.request(method, path).status_code == 401
        viewer = client.request(method, path, headers=_headers("viewer"))
        assert viewer.status_code == 403, viewer.text
        analyst = client.request(method, path, headers=_headers("analyst"))
        assert analyst.status_code == 200, analyst.text

    admin_write = ("POST", POLICY, _proposal_payload())
    assert client.request("POST", POLICY, json=admin_write[2]).status_code == 401
    viewer = client.request(
        "POST", POLICY, headers=_headers("viewer"), json=admin_write[2]
    )
    assert viewer.status_code == 403
    analyst = client.request(
        "POST", POLICY, headers=_headers("analyst"), json=admin_write[2]
    )
    assert analyst.status_code == 403
    admin = client.request(
        "POST", POLICY, headers=_headers("admin"), json=admin_write[2]
    )
    assert admin.status_code == 201, admin.text


def test_policy_lifecycle_persists_and_status_is_advisory_only(db_session: Any) -> None:
    _activate_policy()
    assert db_session.query(MitigationPolicy).count() == 1
    assert db_session.query(MitigationPolicyActivationEvent).count() >= 1
    assert db_session.query(MitigationAuditEvent).count() >= 1

    status = client.get(f"{API}/enforcement/status", headers=_headers("analyst"))
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["enforcement_active"] is False
    assert body["advisory_only"] is True
    assert body["active_version"] == "policy-1"
    assert body["persisted_active_version"] == "policy-1"
    assert body["policy_mode"] == "monitor"
    assert body["activation_event_count"] >= 1
    assert body["latest_activation_event_type"] == "ACTIVATE"

    active = client.get(f"{POLICY}/active", headers=_headers("analyst"))
    assert active.status_code == 200
    assert active.json()["policy"]["policy_version"] == "policy-1"

    detail = client.get(f"{POLICY}/policy-1", headers=_headers("analyst"))
    assert detail.status_code == 200
    assert detail.json()["state"] == "ACTIVE"

    missing = client.get(f"{POLICY}/does-not-exist", headers=_headers("analyst"))
    assert missing.status_code == 404


def test_deactivate_and_rollback_keep_gate_advisory(db_session: Any) -> None:
    admin = _headers("admin")
    _activate_policy()

    deactivated = client.post(
        f"{POLICY}/deactivate",
        headers=admin,
        json={
            "version": "policy-1",
            "at": (FIXED_NOW + timedelta(minutes=1)).isoformat(),
            "expected_active_version": "policy-1",
            "reason_code": "policy_deactivation",
        },
    )
    assert deactivated.status_code == 200, deactivated.text
    status = client.get(f"{API}/enforcement/status", headers=_headers("analyst")).json()
    assert status["active_version"] is None
    assert status["persisted_active_version"] is None

    replacement = client.post(
        POLICY,
        headers=admin,
        json=_proposal_payload("policy-2"),
    )
    assert replacement.status_code == 201, replacement.text
    validate_replacement = client.post(
        f"{POLICY}/policy-2/validate",
        headers=admin,
        json={"at": (FIXED_NOW + timedelta(minutes=2)).isoformat()},
    )
    assert validate_replacement.status_code == 200, validate_replacement.text
    activate_replacement = client.post(
        f"{POLICY}/policy-2/activate",
        headers=admin,
        json={
            "at": (FIXED_NOW + timedelta(minutes=2)).isoformat(),
            "expected_active_version": None,
        },
    )
    assert activate_replacement.status_code == 200, activate_replacement.text

    rolled_back = client.post(
        f"{POLICY}/policy-1/rollback",
        headers=admin,
        json={
            "at": (FIXED_NOW + timedelta(minutes=3)).isoformat(),
            "expected_active_version": "policy-2",
        },
    )
    assert rolled_back.status_code == 200, rolled_back.text
    status = client.get(f"{API}/enforcement/status", headers=_headers("analyst")).json()
    assert status["active_version"] == "policy-1"
    assert status["advisory_only"] is True


def test_expected_active_version_none_is_not_the_same_as_omitted(db_session: Any) -> None:
    _activate_policy()
    admin = _headers("admin")
    proposed = client.post(POLICY, headers=admin, json=_proposal_payload("policy-2"))
    assert proposed.status_code == 201, proposed.text

    wrong_expectation = client.post(
        f"{POLICY}/policy-2/activate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat(), "expected_active_version": None},
    )
    assert wrong_expectation.status_code == 409, wrong_expectation.text
    assert (
        wrong_expectation.json()["detail"]["code"] == "version_conflict"
    )

    omitted = client.post(
        f"{POLICY}/policy-2/activate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat()},
    )
    assert omitted.status_code == 409, omitted.text
    assert (
        omitted.json()["detail"]["code"] == "version_conflict"
    )
    assert (
        wrong_expectation.json()["detail"]["message"]
        != omitted.json()["detail"]["message"]
    )

    validate_second = client.post(
        f"{POLICY}/policy-2/validate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat()},
    )
    assert validate_second.status_code == 200, validate_second.text

    explicit = client.post(
        f"{POLICY}/policy-2/activate",
        headers=admin,
        json={
            "at": FIXED_NOW.isoformat(),
            "expected_active_version": "policy-1",
        },
    )
    assert explicit.status_code == 200, explicit.text
    active = client.get(f"{POLICY}/active", headers=_headers("analyst")).json()
    assert active["active_version"] == "policy-2"


def test_validation_conflict_and_forbidden_actor_fields(db_session: Any) -> None:
    admin = _headers("admin")
    first = client.post(POLICY, headers=admin, json=_proposal_payload("policy-1"))
    assert first.status_code == 201
    duplicate = client.post(POLICY, headers=admin, json=_proposal_payload("policy-1"))
    assert duplicate.status_code == 409, duplicate.text

    spoofed = client.post(
        POLICY,
        headers=admin,
        json={
            **_proposal_payload("spoofed"),
            "role": "admin",
            "actor_hash": "sha256:" + "a" * 64,
        },
    )
    assert spoofed.status_code == 422

    unsupported = client.post(
        f"{POLICY}/policy-1/activate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat(), "reason_code": "not_a_reason"},
    )
    assert unsupported.status_code == 422

    unknown = client.post(
        f"{POLICY}/unknown/validate",
        headers=admin,
        json={"at": FIXED_NOW.isoformat()},
    )
    assert unknown.status_code == 404


def test_mitigation_policy_admin_422_contract_is_starlette_constant_independent(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route must import and return 422 without Starlette's renamed constant."""
    import importlib

    import fastapi

    original_status: Any = fastapi.status

    class StatusWithoutRenamedConstant:
        def __getattr__(self, name: str) -> Any:
            if name == "HTTP_422_UNPROCESSABLE_CONTENT":
                raise AttributeError(name)
            return getattr(original_status, name)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(fastapi, "status", StatusWithoutRenamedConstant())
            module = importlib.reload(policy_admin_module)
            assert (
                module._STATUS_BY_ERROR_CODE[LifecycleErrorCode.VALIDATION_ERROR] == 422
            )
            assert (
                module._STATUS_BY_ERROR_CODE[
                    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID
                ]
                == 422
            )
            assert (
                module._STATUS_BY_ERROR_CODE[LifecycleErrorCode.EVALUATION_FAILED] == 422
            )
            assert module._status_for_error_code("unknown_lifecycle_code") == 422
    finally:
        # The context restores the patch on exit; restore explicitly as well so
        # a failing assertion cannot leave the route module bound to the shim.
        fastapi.status = original_status
        importlib.reload(policy_admin_module)

    response = client.post(
        POLICY,
        headers=_headers("admin"),
        json={
            **_proposal_payload("spoofed-422"),
            "role": "admin",
            "actor_hash": "sha256:" + "a" * 64,
        },
    )
    assert response.status_code == 422, response.text
    assert isinstance(response.json()["detail"], list)


def test_dry_run_is_advisory_and_writes_nothing(db_session: Any) -> None:
    _activate_policy()
    decisions_before = db_session.query(MitigationDecision).count()
    audit_before = db_session.query(MitigationAuditEvent).count()

    response = client.post(
        f"{API}/dry-run",
        headers=_headers("analyst", "analyst-dry@example.test"),
        json=_dry_run_payload(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["decision"]["advisory_only"] is True
    assert body["decision"]["policy_version"] == "policy-1"
    assert body["decision"]["decision_ref"]

    repeated = client.post(
        f"{API}/dry-run",
        headers=_headers("analyst", "analyst-dry@example.test"),
        json=_dry_run_payload(),
    )
    assert repeated.status_code == 200
    assert (
        repeated.json()["decision"]["decision_ref"]
        == body["decision"]["decision_ref"]
    )

    assert db_session.query(MitigationDecision).count() == decisions_before
    assert db_session.query(MitigationAuditEvent).count() == audit_before


def test_decision_and_audit_history_filters_and_sensitive_fields(db_session: Any) -> None:
    _activate_policy()
    actor = LifecycleActor(
        role=LifecycleRole.ANALYST,
        actor_hash=policy_admin_module._verified_actor_hash(
            "analyst-history@example.test"
        ),
    )
    evaluation = policy_admin_module.get_lifecycle_service().evaluate_policy(
        actor=actor,
        version="policy-1",
        at=FIXED_NOW,
        detection_result=_detection(),
        context=_context(),
        dry_run=True,
        idempotency_token="history-1",
    )
    assert evaluation.ok and evaluation.decision is not None
    persisted = persist_evaluation_result(db_session, evaluation)
    assert persisted.ok, persisted.error
    db_session.commit()

    decision_ref = evaluation.decision.decision_ref
    event_uuid = evaluation.audit_event.event_uuid  # type: ignore[union-attr]
    analyst = _headers("analyst", "analyst-history@example.test")

    decisions = client.get(
        f"{API}/decisions",
        headers=analyst,
        params={"policy_version": "policy-1"},
    )
    assert decisions.status_code == 200, decisions.text
    body = decisions.json()
    assert body["total"] == 1
    assert body["items"][0]["decision_uuid"] == decision_ref
    assert body["items"][0]["advisory_only"] is True

    by_ref = client.get(
        f"{API}/decisions",
        headers=analyst,
        params={"decision_ref": decision_ref},
    )
    assert by_ref.status_code == 200
    assert by_ref.json()["total"] == 1

    single_decision = client.get(
        f"{API}/decisions/{decision_ref}", headers=analyst
    )
    assert single_decision.status_code == 200
    assert single_decision.json()["decision_uuid"] == decision_ref

    audit = client.get(
        f"{API}/audit-events",
        headers=analyst,
        params={"event_type": "decision_issued", "decision_ref": decision_ref},
    )
    assert audit.status_code == 200, audit.text
    audit_body = audit.json()
    assert audit_body["total"] == 1
    assert audit_body["items"][0]["event_uuid"] == event_uuid
    assert audit_body["items"][0]["decision_uuid"] == decision_ref

    single_audit = client.get(f"{API}/audit-events/{event_uuid}", headers=analyst)
    assert single_audit.status_code == 200

    paged = client.get(
        f"{API}/audit-events",
        headers=analyst,
        params={"limit": 1, "offset": 0},
    )
    assert paged.status_code == 200
    assert len(paged.json()["items"]) == 1
    assert paged.json()["total"] >= 2

    serialized = json.dumps(body) + json.dumps(audit_body)
    assert "analyst-history@example.test" not in serialized
    assert "password" not in serialized.lower()
    assert "authorization" not in serialized.lower()


def test_persistence_failure_rolls_back_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch, db_session: Any
) -> None:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise LifecyclePersistenceDatabaseError("database unavailable")

    monkeypatch.setattr(policy_admin_module, "persist_lifecycle_result", _boom)
    response = client.post(
        POLICY,
        headers=_headers("admin"),
        json=_proposal_payload("failed-policy"),
    )
    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error."
    assert "database unavailable" not in response.text
    assert db_session.query(MitigationPolicy).count() == 0
