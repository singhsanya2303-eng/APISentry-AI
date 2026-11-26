"""Focused SEC-02 hydration regression tests.

Every database used here is isolated in-memory SQLite. No PostgreSQL server,
configured database, service, container, or enforcement process is contacted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1.routes import mitigation_policy_admin as policy_admin_module
from app.core.security import create_access_token
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.mitigation import MitigationAuditEvent, MitigationDecision, MitigationPolicyState
from app.models.user import User
from app.schemas.bot_detection import BotAnalysisResult, BotClassification
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationPolicyConfig,
    MitigationRequestContext,
)
from app.schemas.mitigation_policy_lifecycle import (
    LifecycleActor,
    LifecycleRole,
    PolicyLifecycleState,
)
from app.services import mitigation_policy_lifecycle_persistence_service as persistence
from app.services.mitigation_demo_service import reset_for_tests
from app.services.mitigation_policy_lifecycle_service import MitigationPolicyLifecycleService
from tests.mitigation_persistence_helpers import sqlite_session_factory

client = TestClient(app)

FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ADMIN_ACTOR = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash="sha256:" + "a" * 64)
API = "/api/v1/security/mitigation"
POLICIES = f"{API}/policies"
DEMO = f"{API}/demo"


def _policy(version: str) -> MitigationPolicyConfig:
    return MitigationPolicyConfig(
        policy_version=version,
        enabled=True,
        mode="enforce",
        monitoring_score_threshold=20.0,
        throttling_score_threshold=60.0,
        blocking_score_threshold=80.0,
        minimum_authentication_failures=3,
        require_grouped_brute_force=False,
        throttle_enabled=True,
        throttle_limit=10,
        throttle_window_seconds=60,
        throttle_duration_seconds=60,
        block_enabled=True,
        block_duration_seconds=60,
        max_block_duration_seconds=300,
        admin_protection_enabled=True,
        max_evidence_references=10,
    )


def _activate_in_memory(service: MitigationPolicyLifecycleService, version: str) -> None:
    created = service.propose_policy(
        actor=ADMIN_ACTOR, config=_policy(version), created_at=FIXED_NOW - timedelta(days=1)
    )
    assert created.ok, created.error
    validated = service.validate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert validated.ok, validated.error
    activated = service.activate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert activated.ok, activated.error


def _persist_active_policy(db: Any, version: str) -> None:
    """Persist a policy and its active pointer using a separate registry."""
    writer = MitigationPolicyLifecycleService()
    created = writer.propose_policy(
        actor=ADMIN_ACTOR, config=_policy(version), created_at=FIXED_NOW - timedelta(days=1)
    )
    assert created.ok, created.error
    validated = writer.validate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert validated.ok, validated.error
    activated = writer.activate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert activated.ok, activated.error
    for result in (created, validated, activated):
        persistence.persist_lifecycle_result(db, result)
    db.commit()


def _seed_conflict(service: MitigationPolicyLifecycleService, db: Any) -> None:
    """Persisted active is db-1.0.0; in-memory active is mem-1.0.0."""
    _persist_active_policy(db, "db-1.0.0")
    _activate_in_memory(service, "mem-1.0.0")


def _headers(role: str, subject: str | None = None) -> dict[str, str]:
    resolved = subject or f"{role}@example.test"
    token = create_access_token(
        subject=resolved,
        extra_claims={
            "user_id": 1,
            "username": resolved,
            "role": role,
            "is_active": True,
        },
    )
    return {"Authorization": f"Bearer {token}"}


def _raise_read_error(*args: Any, **kwargs: Any) -> None:
    raise SQLAlchemyError("simulated DB read failure")


@pytest.fixture(autouse=True)
def _isolate_request_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda *a, **k: None)


@pytest.fixture
def route_env() -> Any:
    """Fresh lifecycle singleton and isolated in-memory SQLite behind routes."""
    original_service = policy_admin_module._lifecycle_service
    service = MitigationPolicyLifecycleService()
    policy_admin_module._lifecycle_service = service
    reset_for_tests()

    engine, factory = sqlite_session_factory()
    session = factory()
    previous_db_override = app.dependency_overrides.get(get_db)

    def _override_get_db() -> Any:
        yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield service, session
    finally:
        if previous_db_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db_override
        session.close()
        engine.dispose()
        reset_for_tests()
        policy_admin_module._lifecycle_service = original_service


@pytest.fixture
def route_env_missing_schema() -> Any:
    """Route environment with auth tables only; mitigation tables are absent."""
    original_service = policy_admin_module._lifecycle_service
    service = MitigationPolicyLifecycleService()
    policy_admin_module._lifecycle_service = service

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine, tables=[User.__table__])
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    previous_db_override = app.dependency_overrides.get(get_db)

    def _override_get_db() -> Any:
        yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield service, session
    finally:
        if previous_db_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db_override
        session.close()
        engine.dispose()
        policy_admin_module._lifecycle_service = original_service


def _request_payload(key: str | None) -> dict[str, Any] | None:
    at = FIXED_NOW.isoformat()
    payloads: dict[str, dict[str, Any]] = {
        "propose": {
            "config": _policy("route-new-1.0.0").model_dump(mode="json"),
            "created_at": at,
        },
        "validate": {"at": at},
        "activate": {"at": at},
        "deactivate": {"version": "mem-1.0.0", "at": at},
        "retire": {"at": at},
        "rollback": {"at": at},
        "demo_enable": {
            "confirmation": "ENABLE_LOCAL_DEMO",
            "policy_version": "mem-1.0.0",
            "max_requests": 25,
            "max_duration_seconds": 300,
            "synthetic_only_ack": True,
            "loopback_only_ack": True,
        },
        "demo_run": {
            "demo_id": "hydration-503-probe",
            "synthetic": True,
            "requests": [{"request_id": "synthetic-1"}],
        },
    }
    return payloads[key] if key is not None else None


def _dry_run_payload(version: str, token: str) -> dict[str, Any]:
    return {
        "version": version,
        "at": FIXED_NOW.isoformat(),
        "detection_result": BotAnalysisResult(
            bot_risk_score=1.0,
            classification=BotClassification.HUMAN_LIKE,
            summary="Neutral advisory test input.",
        ).model_dump(mode="json"),
        "context": MitigationRequestContext(
            evaluated_at=FIXED_NOW,
            attribution_status=MitigationAttributionStatus.MISSING,
        ).model_dump(mode="json"),
        "dry_run": True,
        "idempotency_token": token,
    }


def _active_versions(service: MitigationPolicyLifecycleService) -> list[str]:
    return [
        version
        for version in service.policy_versions()
        if service.get_policy(version).state is PolicyLifecycleState.ACTIVE
    ]


_SENSITIVE_ROUTES = [
    ("GET", POLICIES, None),
    ("GET", f"{POLICIES}/active", None),
    ("POST", POLICIES, "propose"),
    ("POST", f"{POLICIES}/mem-1.0.0/validate", "validate"),
    ("POST", f"{POLICIES}/mem-1.0.0/activate", "activate"),
    ("POST", f"{POLICIES}/deactivate", "deactivate"),
    ("POST", f"{POLICIES}/mem-1.0.0/retire", "retire"),
    ("POST", f"{POLICIES}/mem-1.0.0/rollback", "rollback"),
    ("POST", f"{DEMO}/enable", "demo_enable"),
    ("POST", f"{DEMO}/run", "demo_run"),
]


def test_hydration_conflicting_active_versions_does_not_override_either_state() -> None:
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        _persist_active_policy(db, "db-1.0.0")
        service = MitigationPolicyLifecycleService()
        _activate_in_memory(service, "mem-1.0.0")

        report = service.hydrate_from_persistence(db)

        assert report["ok"] is False
        assert report["diverged"] is True
        assert report["error"] == "active_version_divergence"
        assert report["in_memory_active_version"] == "mem-1.0.0"
        assert report["persisted_active_version"] == "db-1.0.0"
        # In-memory active pointer and its policy record are not silently replaced.
        assert service.active_version == "mem-1.0.0"
        assert service.get_policy("mem-1.0.0").state is PolicyLifecycleState.ACTIVE
        # The persisted-only record is reconstructed non-ACTIVE during divergence;
        # there is exactly one ACTIVE record and it agrees with the pointer.
        reconstructed = service.get_policy("db-1.0.0")
        assert reconstructed is not None
        assert reconstructed.state is PolicyLifecycleState.INACTIVE
        assert _active_versions(service) == ["mem-1.0.0"]
        assert service.active_version == _active_versions(service)[0]
        # Persisted active pointer and rows are unchanged by a read-only hydration.
        assert persistence.load_active_policy_version(db) == "db-1.0.0"
        assert [snap.policy_version for snap in persistence.load_all_persisted_policies(db)] == [
            "db-1.0.0"
        ]
        assert service.hydration_report()["error"] == "active_version_divergence"
    finally:
        db.close()
        engine.dispose()


def test_hydration_adopts_persisted_active_record_as_active() -> None:
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        _persist_active_policy(db, "adopt-1.0.0")
        service = MitigationPolicyLifecycleService()
        assert service.active_version is None

        report = service.hydrate_from_persistence(db)

        assert report["ok"] is True
        assert report["diverged"] is False
        assert service.active_version == "adopt-1.0.0"
        assert service.get_policy("adopt-1.0.0").state is PolicyLifecycleState.ACTIVE
        assert _active_versions(service) == ["adopt-1.0.0"]
        assert service.active_version == _active_versions(service)[0]
        assert persistence.load_active_policy_version(db) == "adopt-1.0.0"
    finally:
        db.close()
        engine.dispose()


def test_conflicting_active_versions_routes_fail_closed_and_report_status(route_env: Any) -> None:
    service, session = route_env
    _seed_conflict(service, session)

    admin_headers = _headers("admin")
    analyst_headers = _headers("analyst")

    for path in (POLICIES, f"{POLICIES}/active"):
        response = client.get(path, headers=admin_headers)
        assert response.status_code == 503, response.text
        assert response.json()["detail"]["error"] == "mitigation_registry_inconsistent"
        assert response.json()["detail"]["consistency_note"] == "active_version_divergence"

    mutation_response = client.post(
        POLICIES,
        headers=admin_headers,
        json=_request_payload("propose"),
    )
    assert mutation_response.status_code == 503, mutation_response.text
    assert mutation_response.json()["detail"]["error"] == "mitigation_registry_inconsistent"
    assert service.get_policy("route-new-1.0.0") is None

    demo_response = client.post(
        f"{DEMO}/enable",
        headers=admin_headers,
        json=_request_payload("demo_enable"),
    )
    assert demo_response.status_code == 503, demo_response.text
    assert demo_response.json()["detail"]["error"] == "mitigation_registry_inconsistent"
    assert demo_response.json()["detail"]["consistency_note"] == "active_version_divergence"

    # Read-only paths follow their actual contract: they report, not reject.
    policy_detail = client.get(f"{POLICIES}/mem-1.0.0", headers=analyst_headers)
    assert policy_detail.status_code == 200, policy_detail.text
    assert policy_detail.json()["policy_version"] == "mem-1.0.0"
    assert client.get(f"{DEMO}/status", headers=analyst_headers).status_code == 200

    status = client.get(f"{API}/enforcement/status", headers=analyst_headers)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["registry_consistent"] is False
    assert body["consistency_note"] == "active_version_divergence"
    assert body["active_version"] == "mem-1.0.0"
    assert body["persisted_active_version"] == "db-1.0.0"

    assert persistence.load_active_policy_version(session) == "db-1.0.0"
    assert [snap.policy_version for snap in persistence.load_all_persisted_policies(session)] == [
        "db-1.0.0"
    ]


def test_hydration_read_failure_reports_error_and_keeps_session_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        monkeypatch.setattr(persistence, "load_all_persisted_policies", _raise_read_error)
        service = MitigationPolicyLifecycleService()
        _activate_in_memory(service, "memory-only-1.0.0")

        report = service.hydrate_from_persistence(db)

        assert report["ok"] is False
        assert report["diverged"] is False
        assert report["error"] == "persistence_read_failed"
        assert report["in_memory_active_version"] == "memory-only-1.0.0"
        assert service.active_version == "memory-only-1.0.0"
        assert service.hydration_report()["error"] == "persistence_read_failed"
        # The simulated read error did not touch the session; it stays usable.
        assert db.execute(text("SELECT 1")).scalar() == 1
    finally:
        db.close()
        engine.dispose()


def test_hydration_read_failure_on_failed_transaction_allows_session_rollback() -> None:
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        # Poison the caller-owned transaction with an FK violation on flush.
        db.add(MitigationPolicyState(id=1, policy_id=999999, singleton_marker=1))
        with pytest.raises(SQLAlchemyError):
            db.flush()

        service = MitigationPolicyLifecycleService()
        report = service.hydrate_from_persistence(db)

        assert report["ok"] is False
        assert report["error"] == "persistence_read_failed"
        assert service.hydration_report()["error"] == "persistence_read_failed"
        # Hydration does not own the caller's transaction; caller rollback restores use.
        db.rollback()
        assert db.execute(text("SELECT 1")).scalar() == 1
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("method,path,payload_key", _SENSITIVE_ROUTES)
def test_sensitive_routes_fail_closed_on_hydration_read_failure(
    route_env: Any,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    payload_key: str | None,
) -> None:
    service, session = route_env
    monkeypatch.setattr(persistence, "load_all_persisted_policies", _raise_read_error)

    kwargs: dict[str, Any] = {"headers": _headers("admin")}
    payload = _request_payload(payload_key)
    if payload is not None:
        kwargs["json"] = payload

    response = client.request(method, path, **kwargs)

    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "mitigation_registry_inconsistent"
    assert detail["consistency_note"] == "persistence_read_failed"
    assert service.hydration_report()["error"] == "persistence_read_failed"
    assert session.execute(text("SELECT 1")).scalar() == 1


def test_missing_persistence_schema_uses_compatibility_fallback() -> None:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        service = MitigationPolicyLifecycleService()
        report = service.hydrate_from_persistence(session)

        # Explicit compatibility fallback: not a durability or multi-worker claim.
        assert report["ok"] is True
        assert report["error"] is None
        assert report["diverged"] is False
        assert report["consistency_note"] == "persistence_store_unavailable"
        assert report["hydrated"] is False
        assert report["loaded_versions"] == []
        assert service.active_version is None
        assert service.policy_versions() == ()
        assert service.hydration_report()["consistency_note"] == "persistence_store_unavailable"
    finally:
        session.close()
        engine.dispose()


def test_missing_persistence_schema_route_contract(route_env_missing_schema: Any) -> None:
    service, session = route_env_missing_schema
    analyst_headers = _headers("analyst")

    # Mutation/list routes allow the documented compatibility fallback.
    listing = client.get(POLICIES, headers=analyst_headers)
    assert listing.status_code == 200, listing.text
    assert listing.json()["versions"] == []
    assert listing.json()["active_version"] is None
    assert service.hydration_report()["consistency_note"] == "persistence_store_unavailable"

    # Enforcement status performs its own direct reads; with no mitigation
    # schema it maps that read failure to 500, not the hydration 503.
    status = client.get(f"{API}/enforcement/status", headers=analyst_headers)
    assert status.status_code == 500, status.text
    assert session.execute(text("SELECT 1 FROM users LIMIT 1")).fetchall() == []


def test_repeated_hydration_is_idempotent_and_non_destructive() -> None:
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        _persist_active_policy(db, "r1.0.0")
        writer = MitigationPolicyLifecycleService()
        inactive_created = writer.propose_policy(
            actor=ADMIN_ACTOR, config=_policy("r2.0.0"), created_at=FIXED_NOW - timedelta(days=1)
        )
        assert inactive_created.ok, inactive_created.error
        inactive_validated = writer.validate_policy(
            actor=ADMIN_ACTOR, version="r2.0.0", at=FIXED_NOW
        )
        assert inactive_validated.ok, inactive_validated.error
        persistence.persist_lifecycle_result(db, inactive_created)
        persistence.persist_lifecycle_result(db, inactive_validated)
        db.commit()

        service = MitigationPolicyLifecycleService()
        first = service.hydrate_from_persistence(db)

        assert first["ok"] is True
        assert first["loaded_versions"] == ["r1.0.0", "r2.0.0"]
        assert service.active_version == "r1.0.0"
        assert service.policy_versions() == ("r1.0.0", "r2.0.0")

        # Simulate a richer in-memory record that hydration must not overwrite.
        richer = service.get_policy("r2.0.0").model_copy(
            update={"state": PolicyLifecycleState.ACTIVE}
        )
        service._policies["r2.0.0"] = richer

        second = service.hydrate_from_persistence(db)
        assert second["ok"] is True
        assert second["loaded_versions"] == []
        assert service.active_version == "r1.0.0"
        assert len(service._policies) == 2
        assert service._policies["r2.0.0"].state is PolicyLifecycleState.ACTIVE
        assert service._policies["r1.0.0"].config.policy_version == "r1.0.0"

        third = service.hydrate_from_persistence(db)
        assert third["ok"] is True
        assert third["loaded_versions"] == []
        assert service.active_version == "r1.0.0"
        assert service.policy_versions() == ("r1.0.0", "r2.0.0")
        assert len(service._policies) == 2
        assert service._policies["r2.0.0"].state is PolicyLifecycleState.ACTIVE
        assert persistence.load_active_policy_version(db) == "r1.0.0"
    finally:
        db.close()
        engine.dispose()


def test_dry_run_fails_closed_when_active_versions_diverge(route_env: Any) -> None:
    service, session = route_env
    _seed_conflict(service, session)
    decisions_before = session.query(MitigationDecision).count()
    audits_before = session.query(MitigationAuditEvent).count()

    for version in ("db-1.0.0", "mem-1.0.0"):
        response = client.post(
            f"{API}/dry-run",
            headers=_headers("analyst"),
            json=_dry_run_payload(version, f"divergent-{version}"),
        )
        assert response.status_code == 503, response.text
        detail = response.json()["detail"]
        assert detail["error"] == "mitigation_registry_inconsistent"
        assert detail["consistency_note"] == "active_version_divergence"
        assert "decision" not in response.json()

    assert service.hydration_report()["error"] == "active_version_divergence"
    assert session.query(MitigationDecision).count() == decisions_before
    assert session.query(MitigationAuditEvent).count() == audits_before


def test_dry_run_remains_advisory_when_registry_is_consistent(route_env: Any) -> None:
    service, session = route_env
    _persist_active_policy(session, "consistent-1.0.0")
    _activate_in_memory(service, "consistent-1.0.0")
    decisions_before = session.query(MitigationDecision).count()
    audits_before = session.query(MitigationAuditEvent).count()

    response = client.post(
        f"{API}/dry-run",
        headers=_headers("analyst"),
        json=_dry_run_payload("consistent-1.0.0", "consistent-1"),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["decision"]["advisory_only"] is True
    assert body["decision"]["policy_version"] == "consistent-1.0.0"
    assert body["decision"]["decision_ref"]
    assert service.hydration_report()["ok"] is True
    assert session.query(MitigationDecision).count() == decisions_before
    assert session.query(MitigationAuditEvent).count() == audits_before
