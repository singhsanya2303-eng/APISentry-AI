"""MW3 Gate B focused persistence tests against the disposable PostgreSQL DB.

These tests deliberately target only the dedicated Gate B retry database on
127.0.0.1:55444. They never use the configured application database, never
touch the historical traffic rows beyond read-only integrity checks, and clean
up only policy rows created with this test module's unique prefix.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
import uuid
from typing import Any

import pytest
from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.models.mitigation import (
    ALLOWED_ACTIVATION_DETAIL_KEYS,
    ALLOWED_AUDIT_DETAIL_KEYS,
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationPolicyConfig,
    MitigationRequestContext,
)
from app.schemas.mitigation_policy_lifecycle import LifecycleActor
from app.services import mitigation_policy_lifecycle_persistence_service as persistence
from app.services.mitigation_policy_lifecycle_service import MitigationPolicyLifecycleService


EXPECTED_HOST = os.environ.get("MW4B_PG_HOST", "127.0.0.1")
EXPECTED_PORT = int(os.environ.get("MW4B_PG_PORT", "55444"))
EXPECTED_DATABASE = os.environ.get("MW4B_PG_DATABASE", "apisentry_gateb_retry")
FIXED_NOW = datetime(2026, 3, 12, 10, 0, tzinfo=timezone.utc)
LATER = FIXED_NOW + timedelta(minutes=5)
ADMIN_HASH = "sha256:" + hashlib.sha256(b"mw3-gateb:admin").hexdigest()
ANALYST_HASH = "sha256:" + hashlib.sha256(b"mw3-gateb:analyst").hexdigest()
OTHER_HASH = "sha256:" + "b" * 64


def _admin() -> LifecycleActor:
    from app.schemas.mitigation_policy_lifecycle import LifecycleRole

    return LifecycleActor(role=LifecycleRole.ADMIN, actor_hash=ADMIN_HASH)


def _analyst() -> LifecycleActor:
    from app.schemas.mitigation_policy_lifecycle import LifecycleRole

    return LifecycleActor(role=LifecycleRole.ANALYST, actor_hash=ANALYST_HASH)


def _opaque(label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"mw3-gateb-persistence:{label}"))


def _config(version: str, **overrides: Any) -> MitigationPolicyConfig:
    values: dict[str, Any] = {"policy_version": version}
    values.update(overrides)
    return MitigationPolicyConfig(**values)


def _context() -> MitigationRequestContext:
    return MitigationRequestContext(
        evaluated_at=FIXED_NOW,
        attribution_status=MitigationAttributionStatus.VERIFIED_USER,
        actor_key_hash=ANALYST_HASH,
    )


def _assert_gateb_url(url_text: str) -> None:
    if not url_text:
        pytest.fail("DATABASE_URL is required for Gate B persistence tests")
    url = make_url(url_text)
    if (
        url.get_backend_name() != "postgresql"
        or url.host != EXPECTED_HOST
        or url.port != EXPECTED_PORT
        or url.database != EXPECTED_DATABASE
    ):
        pytest.fail("Gate B persistence tests require the dedicated disposable database")


@pytest.fixture(scope="session")
def gateb_engine():
    url_text = os.environ.get("DATABASE_URL", "")
    _assert_gateb_url(url_text)
    engine = create_engine(url_text, future=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        pytest.fail(f"dedicated Gate B database is unavailable: {type(exc).__name__}")
    yield engine
    engine.dispose()


@pytest.fixture
def run_prefix() -> str:
    return f"gateb-{uuid.uuid4().hex}-"


def _in_statement(sql: str):
    return text(sql).bindparams(bindparam("ids", expanding=True))


def _cleanup(engine, prefix: str) -> None:
    with engine.begin() as connection:
        policy_ids = [
            int(value)
            for value in connection.execute(
                text("SELECT id FROM mitigation_policies WHERE policy_version LIKE :prefix"),
                {"prefix": f"{prefix}%"},
            ).scalars()
        ]
        if not policy_ids:
            return
        params = {"ids": policy_ids}
        connection.execute(
            _in_statement(
                "DELETE FROM mitigation_audit_events "
                "WHERE policy_id IN :ids OR decision_id IN ("
                "  SELECT id FROM mitigation_decisions WHERE policy_id IN :ids"
                ")"
            ),
            params,
        )
        connection.execute(
            _in_statement("DELETE FROM mitigation_decisions WHERE policy_id IN :ids"),
            params,
        )
        connection.execute(
            _in_statement(
                "DELETE FROM mitigation_policy_activation_events WHERE policy_id IN :ids"
            ),
            params,
        )
        connection.execute(
            _in_statement(
                "UPDATE mitigation_policy_state SET policy_id = NULL "
                "WHERE policy_id IN :ids"
            ),
            params,
        )
        connection.execute(
            _in_statement("DELETE FROM mitigation_policies WHERE id IN :ids"),
            params,
        )


@pytest.fixture
def gateb_db(gateb_engine, run_prefix):
    factory = sessionmaker(
        bind=gateb_engine,
        autoflush=False,
        expire_on_commit=False,
        future=True,
    )
    sessions: list[Session] = []

    def make_session() -> Session:
        session = factory()
        sessions.append(session)
        return session

    yield make_session

    for session in sessions:
        session.close()
    _cleanup(gateb_engine, run_prefix)


def _version(prefix: str, label: str) -> str:
    return f"{prefix}{label}"


def _build_active_service(prefix: str, label: str):
    service = MitigationPolicyLifecycleService()
    version = _version(prefix, label)
    proposed = service.propose_policy(
        actor=_admin(),
        config=_config(version),
        created_at=FIXED_NOW,
    )
    validated = service.validate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    activated = service.activate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    assert proposed.ok and validated.ok and activated.ok
    return service, version, proposed, validated, activated


def _persist_all(db: Session, *results) -> None:
    for result in results:
        assert result.ok
        persistence.persist_lifecycle_result(db, result)


def _count_policies(db: Session, version: str) -> int:
    return int(
        db.execute(
            text("SELECT count(*) FROM mitigation_policies WHERE policy_version = :version"),
            {"version": version},
        ).scalar_one()
    )


def test_policy_creation_and_retrieval(gateb_db, run_prefix) -> None:
    db = gateb_db()
    version = _version(run_prefix, "creation")
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_admin(),
        config=_config(version, monitoring_score_threshold=31.5),
        created_at=FIXED_NOW,
    )
    assert proposed.ok

    saved = persistence.persist_lifecycle_result(db, proposed)
    db.commit()

    assert saved.ok and saved.created
    assert saved.policy is not None
    assert saved.policy.policy_version == version
    assert not saved.policy.active
    assert saved.policy.config.monitoring_score_threshold == 31.5
    assert persistence.load_active_policy_version(db) is None

    loaded = persistence.load_persisted_policy(db, version)
    assert loaded is not None
    assert loaded.config == proposed.policy.config
    assert loaded.creator_hash == ADMIN_HASH
    assert _count_policies(db, version) == 1


def test_update_requires_new_policy_version(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service = MitigationPolicyLifecycleService()
    v1 = _version(run_prefix, "v1")
    v2 = _version(run_prefix, "v2")
    first = service.propose_policy(
        actor=_admin(),
        config=_config(v1, monitoring_score_threshold=25.0),
        created_at=FIXED_NOW,
    )
    second = service.propose_policy(
        actor=_admin(),
        config=_config(v2, monitoring_score_threshold=42.0),
        predecessor_version=v1,
        created_at=LATER,
    )
    assert first.ok and second.ok
    _persist_all(db, first, second)
    db.commit()

    original = persistence.load_persisted_policy(db, v1)
    updated = persistence.load_persisted_policy(db, v2)
    assert original is not None and updated is not None
    assert original.config.monitoring_score_threshold == 25.0
    assert updated.config.monitoring_score_threshold == 42.0
    assert original.config.policy_version == v1
    assert updated.config.policy_version == v2
    assert _count_policies(db, v1) == 1
    assert _count_policies(db, v2) == 1


def test_activate_deactivate_retire_transitions(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service, version, proposed, validated, activated = _build_active_service(run_prefix, "lifecycle")
    _persist_all(db, proposed, validated, activated)
    db.commit()

    assert persistence.load_active_policy_version(db) == version
    active = persistence.load_persisted_policy(db, version)
    assert active is not None and active.active
    assert active.activation_event_count == 1

    deactivated = service.deactivate_policy(actor=_admin(), version=version, at=LATER)
    assert deactivated.ok
    persistence.persist_lifecycle_result(db, deactivated)
    db.commit()

    assert persistence.load_active_policy_version(db) is None
    inactive = persistence.load_persisted_policy(db, version)
    assert inactive is not None and not inactive.active
    assert inactive.activation_event_count == 2

    retired = service.retire_policy(actor=_admin(), version=version, at=LATER)
    assert retired.ok
    retired_saved = persistence.persist_lifecycle_result(db, retired)
    db.commit()

    assert retired_saved.ok and not retired_saved.activation_events
    assert not retired_saved.audit_events
    assert persistence.load_active_policy_version(db) is None


def test_invalid_transition_is_not_persisted(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service, version, proposed, validated, activated = _build_active_service(run_prefix, "invalid")
    _persist_all(db, proposed, validated, activated)
    db.commit()

    before = _count_policies(db, version)
    invalid = service.deactivate_policy(
        actor=_admin(),
        version=version,
        at=LATER,
        expected_active_version=_opaque("wrong-active"),
    )
    assert not invalid.ok and invalid.error is not None

    saved = persistence.persist_lifecycle_result(db, invalid)
    db.commit()

    assert not saved.ok
    assert saved.error == invalid.error.code.value
    assert _count_policies(db, version) == before
    assert persistence.load_active_policy_version(db) == version
    assert (
        db.execute(
            text(
                "SELECT count(*) FROM mitigation_audit_events a "
                "JOIN mitigation_policies p ON p.id = a.policy_id "
                "WHERE p.policy_version = :version"
            ),
            {"version": version},
        ).scalar_one()
        == 1
    )


def test_decision_persistence_and_policy_version_reference(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service, version, proposed, validated, activated = _build_active_service(run_prefix, "decision")
    _persist_all(db, proposed, validated, activated)

    evaluation = service.evaluate_policy(
        actor=_analyst(),
        version=version,
        at=FIXED_NOW,
        detection_result=None,
        context=_context(),
        dry_run=True,
    )
    assert evaluation.ok and evaluation.decision is not None
    saved = persistence.persist_evaluation_result(db, evaluation)
    db.commit()

    assert saved.ok and saved.decision is not None and saved.audit_event is not None
    assert saved.decision.created and saved.audit_event.created
    row = persistence.load_persisted_decision(db, saved.decision.decision_uuid)
    assert row is not None
    assert row.decision_uuid == evaluation.decision.decision_ref
    assert row.dedupe_key == evaluation.decision.decision_ref
    assert row.advisory_only is True
    assert row.policy.policy_version == version

    audit = persistence.load_persisted_audit_event(db, saved.audit_event.event_uuid)
    assert audit is not None
    assert audit.decision_id == row.id
    assert audit.policy_id == row.policy_id


def test_audit_persistence_is_allowlisted_and_privacy_safe(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service, version, proposed, validated, activated = _build_active_service(run_prefix, "audit")
    _persist_all(db, proposed, validated, activated)

    evaluation = service.evaluate_policy(
        actor=_analyst(),
        version=version,
        at=FIXED_NOW,
        detection_result=None,
        context=_context(),
        dry_run=True,
    )
    assert evaluation.ok
    persistence.persist_evaluation_result(db, evaluation)
    db.commit()

    activation_details = db.execute(
        text(
            "SELECT a.details FROM mitigation_policy_activation_events a "
            "JOIN mitigation_policies p ON p.id = a.policy_id "
            "WHERE p.policy_version = :version"
        ),
        {"version": version},
    ).scalars().all()
    assert activation_details
    for details in activation_details:
        assert set(details).issubset(ALLOWED_ACTIVATION_DETAIL_KEYS)

    audit_rows = db.execute(
        text(
            "SELECT a.details, a.event_hash, a.chain_id, a.event_type "
            "FROM mitigation_audit_events a "
            "JOIN mitigation_policies p ON p.id = a.policy_id "
            "WHERE p.policy_version = :version"
        ),
        {"version": version},
    ).all()
    assert len(audit_rows) == 2
    for details, event_hash, chain_id, event_type in audit_rows:
        assert set(details).issubset(ALLOWED_AUDIT_DETAIL_KEYS)
        assert event_hash.startswith("sha256:")
        assert len(chain_id) == 36
        assert event_type in {"policy_activated", "decision_issued"}


def test_foreign_key_integrity_is_enforced(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service = MitigationPolicyLifecycleService()
    version = _version(run_prefix, "fk")
    proposed = service.propose_policy(
        actor=_admin(), config=_config(version), created_at=FIXED_NOW
    )
    assert proposed.ok
    persistence.persist_lifecycle_result(db, proposed)
    db.commit()

    before = db.execute(text("SELECT count(*) FROM mitigation_decisions")).scalar_one()
    invalid_policy_id = 2_000_000_000
    bad_decision = MitigationDecision(
        decision_uuid=_opaque("bad-decision"),
        decision_type="allow",
        scope_type="unattributed",
        scope_key_hash=None,
        attribution_status="missing",
        verified_attribution=False,
        reason_codes=["detection_unavailable"],
        explanation="Gate B foreign-key integrity test.",
        policy_id=invalid_policy_id,
        evidence_references=[],
        issued_at=FIXED_NOW,
        expires_at=None,
        rate_limit=None,
        rate_limit_window_seconds=None,
        advisory_only=True,
        dedupe_key=_opaque("bad-decision-dedupe"),
        created_at=FIXED_NOW,
    )
    db.add(bad_decision)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()

    plan = activated_plan = None
    activated = service.validate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    assert activated.ok
    activation = service.activate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    assert activation.ok and activation.audit_events
    plan = activation.audit_events[0]
    bad_audit = MitigationAuditEvent(
        event_uuid=_opaque("bad-audit"),
        event_type=plan.event_type.value,
        entity_type=plan.entity_type.value,
        entity_identifier=plan.entity_identifier,
        policy_id=invalid_policy_id,
        decision_id=None,
        actor_hash=plan.actor_hash,
        actor_role=plan.actor_role,
        details={"policy_version": version},
        previous_event_hash=None,
        event_hash=plan.content_digest,
        sequence_no=1,
        chain_id=_opaque("bad-chain"),
        created_at=FIXED_NOW,
    )
    db.add(bad_audit)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()

    after = db.execute(text("SELECT count(*) FROM mitigation_decisions")).scalar_one()
    assert after == before


def test_duplicate_prevention_and_conflict_detection(gateb_db, run_prefix) -> None:
    db = gateb_db()
    version = _version(run_prefix, "duplicate")
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_admin(), config=_config(version), created_at=FIXED_NOW
    )
    assert proposed.ok

    first = persistence.persist_lifecycle_result(db, proposed)
    second = persistence.persist_lifecycle_result(db, proposed)
    db.commit()
    assert first.created and not second.created
    assert _count_policies(db, version) == 1

    from app.schemas.mitigation_policy_lifecycle import PolicyLifecycleResult

    changed_config = _config(version, monitoring_score_threshold=26.0)
    conflicting_policy = proposed.policy.model_copy(update={"config": changed_config})
    conflicting_result = PolicyLifecycleResult(ok=True, policy=conflicting_policy)
    with pytest.raises(persistence.LifecyclePersistenceConflictError):
        persistence.persist_lifecycle_result(db, conflicting_result)
    db.rollback()

    service.validate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    activated = service.activate_policy(actor=_admin(), version=version, at=FIXED_NOW)
    assert activated.ok
    persistence.persist_lifecycle_result(db, activated)
    evaluation = service.evaluate_policy(
        actor=_analyst(),
        version=version,
        at=FIXED_NOW,
        detection_result=None,
        context=_context(),
        dry_run=True,
    )
    assert evaluation.ok
    first_eval = persistence.persist_evaluation_result(db, evaluation)
    second_eval = persistence.persist_evaluation_result(db, evaluation)
    db.commit()
    assert first_eval.decision is not None and second_eval.decision is not None
    assert first_eval.decision.created and not second_eval.decision.created

    from app.schemas.mitigation_policy_lifecycle import PolicyEvaluationResult

    changed_decision = evaluation.decision.decision.model_copy(
        update={"explanation": "A conflicting explanation for the same decision ref."}
    )
    conflicting_decision = evaluation.decision.model_copy(update={"decision": changed_decision})
    conflicting_eval = PolicyEvaluationResult(
        ok=True,
        decision=conflicting_decision,
        audit_event=evaluation.audit_event,
    )
    with pytest.raises(persistence.LifecyclePersistenceConflictError):
        persistence.persist_evaluation_result(db, conflicting_eval)
    db.rollback()


def test_commit_and_rollback_boundary(gateb_db, run_prefix) -> None:
    db = gateb_db()
    rollback_version = _version(run_prefix, "rollback")
    commit_version = _version(run_prefix, "commit")
    service = MitigationPolicyLifecycleService()
    rollback_result = service.propose_policy(
        actor=_admin(), config=_config(rollback_version), created_at=FIXED_NOW
    )
    commit_result = service.propose_policy(
        actor=_admin(), config=_config(commit_version), created_at=FIXED_NOW
    )
    assert rollback_result.ok and commit_result.ok

    persistence.persist_lifecycle_result(db, rollback_result)
    db.rollback()
    assert _count_policies(db, rollback_version) == 0

    persistence.persist_lifecycle_result(db, commit_result)
    db.commit()
    verifier = gateb_db()
    try:
        assert _count_policies(verifier, rollback_version) == 0
        assert _count_policies(verifier, commit_version) == 1
    finally:
        verifier.close()


def test_failed_write_raises_boundary_error(gateb_db, run_prefix, monkeypatch) -> None:
    db = gateb_db()
    version = _version(run_prefix, "failed-write")
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_admin(), config=_config(version), created_at=FIXED_NOW
    )
    assert proposed.ok

    def fail_flush() -> None:
        raise SQLAlchemyError("simulated write failure")

    monkeypatch.setattr(db, "flush", fail_flush)
    with pytest.raises(persistence.LifecyclePersistenceDatabaseError) as exc_info:
        persistence.persist_lifecycle_result(db, proposed)
    assert "simulated" not in str(exc_info.value)
    db.rollback()

    verifier = gateb_db()
    try:
        assert _count_policies(verifier, version) == 0
    finally:
        verifier.close()


def test_database_connection_failure_is_reported_without_dsn(gateb_db, run_prefix, monkeypatch) -> None:
    gateb_db()
    version = _version(run_prefix, "conn-failure")
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_admin(), config=_config(version), created_at=FIXED_NOW
    )
    assert proposed.ok

    broken_engine = create_engine(
        os.environ["DATABASE_URL"], future=True, poolclass=NullPool
    )

    def fail_connect(*_args: Any, **_kwargs: Any) -> None:
        raise SQLAlchemyError("simulated connection failure")

    monkeypatch.setattr(broken_engine, "connect", fail_connect)
    broken_db = Session(broken_engine, future=True)
    try:
        with pytest.raises(persistence.LifecyclePersistenceDatabaseError) as exc_info:
            persistence.persist_lifecycle_result(broken_db, proposed)
        message = str(exc_info.value)
        assert "simulated" not in message
        assert EXPECTED_HOST not in message
        assert str(EXPECTED_PORT) not in message
        assert EXPECTED_DATABASE not in message
    finally:
        broken_db.close()
        broken_engine.dispose()


def test_rollback_activation_events_reference_owning_versions(gateb_db, run_prefix) -> None:
    db = gateb_db()
    service, v1, proposed1, validated1, activated1 = _build_active_service(run_prefix, "rb-v1")
    _persist_all(db, proposed1, validated1, activated1)

    v2 = _version(run_prefix, "rb-v2")
    proposed2 = service.propose_policy(
        actor=_admin(),
        config=_config(v2, monitoring_score_threshold=35.0),
        created_at=LATER,
        predecessor_version=v1,
    )
    validated2 = service.validate_policy(actor=_admin(), version=v2, at=LATER)
    activated2 = service.activate_policy(
        actor=_admin(),
        version=v2,
        at=LATER,
        expected_active_version=v1,
    )
    assert proposed2.ok and validated2.ok and activated2.ok
    assert len(activated2.activation_events) == 2
    _persist_all(db, proposed2, validated2, activated2)
    db.commit()
    assert persistence.load_active_policy_version(db) == v2

    rolled_back = service.rollback_policy(
        actor=_admin(),
        target_version=v1,
        at=LATER + timedelta(minutes=1),
        expected_active_version=v2,
    )
    assert rolled_back.ok and len(rolled_back.activation_events) == 2
    persistence.persist_lifecycle_result(db, rolled_back)
    db.commit()
    assert persistence.load_active_policy_version(db) == v1

    ownership = db.execute(
        text(
            "SELECT p.policy_version, e.event_type, count(*) "
            "FROM mitigation_policy_activation_events e "
            "JOIN mitigation_policies p ON p.id = e.policy_id "
            "WHERE p.policy_version IN (:v1, :v2) "
            "GROUP BY p.policy_version, e.event_type"
        ),
        {"v1": v1, "v2": v2},
    ).all()
    counts = {(version, event_type): count for version, event_type, count in ownership}
    assert counts[(v1, "ACTIVATE")] == 2
    assert counts[(v1, "DEACTIVATE")] == 1
    assert counts[(v2, "ACTIVATE")] == 1
    assert counts[(v2, "DEACTIVATE")] == 1
