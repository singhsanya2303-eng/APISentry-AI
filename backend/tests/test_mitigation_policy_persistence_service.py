"""Focused active-policy loading tests for Stage 2C Phase 3.

All databases are isolated in-memory SQLite instances. The service is read-only:
these tests verify that it does not commit caller transactions.
"""

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models.mitigation import MitigationPolicyState
from app.services.mitigation_policy_persistence_service import (
    load_active_policy,
    load_policy_by_version,
)
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    PolicyConfigurationError,
    PolicyVersionMismatchError,
)
from tests.mitigation_persistence_helpers import (
    activate_policy,
    policy_record,
    sqlite_session_factory,
)


@pytest.fixture
def db_session():
    engine, factory = sqlite_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_load_active_policy_validates_stored_config_and_preserves_version(db_session):
    stored = policy_record(
        policy_version="version-2026-02-10",
        monitoring_score_threshold=30.0,
        throttling_score_threshold=80.0,
        max_evidence_references=12,
    )
    db_session.add(stored)
    db_session.flush()
    activate_policy(db_session, stored)

    loaded = load_active_policy(db_session)

    assert loaded.record is stored
    assert loaded.config.policy_version == "version-2026-02-10"
    assert loaded.config.monitoring_score_threshold == 30.0
    assert loaded.config.throttling_score_threshold == 80.0
    assert loaded.config.max_evidence_references == 12
    assert loaded.config.mode.value == stored.mode.value
    assert not db_session.new


def test_load_active_policy_rejects_missing_marker_and_empty_reference(db_session):
    with pytest.raises(ActivePolicyNotFoundError):
        load_active_policy(db_session)

    db_session.add(policy_record(policy_version="empty-reference"))
    db_session.flush()
    db_session.add(MitigationPolicyState(id=1, policy_id=None))
    with pytest.raises(ActivePolicyNotFoundError):
        load_active_policy(db_session)


def test_load_active_policy_rejects_invalid_stored_configuration(db_session):
    stored = policy_record(
        policy_version="invalid-thresholds",
        monitoring_score_threshold=90.0,
        throttling_score_threshold=10.0,
    )
    db_session.add(stored)
    db_session.flush()
    activate_policy(db_session, stored)

    with pytest.raises(PolicyConfigurationError):
        load_active_policy(db_session)


def test_load_active_policy_rejects_expected_version_mismatch(db_session):
    stored = policy_record(policy_version="stored-version")
    db_session.add(stored)
    db_session.flush()
    activate_policy(db_session, stored)

    with pytest.raises(PolicyVersionMismatchError):
        load_active_policy(db_session, expected_policy_version="different-version")


def test_load_policy_by_version_uses_exact_identity(db_session):
    stored = policy_record(policy_version="exact-version")
    db_session.add(stored)
    db_session.flush()

    assert load_policy_by_version(db_session, "exact-version") is stored
    with pytest.raises(ActivePolicyNotFoundError):
        load_policy_by_version(db_session, "EXACT-VERSION")


def test_database_failure_is_wrapped_without_raw_diagnostics(caplog):
    secret = "phase3-private-dsn-marker"

    class BrokenSession:
        def get(self, *_args, **_kwargs):
            raise SQLAlchemyError(secret)

    with caplog.at_level("ERROR"):
        with pytest.raises(PolicyConfigurationError) as exc_info:
            load_active_policy(BrokenSession())

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None


def test_read_service_does_not_commit_caller_transaction(db_session):
    stored = policy_record(policy_version="uncommitted-version")
    db_session.add(stored)
    db_session.flush()
    activate_policy(db_session, stored)

    load_active_policy(db_session)
    assert db_session.in_transaction() is True

    db_session.rollback()
    assert db_session.query(type(stored)).filter_by(policy_version="uncommitted-version").first() is None
