"""Focused audit-event persistence tests for Stage 2C Phase 3."""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import text

from app.models.mitigation import MitigationAuditEvent
from app.services import mitigation_audit_persistence_service as audit_service
from app.services import mitigation_persistence_common as persistence_common
from app.services.mitigation_audit_persistence_service import persist_audit_event
from app.services.mitigation_decision_persistence_service import persist_evaluated_decision
from app.services.mitigation_persistence_common import (
    AuditEventPersistenceError,
    AuditEventValidationError,
    PrivacySensitiveDataError,
)
from tests.mitigation_persistence_helpers import (
    OTHER_HASH,
    VALID_HASH,
    audit_kwargs,
    evaluated_decision,
    policy_record,
    sqlite_session_factory,
    unique_uuid5,
)


@pytest.fixture
def db_env():
    engine, factory = sqlite_session_factory()
    session = factory()
    try:
        yield session, factory, engine
    finally:
        session.close()
        engine.dispose()


def _stored_policy(session):
    policy = policy_record(policy_version="phase3-audit-1.0")
    session.add(policy)
    session.flush()
    return policy


def test_audit_event_round_trip_stores_caller_supplied_chain_data(db_env):
    session, _factory, _engine = db_env
    values = audit_kwargs(
        event_hash=OTHER_HASH,
        previous_event_hash=VALID_HASH,
        chain_id="explicit-chain-one",
        sequence_no=7,
        details={
            "policy_version": "phase3-audit-1.0",
            "decision_type": "allow",
            "evidence_reference_count": 1,
            "advisory_only": True,
        },
    )

    result = persist_audit_event(session, **values)

    assert result.created is True
    stored = result.event
    assert stored.id is not None
    assert stored.event_uuid == values["event_uuid"]
    assert stored.event_type == "decision_issued"
    assert stored.entity_type == "decision"
    assert stored.event_hash == OTHER_HASH
    assert stored.previous_event_hash == VALID_HASH
    assert stored.chain_id == "explicit-chain-one"
    assert stored.sequence_no == 7
    assert stored.details == values["details"]

    raw = session.execute(
        text(
            "SELECT event_type, event_hash, previous_event_hash, sequence_no, chain_id "
            "FROM mitigation_audit_events WHERE id = :id"
        ),
        {"id": stored.id},
    ).one()
    assert raw == (
        "decision_issued",
        OTHER_HASH,
        VALID_HASH,
        7,
        "explicit-chain-one",
    )


def test_duplicate_event_uuid_is_idempotent_and_never_overwrites(db_env):
    session, _factory, _engine = db_env
    shared_uuid = unique_uuid5()
    first = persist_audit_event(
        session,
        **audit_kwargs(event_uuid=shared_uuid, details={"decision_type": "allow"}),
    )
    second = persist_audit_event(
        session,
        **audit_kwargs(event_uuid=shared_uuid, details={"decision_type": "block"}),
    )

    assert first.created is True
    assert second.created is False
    assert second.event.id == first.event.id
    assert second.event.details == {"decision_type": "allow"}
    assert session.query(MitigationAuditEvent).count() == 1


@pytest.mark.parametrize(
    "change, expected_error",
    [
        ({"event_type": "enforcement_applied"}, AuditEventValidationError),
        ({"entity_type": "request"}, AuditEventValidationError),
        ({"event_uuid": str(uuid.uuid4())}, AuditEventValidationError),
        ({"entity_identifier": "raw-user@example.test"}, AuditEventValidationError),
        ({"actor_hash": "203.0.113.9"}, AuditEventValidationError),
        ({"event_hash": "raw-hash"}, AuditEventValidationError),
        ({"previous_event_hash": "sha512:" + "a" * 64}, AuditEventValidationError),
        ({"sequence_no": 0}, AuditEventValidationError),
        ({"chain_id": "chain with spaces"}, AuditEventValidationError),
        ({"actor_role": "Admin"}, AuditEventValidationError),
    ],
)
def test_invalid_enum_and_opaque_identifier_values_are_rejected(
    db_env, change, expected_error
):
    session, _factory, _engine = db_env

    with pytest.raises(expected_error):
        persist_audit_event(session, **audit_kwargs(**change))

    assert session.query(MitigationAuditEvent).count() == 0


@pytest.mark.parametrize(
    "details, expected_error",
    [
        ({"client_ip": "203.0.113.8"}, PrivacySensitiveDataError),
        ({"user_id": "raw-user-42"}, PrivacySensitiveDataError),
        ({"nested": {"token": "abc"}}, PrivacySensitiveDataError),
        ({"explanation_summary": "203.0.113.8"}, AuditEventValidationError),
        (["not", "an", "object"], AuditEventValidationError),
    ],
)
def test_privacy_sensitive_audit_details_are_rejected(db_env, details, expected_error):
    session, _factory, _engine = db_env

    with pytest.raises(expected_error):
        persist_audit_event(session, **audit_kwargs(details=details))

    assert session.query(MitigationAuditEvent).count() == 0


def test_duplicate_chain_sequence_conflict_is_not_silently_reused(db_env):
    session, _factory, _engine = db_env
    first = persist_audit_event(
        session,
        **audit_kwargs(chain_id="shared-chain", sequence_no=3),
    )
    with pytest.raises(AuditEventPersistenceError):
        persist_audit_event(
            session,
            **audit_kwargs(chain_id="shared-chain", sequence_no=3),
        )

    assert first.created is True
    assert session.query(MitigationAuditEvent).count() == 1


def test_foreign_key_restrictions_are_preserved(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    decision = persist_evaluated_decision(
        session,
        evaluated_decision(policy.policy_version),
        dedupe_key="audit-fk-decision",
    ).decision
    event = persist_audit_event(
        session,
        **audit_kwargs(policy_id=policy.id, decision_id=decision.id),
    )
    session.commit()

    session.delete(decision)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    assert session.query(MitigationAuditEvent).filter_by(id=event.event.id).first() is not None

    session.delete(policy)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_failed_insert_rolls_back_only_its_savepoint(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)

    with pytest.raises(AuditEventPersistenceError):
        persist_audit_event(session, **audit_kwargs(policy_id=999999))

    assert session.in_transaction() is True
    assert session.query(type(policy)).filter_by(policy_version="phase3-audit-1.0").first() is policy
    assert session.query(MitigationAuditEvent).count() == 0


def test_service_does_not_commit_caller_transaction(db_env):
    session, factory, _engine = db_env
    persist_audit_event(session, **audit_kwargs())

    assert session.in_transaction() is True
    session.rollback()

    checker = factory()
    try:
        assert checker.query(MitigationAuditEvent).count() == 0
    finally:
        checker.close()


def test_database_lookup_failure_is_wrapped_safely(db_env, monkeypatch, caplog):
    session, _factory, _engine = db_env
    secret = "phase3-audit-private-marker"

    def _fail(*_args, **_kwargs):
        raise SQLAlchemyError(secret)

    monkeypatch.setattr(audit_service, "_find_existing", _fail)

    with caplog.at_level("ERROR"):
        with pytest.raises(AuditEventPersistenceError) as exc_info:
            persist_audit_event(session, **audit_kwargs())

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None


def test_duplicate_event_uuid_integrity_error_recovers_existing_event(
    db_env, monkeypatch
):
    session, _factory, _engine = db_env
    shared_uuid = unique_uuid5()
    existing = persist_audit_event(
        session,
        **audit_kwargs(
            event_uuid=shared_uuid,
            chain_id="original-chain",
            details={"decision_type": "allow"},
        ),
    )

    original_find = audit_service._find_existing
    calls = []

    def _race_find(current_session, event_uuid):
        calls.append(event_uuid)
        if len(calls) == 1:
            return None
        return original_find(current_session, event_uuid)

    monkeypatch.setattr(audit_service, "_find_existing", _race_find)

    recovered = persist_audit_event(
        session,
        **audit_kwargs(
            event_uuid=shared_uuid,
            chain_id="different-chain",
            details={"decision_type": "block"},
        ),
    )

    assert len(calls) == 2
    assert recovered.created is False
    assert recovered.event.id == existing.event.id
    assert recovered.event.details == {"decision_type": "allow"}
    assert session.in_transaction() is True
    assert session.query(MitigationAuditEvent).count() == 1


def test_same_sequence_number_is_allowed_on_a_different_chain(db_env):
    session, _factory, _engine = db_env

    first = persist_audit_event(
        session,
        **audit_kwargs(chain_id="chain-a", sequence_no=5),
    )
    second = persist_audit_event(
        session,
        **audit_kwargs(chain_id="chain-b", sequence_no=5),
    )

    assert first.created is True
    assert second.created is True
    assert session.query(MitigationAuditEvent).count() == 2


@pytest.mark.parametrize(
    "field_name, raw_value",
    [
        ("chain_id", "203.0.113.10"),
        ("chain_id", "2001:db8::1"),
        ("entity_identifier", "203.0.113.11"),
        ("entity_identifier", "2001:db8::2"),
    ],
)
def test_raw_ip_in_opaque_audit_fields_is_rejected_without_opening_transaction(
    db_env, field_name, raw_value
):
    session, _factory, _engine = db_env
    assert session.in_transaction() is False

    with pytest.raises(AuditEventValidationError):
        persist_audit_event(session, **audit_kwargs(**{field_name: raw_value}))

    assert session.in_transaction() is False
    assert session.query(MitigationAuditEvent).count() == 0


@pytest.mark.parametrize(
    "details",
    [
        {"remote_addr": "203.0.113.7"},
        {"x_forwarded_for": "203.0.113.8"},
        {"explanation_summary": {"nested": {"x-api-key": "raw-key"}}},
        {"payload": {"query_string": "token=abc"}},
        {"authorization_header": "Bearer raw-token"},
    ],
)
def test_sensitive_aliases_and_nested_mappings_are_rejected(db_env, details):
    session, _factory, _engine = db_env

    with pytest.raises(PrivacySensitiveDataError):
        persist_audit_event(session, **audit_kwargs(details=details))

    assert session.query(MitigationAuditEvent).count() == 0


@pytest.mark.parametrize(
    "summary",
    [
        "caller at 203.0.113.9 was reviewed",
        "contact user@example.test before retry",
        "raw identifier 00000000-0000-4000-8000-000000000000",
    ],
)
def test_embedded_raw_identifiers_in_audit_details_are_rejected(
    db_env, summary, caplog
):
    session, _factory, _engine = db_env

    with caplog.at_level("ERROR"):
        with pytest.raises(AuditEventValidationError):
            persist_audit_event(
                session,
                **audit_kwargs(details={"explanation_summary": summary}),
            )

    assert summary not in caplog.text
    assert session.query(MitigationAuditEvent).count() == 0


def test_valid_opaque_uuid5_identifiers_continue_to_work(db_env):
    session, _factory, _engine = db_env
    opaque = unique_uuid5()

    result = persist_audit_event(
        session,
        **audit_kwargs(
            chain_id=opaque,
            entity_identifier=opaque,
            details={"explanation_summary": f"Correlated reference {opaque}."},
        ),
    )

    assert result.created is True
    assert result.event.chain_id == opaque
    assert result.event.entity_identifier == opaque


def test_transaction_setup_failure_is_generic_and_does_not_leak_diagnostics(
    db_env, monkeypatch, caplog
):
    session, _factory, _engine = db_env
    secret = "phase3-audit-transaction-private-marker"

    def _fail(_db):
        raise SQLAlchemyError(secret)

    monkeypatch.setattr(persistence_common, "ensure_outer_transaction", _fail)

    with caplog.at_level("ERROR"):
        with pytest.raises(AuditEventPersistenceError) as exc_info:
            persist_audit_event(session, **audit_kwargs())

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None
    assert session.in_transaction() is False
