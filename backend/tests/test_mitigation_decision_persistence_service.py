"""Focused decision persistence tests for Stage 2C Phase 3."""

from datetime import timedelta
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models.mitigation import MitigationDecision
from app.services import mitigation_decision_persistence_service as decision_service
from app.services import mitigation_persistence_common as persistence_common
from app.services.mitigation_persistence_common import (
    DecisionPersistenceError,
    DecisionPolicyNotFoundError,
    DecisionValidationError,
    DuplicateDecisionConflictError,
    PrivacySensitiveDataError,
)
from app.services.mitigation_decision_persistence_service import (
    persist_evaluated_decision,
)
from tests.mitigation_persistence_helpers import (
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


def _stored_policy(session, version="phase3-decision-1.0"):
    stored = policy_record(policy_version=version)
    session.add(stored)
    session.flush()
    return stored


def test_decision_round_trip_preserves_schema_values_and_advisory_only(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    evaluated = evaluated_decision(
        policy.policy_version,
        explanation="Monitor-only advisory recommendation.",
    )

    result = persist_evaluated_decision(session, evaluated, dedupe_key="decision-round-trip")

    assert result.created is True
    stored = result.decision
    assert stored.id is not None
    assert stored.policy_id == policy.id
    assert stored.decision_type == evaluated.decision.value
    assert stored.scope_type == evaluated.scope_type.value
    assert stored.attribution_status == evaluated.attribution_status.value
    assert stored.reason_codes == ["no_suspicious_evidence"]
    assert stored.evidence_references == evaluated.evidence_references
    assert stored.explanation == evaluated.explanation
    assert stored.issued_at == evaluated.issued_at
    assert stored.expires_at == evaluated.expires_at
    assert stored.advisory_only is True
    assert stored.dedupe_key == "decision-round-trip"

    raw = session.execute(
        text(
            "SELECT decision_type, advisory_only, policy_id, dedupe_key "
            "FROM mitigation_decisions WHERE id = :id"
        ),
        {"id": stored.id},
    ).one()
    assert raw == ("allow", 1, policy.id, "decision-round-trip")


def test_equivalent_retry_is_idempotent_and_never_overwrites(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    shared_reference = unique_uuid5()
    equivalent = evaluated_decision(
        policy.policy_version,
        explanation="Stable advisory explanation.",
        evidence_references=[shared_reference],
    )

    first = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="same-dedupe",
    )
    second = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="same-dedupe",
    )

    assert first.created is True
    assert second.created is False
    assert second.decision.id == first.decision.id
    assert second.decision.explanation == "Stable advisory explanation."
    assert session.query(MitigationDecision).count() == 1


def test_duplicate_decision_uuid_conflict_is_rejected(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    shared_uuid = unique_uuid5()

    persist_evaluated_decision(
        session,
        evaluated_decision(policy.policy_version),
        dedupe_key="uuid-owner",
        decision_uuid=shared_uuid,
    )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision(policy.policy_version),
            dedupe_key="different-dedupe",
            decision_uuid=shared_uuid,
        )

    assert session.query(MitigationDecision).count() == 1


@pytest.mark.parametrize(
    "change, expected_error",
    [
        ({"decision": "deny"}, DecisionValidationError),
        ({"scope_key_hash": "sha256:" + "A" * 64}, DecisionValidationError),
        ({"advisory_only": False}, DecisionValidationError),
        ({"client_ip": "203.0.113.44"}, PrivacySensitiveDataError),
        ({"request_body": {"secret": "value"}}, PrivacySensitiveDataError),
    ],
)
def test_invalid_and_privacy_sensitive_decision_inputs_are_rejected(
    db_env, change, expected_error
):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    payload = evaluated_decision(policy.policy_version).model_dump()
    payload.update(change)

    with pytest.raises(expected_error):
        persist_evaluated_decision(session, payload, dedupe_key="invalid-input")

    assert session.query(MitigationDecision).count() == 0


def test_missing_policy_version_is_rejected(db_env):
    session, _factory, _engine = db_env
    _stored_policy(session, "present-version")

    with pytest.raises(DecisionPolicyNotFoundError):
        persist_evaluated_decision(
            session,
            evaluated_decision("absent-version"),
            dedupe_key="missing-policy",
        )


def test_failed_insert_rolls_back_only_its_savepoint(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session, "rollback-policy")
    bad = evaluated_decision(
        policy.policy_version,
        expires_at=evaluated_decision(policy.policy_version).issued_at - timedelta(minutes=1),
    )

    with pytest.raises(DecisionPersistenceError):
        persist_evaluated_decision(session, bad, dedupe_key="invalid-expiry")

    assert session.in_transaction() is True
    assert session.query(type(policy)).filter_by(policy_version="rollback-policy").first() is policy
    assert session.query(MitigationDecision).count() == 0


def test_service_does_not_commit_caller_transaction(db_env):
    session, factory, _engine = db_env
    policy = _stored_policy(session)
    persist_evaluated_decision(
        session,
        evaluated_decision(policy.policy_version),
        dedupe_key="uncommitted-decision",
    )

    assert session.in_transaction() is True
    session.rollback()

    checker = factory()
    try:
        assert checker.query(MitigationDecision).count() == 0
    finally:
        checker.close()


def test_foreign_key_restriction_is_preserved(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    persist_evaluated_decision(
        session,
        evaluated_decision(policy.policy_version),
        dedupe_key="fk-decision",
    )
    session.commit()

    session.delete(policy)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_policy_resolution_failure_is_wrapped_safely(db_env, monkeypatch, caplog):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    secret = "phase3-decision-private-marker"

    def _fail(*_args, **_kwargs):
        raise SQLAlchemyError(secret)

    monkeypatch.setattr(decision_service, "load_policy_by_version", _fail)

    with caplog.at_level("ERROR"):
        with pytest.raises(DecisionValidationError) as exc_info:
            persist_evaluated_decision(
                session,
                evaluated_decision(policy.policy_version),
                dedupe_key="db-failure",
            )

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize("dedupe_key", ["203.0.113.10", "2001:db8::1"])
def test_raw_ip_dedupe_key_is_rejected_without_opening_transaction(db_env, dedupe_key):
    session, _factory, _engine = db_env
    assert session.in_transaction() is False

    with pytest.raises(DecisionValidationError):
        persist_evaluated_decision(
            session,
            evaluated_decision("phase3-decision-1.0"),
            dedupe_key=dedupe_key,
        )

    assert session.in_transaction() is False
    assert session.query(MitigationDecision).count() == 0


@pytest.mark.parametrize(
    "sensitive_input",
    [
        {"remote_addr": "203.0.113.7"},
        {"headers": {"x_forwarded_for": "203.0.113.7"}},
        {"nested": [{"userId": "raw-user-1"}]},
        {"credentials": {"passwd": "raw-password"}},
        {"payload": {"query_string": "token=abc"}},
        {"authorization_header": "Bearer raw-token"},
        {"x-api-key": "raw-api-key"},
    ],
)
def test_sensitive_aliases_and_nested_mappings_are_rejected(db_env, sensitive_input):
    session, _factory, _engine = db_env
    payload = evaluated_decision("phase3-decision-1.0").model_dump()
    payload.update(sensitive_input)

    with pytest.raises(PrivacySensitiveDataError):
        persist_evaluated_decision(session, payload, dedupe_key="sensitive-alias")

    assert session.query(MitigationDecision).count() == 0


@pytest.mark.parametrize(
    "explanation",
    [
        "caller at 203.0.113.9 was reviewed",
        "contact user@example.test before retry",
        "raw identifier 00000000-0000-4000-8000-000000000000",
    ],
)
def test_embedded_raw_identifiers_in_explanation_are_rejected(
    db_env, explanation, caplog
):
    session, _factory, _engine = db_env

    with caplog.at_level("ERROR"):
        with pytest.raises(DecisionValidationError):
            persist_evaluated_decision(
                session,
                evaluated_decision("phase3-decision-1.0", explanation=explanation),
                dedupe_key="embedded-raw",
            )

    assert explanation not in caplog.text
    assert session.query(MitigationDecision).count() == 0


def test_valid_opaque_uuid5_identifiers_continue_to_work(db_env):
    session, _factory, _engine = db_env
    _stored_policy(session, "phase3-decision-1.0")
    opaque = unique_uuid5()
    equivalent = evaluated_decision(
        "phase3-decision-1.0",
        explanation=f"Correlated opaque reference {opaque}.",
        evidence_references=[opaque],
    )

    first = persist_evaluated_decision(session, equivalent, dedupe_key=opaque)
    second = persist_evaluated_decision(session, equivalent, dedupe_key=opaque)

    assert first.created is True
    assert second.created is False
    assert second.decision.id == first.decision.id


def test_same_dedupe_key_with_conflicting_explicit_uuid_is_rejected(db_env):
    session, _factory, _engine = db_env
    _stored_policy(session)

    persist_evaluated_decision(
        session,
        evaluated_decision("phase3-decision-1.0"),
        dedupe_key="uuid-conflict-dedupe",
    )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision("phase3-decision-1.0"),
            dedupe_key="uuid-conflict-dedupe",
            decision_uuid=unique_uuid5(),
        )

    assert session.query(MitigationDecision).count() == 1


def test_same_dedupe_key_with_different_policy_version_is_rejected(db_env):
    session, _factory, _engine = db_env
    _stored_policy(session, "phase3-policy-v1")
    _stored_policy(session, "phase3-policy-v2")

    first = persist_evaluated_decision(
        session,
        evaluated_decision("phase3-policy-v1", explanation="Stable explanation."),
        dedupe_key="version-conflict-dedupe",
    )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision("phase3-policy-v2", explanation="Stable explanation."),
            dedupe_key="version-conflict-dedupe",
        )

    assert first.created is True
    assert session.query(MitigationDecision).count() == 1


def test_same_dedupe_key_with_materially_different_payload_is_rejected(db_env):
    session, _factory, _engine = db_env
    _stored_policy(session)

    first = persist_evaluated_decision(
        session,
        evaluated_decision("phase3-decision-1.0", explanation="First version."),
        dedupe_key="payload-conflict-dedupe",
    )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision("phase3-decision-1.0", explanation="Materially different."),
            dedupe_key="payload-conflict-dedupe",
        )

    assert first.created is True
    assert session.query(MitigationDecision).count() == 1


def test_integrity_error_recovers_existing_equivalent_decision(db_env, monkeypatch):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    shared_reference = unique_uuid5()
    equivalent = evaluated_decision(
        policy.policy_version,
        explanation="Recovered retry.",
        evidence_references=[shared_reference],
    )
    existing = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="integrity-recovery",
    )

    original_find = decision_service._find_existing
    calls = []

    def _race_find(current_session, *, dedupe_key, decision_uuid):
        calls.append((dedupe_key, decision_uuid))
        if len(calls) == 1:
            return None, None
        return original_find(
            current_session, dedupe_key=dedupe_key, decision_uuid=decision_uuid
        )

    monkeypatch.setattr(decision_service, "_find_existing", _race_find)

    recovered = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="integrity-recovery",
    )

    assert len(calls) == 2
    assert recovered.created is False
    assert recovered.decision.id == existing.decision.id
    assert session.in_transaction() is True
    assert session.query(MitigationDecision).count() == 1


def test_transaction_setup_failure_is_generic_and_does_not_leak_diagnostics(
    db_env, monkeypatch, caplog
):
    session, _factory, _engine = db_env
    secret = "phase3-decision-transaction-private-marker"

    def _fail(_db):
        raise SQLAlchemyError(secret)

    monkeypatch.setattr(persistence_common, "ensure_outer_transaction", _fail)

    with caplog.at_level("ERROR"):
        with pytest.raises(DecisionPersistenceError) as exc_info:
            persist_evaluated_decision(
                session,
                evaluated_decision("phase3-decision-1.0"),
                dedupe_key="transaction-setup-failure",
            )

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None
    assert session.in_transaction() is False


def test_invalid_created_at_is_rejected_without_opening_transaction(db_env):
    session, _factory, _engine = db_env
    assert session.in_transaction() is False

    with pytest.raises(DecisionValidationError):
        persist_evaluated_decision(
            session,
            evaluated_decision("phase3-decision-1.0"),
            dedupe_key="invalid-created-at",
            created_at="not-a-datetime",
        )

    assert session.in_transaction() is False
    assert session.query(MitigationDecision).count() == 0


def test_same_dedupe_key_and_same_explicit_uuid_is_idempotent(db_env):
    session, _factory, _engine = db_env
    policy = _stored_policy(session)
    shared_uuid = unique_uuid5()
    shared_reference = unique_uuid5()
    equivalent = evaluated_decision(
        policy.policy_version,
        explanation="Stable explicit-UUID decision.",
        evidence_references=[shared_reference],
    )

    first = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="explicit-uuid-retry",
        decision_uuid=shared_uuid,
    )
    second = persist_evaluated_decision(
        session,
        equivalent,
        dedupe_key="explicit-uuid-retry",
        decision_uuid=shared_uuid,
    )

    assert first.created is True
    assert second.created is False
    assert second.decision.id == first.decision.id
    assert second.decision.decision_uuid == shared_uuid


def test_existing_decision_lookup_failure_is_wrapped_safely(
    db_env, monkeypatch, caplog
):
    session, _factory, _engine = db_env
    _stored_policy(session)
    secret = "phase3-decision-lookup-private-marker"

    def _fail(*_args, **_kwargs):
        raise SQLAlchemyError(secret)

    monkeypatch.setattr(decision_service, "_find_existing", _fail)

    with caplog.at_level("ERROR"):
        with pytest.raises(DecisionPersistenceError) as exc_info:
            persist_evaluated_decision(
                session,
                evaluated_decision("phase3-decision-1.0"),
                dedupe_key="lookup-failure",
            )

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "change, keyword_overrides",
    [
        ({"policy_version": "x" * 65}, {}),
        ({"explanation": "x" * 2001}, {}),
        ({"issued_at": "not-a-datetime"}, {}),
        ({"expires_at": "not-a-datetime"}, {}),
        ({"rate_limit": 0}, {}),
        ({"rate_limit_window_seconds": 0}, {}),
        ({"decision": "deny"}, {}),
        ({"scope_key_hash": "sha256:" + "A" * 64}, {}),
        (
            {"evidence_references": ["00000000-0000-4000-8000-000000000000"]},
            {},
        ),
        ({}, {"decision_uuid": str(uuid.uuid4())}),
        ({}, {"dedupe_key": "203.0.113.10"}),
        ({}, {"created_at": "not-a-datetime"}),
    ],
)
def test_all_caller_validation_rejects_before_opening_transaction(
    db_env, change, keyword_overrides
):
    session, _factory, _engine = db_env
    assert session.in_transaction() is False

    payload = evaluated_decision("phase3-decision-1.0").model_dump()
    payload.update(change)
    kwargs = {"dedupe_key": "preflight-reject", **keyword_overrides}

    with pytest.raises(DecisionValidationError):
        persist_evaluated_decision(session, payload, **kwargs)

    assert session.in_transaction() is False
    # The session is still usable after every rejected input.
    assert session.query(MitigationDecision).count() == 0


def test_preflight_validation_preserves_valid_persistence_and_identity_contract(db_env):
    session, _factory, _engine = db_env
    v1 = _stored_policy(session, "preflight-v1")
    v2 = _stored_policy(session, "preflight-v2")
    shared_uuid = unique_uuid5()
    payload = evaluated_decision(
        v1.policy_version,
        explanation="Stable preflight explanation.",
    )

    first = persist_evaluated_decision(
        session,
        payload,
        dedupe_key="preflight-valid",
        decision_uuid=shared_uuid,
    )
    retry = persist_evaluated_decision(
        session,
        payload,
        dedupe_key="preflight-valid",
        decision_uuid=shared_uuid,
    )

    assert first.created is True
    assert retry.created is False
    assert retry.decision.id == first.decision.id
    assert session.in_transaction() is True

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision(
                v1.policy_version,
                explanation="Stable preflight explanation.",
                evidence_references=payload.evidence_references,
            ),
            dedupe_key="preflight-other-uuid",
            decision_uuid=shared_uuid,
        )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision(
                v1.policy_version,
                explanation="Different preflight payload.",
                evidence_references=payload.evidence_references,
            ),
            dedupe_key="preflight-valid",
            decision_uuid=shared_uuid,
        )

    with pytest.raises(DuplicateDecisionConflictError):
        persist_evaluated_decision(
            session,
            evaluated_decision(
                v2.policy_version,
                explanation="Stable preflight explanation.",
                evidence_references=payload.evidence_references,
            ),
            dedupe_key="preflight-valid",
            decision_uuid=shared_uuid,
        )

    assert session.query(MitigationDecision).count() == 1
