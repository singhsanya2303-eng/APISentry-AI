"""Focused C1 unit tests for audit-event integration.

All databases are isolated in-memory SQLite databases created by the accepted
project helpers. No configured database, PostgreSQL connection, migration, route,
or enforcement code is used.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from unittest.mock import Mock
import uuid

import pytest
from sqlalchemy import inspect as sa_inspect, text as sa_text

from app.models.mitigation import MitigationAuditEvent
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision as EvaluatedDecision,
    MitigationDecisionType,
    MitigationReasonCode,
    MitigationScopeType,
)
from app.schemas.mitigation_audit_integration import MitigationAuditEventStatus
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationDecisionOutcome,
    MitigationIntegrationResult,
    MitigationOutcomeStatus,
    VerifiedMitigationPrincipal,
)
from app.services import mitigation_audit_integration_service as service
from app.services.mitigation_audit_persistence_service import persist_audit_event
from app.services.mitigation_decision_persistence_service import persist_evaluated_decision
from tests.mitigation_persistence_helpers import (
    OTHER_HASH,
    VALID_HASH,
    audit_kwargs,
    evaluated_decision,
    policy_record,
    sqlite_session_factory,
    unique_uuid5,
)

ANALYST_HASH = "sha256:" + "a" * 64
ADMIN_HASH = "sha256:" + "c" * 64
POLICY_VERSION = "c1-policy-1.0"


@pytest.fixture
def db_env():
    engine, factory = sqlite_session_factory()
    session = factory()
    try:
        yield session, factory, engine
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def policy_env(db_env):
    session, _factory, _engine = db_env
    policy = policy_record(policy_version=POLICY_VERSION)
    session.add(policy)
    session.flush()
    return session, policy


def _verified_principal(role: str, actor_hash: str) -> VerifiedMitigationPrincipal:
    return VerifiedMitigationPrincipal(actor_key_hash=actor_hash, role=role)  # type: ignore[arg-type]


def _persist_decision(session, policy, **overrides):
    values = {"policy_version": policy.policy_version}
    values.update(overrides)
    decision = evaluated_decision(**values)
    persisted = persist_evaluated_decision(
        session,
        decision,
        dedupe_key="c1-" + uuid.uuid4().hex,
    )
    return decision, persisted.decision


def _verified_overrides(actor_hash: str) -> dict:
    return {
        "decision": MitigationDecisionType.MONITOR.value,
        "scope_type": MitigationScopeType.VERIFIED_USER.value,
        "scope_key_hash": actor_hash,
        "attribution_status": MitigationAttributionStatus.VERIFIED_USER.value,
        "verified_attribution": True,
        "reason_codes": [MitigationReasonCode.HUMAN_LIKE_NO_ACTION.value],
        "evidence_references": [unique_uuid5()],
    }


def _outcome(decision, decision_uuid, *, status=MitigationOutcomeStatus.PERSISTED, index=0):
    return MitigationDecisionOutcome(
        result_index=index,
        status=status,
        decision=decision,
        decision_uuid=decision_uuid,
    )


def _result(*outcomes):
    return MitigationIntegrationResult(outcomes=list(outcomes))


def _plan(decision, policy, *, mode=MitigationAuthenticationMode.API_KEY, principal=None):
    return service.build_decision_audit_event_plan(
        decision=decision,
        policy=policy,
        authentication_mode=mode,
        verified_principal=principal,
    )


def _digest_hex(plan):
    return plan.event_hash.split(":", 1)[1]


def _column(row, name):
    """Read a real persisted SQLAlchemy-mapped column value."""
    return sa_inspect(row).attrs[name].value


def _assert_no_sensitive_values_in_audit_columns(stored, sensitive_values):
    """Inspect the actual audit columns instead of relying on ``repr(stored)``."""
    columns = {
        name: _column(stored, name)
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


def _audit_content(**overrides):
    issued_at = datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc)
    values = {
        "domain": service._DIGEST_DOMAIN,
        "event_type": "decision_issued",
        "entity_type": "decision",
        "entity_identifier": unique_uuid5(),
        "decision_id": 1,
        "policy_id": 1,
        "policy_version": POLICY_VERSION,
        "decision_type": "allow",
        "scope_type": "unattributed",
        "scope_key_hash": None,
        "attribution_status": "missing",
        "verified_attribution": False,
        "actor_hash": None,
        "actor_role": None,
        "reason_codes": [MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE.value],
        "evidence_references": [unique_uuid5()],
        "issued_at": issued_at.isoformat(),
        "created_at": issued_at.isoformat(),
        "advisory_only": True,
        "details": {
            "advisory_only": True,
            "policy_version": POLICY_VERSION,
        },
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "role, actor_hash",
    [("analyst", ANALYST_HASH), ("admin", ADMIN_HASH)],
)
def test_exact_event_field_mapping_for_verified_principal(policy_env, role, actor_hash):
    session, policy = policy_env
    _decision, row = _persist_decision(session, policy, **_verified_overrides(actor_hash))
    result = _result(_outcome(_decision, row.decision_uuid))
    principal = _verified_principal(role, actor_hash)

    integration = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.JWT,
        verified_principal=principal,
    )

    assert integration.event_count == 1
    assert integration.skipped_count == 0
    assert integration.outcomes[0].status == MitigationAuditEventStatus.CREATED
    assert integration.outcomes[0].decision_uuid == row.decision_uuid
    assert integration.outcomes[0].event_uuid is not None

    stored = session.query(MitigationAuditEvent).one()
    assert stored.event_type == "decision_issued"
    assert stored.entity_type == "decision"
    assert stored.entity_identifier == row.decision_uuid
    assert stored.event_hash.startswith("sha256:")
    assert len(stored.event_hash) == 71
    assert stored.chain_id == "decision-" + row.decision_uuid
    assert stored.sequence_no == 1
    assert stored.previous_event_hash is None
    assert stored.policy_id == policy.id
    assert stored.decision_id == row.id
    assert stored.actor_hash == actor_hash
    assert stored.actor_role == role
    assert service._ensure_utc(stored.created_at) == row.issued_at
    assert stored.details == {
        "advisory_only": True,
        "attribution_status": "verified_user",
        "decision_type": "monitor",
        "evidence_reference_count": 1,
        "policy_version": POLICY_VERSION,
        "scope_type": "verified_user",
    }

    plan_again = service.build_decision_audit_event_plan(
        decision=row,
        policy=policy,
        authentication_mode=MitigationAuthenticationMode.JWT,
        verified_principal=principal,
    )
    assert plan_again.event_uuid == integration.outcomes[0].event_uuid
    assert plan_again.event_hash == stored.event_hash


def test_api_key_attribution_remains_missing(policy_env):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    result = _result(_outcome(decision, row.decision_uuid))

    integration = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    stored = session.query(MitigationAuditEvent).one()
    assert integration.event_count == 1
    assert stored.actor_hash is None
    assert stored.actor_role is None
    assert stored.details["attribution_status"] == "missing"
    assert stored.details["scope_type"] == "unattributed"


def test_real_builder_digest_changes_for_material_persisted_decision_fields(policy_env):
    """Builder-level proof that each material persisted decision field is hashed."""
    session, policy = policy_env
    evidence_reference = unique_uuid5()
    _decision, row = _persist_decision(
        session, policy, evidence_references=[evidence_reference]
    )
    baseline = _plan(row, policy)
    baseline_digest = _digest_hex(baseline)
    baseline_uuid = baseline.event_uuid

    assert baseline.sequence_no == 1
    assert baseline.previous_event_hash is None
    assert baseline.chain_id == "decision-" + row.decision_uuid

    changes = (
        ("decision_type", MitigationDecisionType.BLOCK.value),
        ("scope_type", MitigationScopeType.NETWORK_IP.value),
        ("reason_codes", [MitigationReasonCode.HUMAN_LIKE_NO_ACTION.value]),
        ("evidence_references", [unique_uuid5()]),
        ("issued_at", row.issued_at + timedelta(minutes=1)),
        ("decision_uuid", unique_uuid5()),
    )
    for field, changed_value in changes:
        original = getattr(row, field)
        setattr(row, field, changed_value)
        try:
            changed_plan = _plan(row, policy)
        finally:
            setattr(row, field, original)

        assert _digest_hex(changed_plan) != baseline_digest, field
        assert changed_plan.event_uuid != baseline_uuid, field
        if field == "decision_uuid":
            assert changed_plan.chain_id == "decision-" + changed_value


def test_real_builder_digest_changes_for_verified_actor_fields(policy_env):
    """Actor hash and role from a verified principal are part of the digest."""
    session, policy = policy_env
    _decision, row = _persist_decision(
        session, policy, **_verified_overrides(ANALYST_HASH)
    )
    baseline = _plan(
        row,
        policy,
        mode=MitigationAuthenticationMode.JWT,
        principal=_verified_principal("analyst", ANALYST_HASH),
    )

    original_scope_hash = row.scope_key_hash
    row.scope_key_hash = ADMIN_HASH
    try:
        changed_hash_plan = _plan(
            row,
            policy,
            mode=MitigationAuthenticationMode.JWT,
            principal=_verified_principal("analyst", ADMIN_HASH),
        )
    finally:
        row.scope_key_hash = original_scope_hash

    changed_role_plan = _plan(
        row,
        policy,
        mode=MitigationAuthenticationMode.JWT,
        principal=_verified_principal("admin", ANALYST_HASH),
    )

    assert _digest_hex(changed_hash_plan) != _digest_hex(baseline)
    assert changed_hash_plan.event_uuid != baseline.event_uuid
    assert _digest_hex(changed_role_plan) != _digest_hex(baseline)
    assert changed_role_plan.event_uuid != baseline.event_uuid


def test_real_builder_ignores_non_digest_decision_metadata(policy_env):
    """Non-digest row metadata cannot alter either the digest or event UUID."""
    session, policy = policy_env
    _decision, row = _persist_decision(session, policy)
    baseline = _plan(row, policy)
    baseline_digest = _digest_hex(baseline)

    ignored_changes = (
        ("explanation", "A different advisory-only explanation."),
        ("expires_at", row.issued_at + timedelta(hours=1)),
        ("rate_limit", 120),
        ("rate_limit_window_seconds", 120),
        (
            "created_at",
            datetime(2026, 2, 10, 11, 0, tzinfo=timezone.utc),
        ),
        ("dedupe_key", "c1-different-dedupe-key"),
    )
    for field, changed_value in ignored_changes:
        original = getattr(row, field)
        setattr(row, field, changed_value)
        try:
            unchanged_plan = _plan(row, policy)
        finally:
            setattr(row, field, original)

        assert _digest_hex(unchanged_plan) == baseline_digest, field
        assert unchanged_plan.event_uuid == baseline.event_uuid, field


def test_idempotent_reuse_decision_outcome_still_creates_one_audit_event(policy_env):
    """An eligible Stage A IDEMPOTENT_REUSE outcome is audited once, then reused."""
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    outcome = _outcome(
        decision,
        row.decision_uuid,
        status=MitigationOutcomeStatus.IDEMPOTENT_REUSE,
    )
    result = _result(outcome)

    first = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    stored = session.query(MitigationAuditEvent).one()
    snapshot = (
        stored.id,
        stored.event_uuid,
        stored.event_hash,
        stored.details,
        stored.created_at,
    )

    second = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert first.event_count == 1
    assert first.outcomes[0].status == MitigationAuditEventStatus.CREATED
    assert second.event_count == 1
    assert second.outcomes[0].status == MitigationAuditEventStatus.IDEMPOTENT_REUSE
    assert session.query(MitigationAuditEvent).count() == 1
    again = session.query(MitigationAuditEvent).one()
    assert (
        again.id,
        again.event_uuid,
        again.event_hash,
        again.details,
        again.created_at,
    ) == snapshot


def test_duplicate_eligible_outcomes_share_one_row_but_count_two(policy_env):
    """Document current behavior: event_count counts outcome attempts, not rows.

    Both outcomes are eligible and reference the same persisted decision UUID, so
    the deterministic UUID produces one stored audit row. The current C1 result
    still reports ``event_count == 2`` because it counts eligible outcomes. This
    test records that ambiguity without changing production code.
    """
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    result = _result(
        _outcome(decision, row.decision_uuid, index=0),
        _outcome(decision, row.decision_uuid, index=1),
    )

    integration = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert [item.status for item in integration.outcomes] == [
        MitigationAuditEventStatus.CREATED,
        MitigationAuditEventStatus.IDEMPOTENT_REUSE,
    ]
    assert [item.created for item in integration.outcomes] == [True, False]
    assert integration.outcomes[0].event_uuid == integration.outcomes[1].event_uuid
    # Ambiguous/misleading: two outcomes are counted, but only one event exists.
    assert integration.event_count == 2
    assert integration.skipped_count == 0
    stored = session.query(MitigationAuditEvent).all()
    assert len(stored) == 1
    assert stored[0].event_uuid == integration.outcomes[0].event_uuid


def test_digest_and_uuid_are_deterministic_and_change_with_material_content():
    content = _audit_content()
    digest = service._content_digest(content)
    event_uuid = service._event_uuid(digest)

    assert digest == service._content_digest(_audit_content(**content))
    assert event_uuid == service._event_uuid(digest)
    assert service._UUID5_PATTERN.fullmatch(event_uuid) is not None

    changes = {
        "decision_type": "block",
        "policy_version": "c1-policy-2.0",
        "reason_codes": [MitigationReasonCode.HUMAN_LIKE_NO_ACTION.value],
        "evidence_references": [unique_uuid5()],
        "actor_role": "admin",
        "created_at": datetime(2026, 2, 10, 10, 0, tzinfo=timezone.utc).isoformat(),
        "details": {"advisory_only": True, "policy_version": "c1-policy-2.0"},
    }
    for field, changed_value in changes.items():
        altered = dict(content)
        altered[field] = changed_value
        assert service._content_digest(altered) != digest
        assert service._event_uuid(service._content_digest(altered)) != event_uuid


def test_chain_metadata_is_excluded_from_content_digest():
    content = _audit_content()
    digest = service._content_digest(content)
    with_chain = dict(content)
    with_chain.update(
        {
            "chain_id": "a-different-chain",
            "sequence_no": 99,
            "previous_event_hash": OTHER_HASH,
        }
    )

    assert service._content_digest(with_chain) == digest
    canonical = service._canonical_content(with_chain)
    assert not {"chain_id", "sequence_no", "previous_event_hash"} & set(canonical)
    assert "id" not in canonical


def test_created_at_equals_utc_normalized_issued_at(policy_env):
    session, policy = policy_env
    offset = timezone(timedelta(hours=5, minutes=30))
    issued_at = datetime(2026, 2, 10, 14, 30, tzinfo=offset)
    expected_utc = datetime(2026, 2, 10, 9, 0, tzinfo=timezone.utc)
    decision, row = _persist_decision(session, policy, issued_at=issued_at)
    result = _result(_outcome(decision, row.decision_uuid))

    integration = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    stored = session.query(MitigationAuditEvent).one()
    assert integration.outcomes[0].event_uuid is not None
    assert row.issued_at == expected_utc
    assert service._ensure_utc(stored.created_at) == expected_utc


def test_identical_retry_is_reported_as_safe_idempotent_reuse(policy_env):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    result = _result(_outcome(decision, row.decision_uuid))

    first = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    first_event = session.query(MitigationAuditEvent).one()
    second = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert first.outcomes[0].status == MitigationAuditEventStatus.CREATED
    assert first.outcomes[0].created is True
    assert second.outcomes[0].status == MitigationAuditEventStatus.IDEMPOTENT_REUSE
    assert second.outcomes[0].created is False
    assert first.outcomes[0].event_uuid == second.outcomes[0].event_uuid
    assert session.query(MitigationAuditEvent).count() == 1
    assert session.query(MitigationAuditEvent).one().id == first_event.id


def test_existing_uuid_with_different_digest_raises_conflict_without_overwrite(policy_env):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    result = _result(_outcome(decision, row.decision_uuid))

    service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    stored = session.query(MitigationAuditEvent).one()
    original_hash = stored.event_hash
    original_details = dict(stored.details)
    stored.event_hash = OTHER_HASH
    session.flush()

    with pytest.raises(service.MitigationAuditConflictError):
        service.persist_decision_audit_events(
            session,
            result,
            authentication_mode=MitigationAuthenticationMode.API_KEY,
        )

    session.expire_all()
    stored = session.query(MitigationAuditEvent).one()
    assert session.query(MitigationAuditEvent).count() == 1
    assert stored.event_hash == OTHER_HASH
    assert stored.event_hash != original_hash
    assert stored.details == original_details


def test_non_persisted_outcomes_are_skipped_without_events(db_env):
    session, _factory, _engine = db_env
    outcomes = [
        _outcome(None, None, status=status, index=index)
        for index, status in enumerate(
            (
                MitigationOutcomeStatus.POLICY_UNAVAILABLE,
                MitigationOutcomeStatus.DECISION_NOT_PERSISTED,
                MitigationOutcomeStatus.CONFLICT,
            )
        )
    ]

    integration = service.persist_decision_audit_events(
        session,
        _result(*outcomes),
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert integration.event_count == 0
    assert integration.skipped_count == 3
    assert all(
        item.status == MitigationAuditEventStatus.SKIPPED
        for item in integration.outcomes
    )
    assert session.query(MitigationAuditEvent).count() == 0


def test_integration_service_never_commits_or_rolls_back(policy_env):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    result = _result(_outcome(decision, row.decision_uuid))
    session.commit = Mock(side_effect=AssertionError("commit must not be called"))  # type: ignore[method-assign]
    session.rollback = Mock(side_effect=AssertionError("rollback must not be called"))  # type: ignore[method-assign]

    integration = service.persist_decision_audit_events(
        session,
        result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert integration.event_count == 1
    session.commit.assert_not_called()  # type: ignore[attr-defined]
    session.rollback.assert_not_called()  # type: ignore[attr-defined]


def test_no_sensitive_values_in_success_output_or_persisted_audit_columns(policy_env):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy)
    safe_result = _result(_outcome(decision, row.decision_uuid))

    success = service.persist_decision_audit_events(
        session,
        safe_result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    success_text = json.dumps(success.model_dump(mode="json"), sort_keys=True)
    sensitive_values = (
        decision.explanation,
        "alice@example.test",
        "203.0.113.9",
        "Bearer raw-jwt-token",
        "api-key-secret",
    )
    for value in sensitive_values:
        assert value not in success_text

    api_key_stored = session.query(MitigationAuditEvent).one()
    columns = _assert_no_sensitive_values_in_audit_columns(
        api_key_stored, sensitive_values
    )
    assert columns["entity_identifier"] == row.decision_uuid
    assert columns["actor_hash"] is None
    assert columns["actor_role"] is None
    assert columns["event_hash"].startswith("sha256:")
    assert columns["details"] == {
        "advisory_only": True,
        "attribution_status": "missing",
        "decision_type": "allow",
        "evidence_reference_count": 1,
        "policy_version": POLICY_VERSION,
        "scope_type": "unattributed",
    }
    assert set(columns["details"]) <= service._DETAIL_KEYS

    verified_decision, verified_row = _persist_decision(
        session, policy, **_verified_overrides(ANALYST_HASH)
    )
    verified_result = _result(_outcome(verified_decision, verified_row.decision_uuid))
    principal = _verified_principal("analyst", ANALYST_HASH)
    service.persist_decision_audit_events(
        session,
        verified_result,
        authentication_mode=MitigationAuthenticationMode.JWT,
        verified_principal=principal,
    )
    verified_stored = (
        session.query(MitigationAuditEvent)
        .filter(MitigationAuditEvent.decision_id == verified_row.id)
        .one()
    )
    verified_columns = _assert_no_sensitive_values_in_audit_columns(
        verified_stored, sensitive_values
    )
    assert verified_columns["actor_hash"] == ANALYST_HASH
    assert verified_columns["actor_role"] == "analyst"
    assert verified_columns["entity_identifier"] == verified_row.decision_uuid
    assert set(verified_columns["details"]) <= service._DETAIL_KEYS


def test_logged_persistence_failure_never_leaks_sensitive_values_or_raw_errors(
    policy_env, caplog
):
    """A real SQLite insert failure must produce only safe, sanitized logs."""
    session, policy = policy_env
    # The database error itself intentionally carries raw sensitive-looking text,
    # SQL, and a traceback marker. Safe logging must not echo any of it.
    session.execute(
        sa_text(
            """
            CREATE TRIGGER c1_reject_audit_insert
            BEFORE INSERT ON mitigation_audit_events
            BEGIN
                SELECT RAISE(ABORT, 'alice@example.test 203.0.113.9 Bearer raw-jwt-token api-key-secret SELECT * FROM mitigation_audit_events Traceback (most recent call last)');
            END
            """
        )
    )
    explanation_marker = "SENSITIVE-OPAQUE-REF-C1"
    decision, row = _persist_decision(
        session,
        policy,
        explanation=f"Opaque marker {explanation_marker}",
    )
    result = _result(_outcome(decision, row.decision_uuid))

    with caplog.at_level(logging.ERROR):
        with pytest.raises(service.MitigationAuditPersistenceFailure):
            service.persist_decision_audit_events(
                session,
                result,
                authentication_mode=MitigationAuthenticationMode.API_KEY,
            )

    service_loggers = {
        service.logger.name,
        "apisentry.persistence.mitigation.audit",
    }
    service_records = [
        record for record in caplog.records if record.name in service_loggers
    ]
    log_text = "\n".join(record.getMessage() for record in service_records)
    assert log_text
    assert "Decision audit event persistence failed" in log_text
    assert (
        "Audit event insert violated a database constraint" in log_text
        or "Audit event insert failed" in log_text
    )

    sensitive_values = (
        "alice@example.test",
        "203.0.113.9",
        "Bearer raw-jwt-token",
        "api-key-secret",
        explanation_marker,
    )
    for value in sensitive_values:
        assert value not in log_text
        assert value not in caplog.text

    upper_log_text = log_text.upper()
    for raw_marker in (
        "SELECT",
        "TRACEBACK",
        "MOST RECENT CALL LAST",
        "RAISE(ABORT",
        "SQLALCHEMY.EXC",
        "FILE ",
        "LINE ",
    ):
        assert raw_marker not in upper_log_text

    assert session.query(MitigationAuditEvent).count() == 0


@pytest.mark.parametrize(
    "change, authentication_mode, principal, expected_error",
    [
        ("missing_decision", MitigationAuthenticationMode.API_KEY, None, service.MitigationAuditValidationError),
        ("missing_uuid", MitigationAuthenticationMode.API_KEY, None, service.MitigationAuditValidationError),
        ("invalid_uuid", MitigationAuthenticationMode.API_KEY, None, service.MitigationAuditValidationError),
        ("unknown_uuid", MitigationAuthenticationMode.API_KEY, None, service.MitigationAuditValidationError),
        ("jwt_without_principal", MitigationAuthenticationMode.JWT, None, service.MitigationAuditValidationError),
        ("api_key_with_principal", MitigationAuthenticationMode.API_KEY, "analyst", service.MitigationAuditValidationError),
        ("viewer_principal", MitigationAuthenticationMode.JWT, "viewer", service.MitigationAuditValidationError),
    ],
)
def test_invalid_or_incomplete_data_fails_safely(
    policy_env, change, authentication_mode, principal, expected_error
):
    session, policy = policy_env
    decision, row = _persist_decision(session, policy, **_verified_overrides(ANALYST_HASH))
    decision_uuid = row.decision_uuid
    outcome_decision = decision

    if change == "missing_decision":
        outcome_decision = None
    elif change == "missing_uuid":
        decision_uuid = None
    elif change == "invalid_uuid":
        decision_uuid = str(uuid.uuid4())
    elif change == "unknown_uuid":
        decision_uuid = unique_uuid5()

    result = _result(_outcome(outcome_decision, decision_uuid))
    verified_principal = None
    if principal == "analyst":
        verified_principal = _verified_principal("analyst", ANALYST_HASH)
    elif principal == "viewer":
        verified_principal = _verified_principal("viewer", VALID_HASH)

    with pytest.raises(expected_error):
        service.persist_decision_audit_events(
            session,
            result,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )

    assert session.query(MitigationAuditEvent).count() == 0


def test_accepted_audit_persistence_contract_stores_chain_data_as_data(db_env):
    session, _factory, _engine = db_env
    values = audit_kwargs(
        event_hash=VALID_HASH,
        previous_event_hash=OTHER_HASH,
        chain_id="accepted-chain-one",
        sequence_no=7,
        details={"decision_type": "allow", "evidence_reference_count": 2},
    )

    result = persist_audit_event(session, **values)

    assert result.created is True
    assert result.event.event_hash == VALID_HASH
    assert result.event.previous_event_hash == OTHER_HASH
    assert result.event.chain_id == "accepted-chain-one"
    assert result.event.sequence_no == 7
    assert result.event.details == values["details"]
