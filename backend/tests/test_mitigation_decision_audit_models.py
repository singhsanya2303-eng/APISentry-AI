"""Focused Stage 2C Phase 2 decision and audit model tests.

All databases in this module are isolated in-memory or temporary SQLite
databases. No configured development or production database is contacted, and
no hash-chain writer, persistence service, or request-enforcement code is
exercised.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event as sa_event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.models import (
    MitigationAttributionStatus,
    MitigationAuditEntityType,
    MitigationAuditEvent,
    MitigationAuditEventType,
    MitigationDecision,
    MitigationDecisionType,
    MitigationPolicy,
    MitigationScopeType,
)
from app.models import mitigation as mitigation_models
from app.schemas.mitigation import (
    MitigationAttributionStatus as SchemaAttributionStatus,
    MitigationDecisionType as SchemaDecisionType,
    MitigationScopeType as SchemaScopeType,
)

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
BASELINE_REVISION = "0001_baseline_existing_schema"
PHASE1_REVISION = "0002_mitigation_policy_models"
PHASE2_REVISION = "0003_mitigation_decision_audit"
HEAD_REVISION = "0004_revoked_tokens"
BASELINE_TABLES = {"api_traffic_logs", "users"}
PHASE1_TABLES = {
    "mitigation_policies",
    "mitigation_policy_state",
    "mitigation_policy_activation_events",
}
PHASE2_TABLES = {"mitigation_decisions", "mitigation_audit_events"}
PHASE3_TABLES = {"revoked_tokens"}
_VALID_HASH = "sha256:" + "a" * 64
_OTHER_HASH = "sha256:" + "b" * 64
_DECISION_INSERT_COLUMNS = (
    "id, decision_uuid, decision_type, scope_type, scope_key_hash, "
    "attribution_status, verified_attribution, reason_codes, explanation, "
    "policy_id, evidence_references, issued_at, expires_at, rate_limit, "
    "rate_limit_window_seconds, dedupe_key, created_at"
)
_DECISION_INSERT_VALUES = (
    ":id, :decision_uuid, :decision_type, :scope_type, :scope_key_hash, "
    ":attribution_status, :verified_attribution, :reason_codes, :explanation, "
    ":policy_id, :evidence_references, :issued_at, :expires_at, :rate_limit, "
    ":rate_limit_window_seconds, :dedupe_key, :created_at"
)
_AUDIT_INSERT_SQL = text(
    "INSERT INTO mitigation_audit_events ("
    "id, event_uuid, event_type, entity_type, entity_identifier, policy_id, "
    "decision_id, actor_hash, actor_role, details, previous_event_hash, "
    "event_hash, sequence_no, chain_id, created_at"
    ") VALUES ("
    ":id, :event_uuid, :event_type, :entity_type, :entity_identifier, :policy_id, "
    ":decision_id, :actor_hash, :actor_role, :details, :previous_event_hash, "
    ":event_hash, :sequence_no, :chain_id, :created_at"
    ")"
)


@pytest.fixture
def session_factory():
    """Provide an isolated in-memory SQLite session factory with FKs enabled."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def alembic_config(tmp_path, monkeypatch):
    """Point Alembic at an isolated temporary SQLite file via settings."""
    url = "sqlite:///" + (tmp_path / "phase2-private-marker.db").as_posix()
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    return Config(str(ALEMBIC_INI)), url


def _inspector(url):
    engine = create_engine(url)
    try:
        return engine, inspect(engine)
    except Exception:
        engine.dispose()
        raise


def _uuid5(label):
    """Return a deterministic lowercase UUID5 accepted by the DB checks."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"apisentry-phase2:{label}"))


def _unique_uuid5():
    return _uuid5(uuid.uuid4().hex)


def _policy(version="phase2-1.0.0", **overrides):
    values = {
        "creator_hash": _VALID_HASH,
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationPolicy(policy_version=version, **values)


def _decision(policy_id, **overrides):
    issued_at = datetime.now(timezone.utc)
    values = {
        "decision_uuid": _unique_uuid5(),
        "decision_type": MitigationDecisionType.ALLOW,
        "scope_type": MitigationScopeType.UNATTRIBUTED,
        "scope_key_hash": None,
        "attribution_status": MitigationAttributionStatus.MISSING,
        "verified_attribution": False,
        "reason_codes": ["no_suspicious_evidence"],
        "explanation": "Advisory-only decision; no request enforcement performed.",
        "policy_id": policy_id,
        "evidence_references": [],
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(minutes=5),
        "advisory_only": True,
        "dedupe_key": "dedupe-" + uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationDecision(**values)


def _audit_event(**overrides):
    values = {
        "event_uuid": _unique_uuid5(),
        "event_type": MitigationAuditEventType.DECISION_ISSUED,
        "entity_type": MitigationAuditEntityType.DECISION,
        "entity_identifier": "decision-" + uuid.uuid4().hex,
        "policy_id": None,
        "decision_id": None,
        "actor_hash": None,
        "actor_role": None,
        "details": None,
        "previous_event_hash": None,
        "event_hash": _VALID_HASH,
        "sequence_no": 1,
        "chain_id": "chain-" + uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationAuditEvent(**values)


def _decision_insert_sql(*, include_advisory_only):
    columns = _DECISION_INSERT_COLUMNS
    values = _DECISION_INSERT_VALUES
    if include_advisory_only:
        columns += ", advisory_only"
        values += ", :advisory_only"
    return text(f"INSERT INTO mitigation_decisions ({columns}) VALUES ({values})")


def _decision_sql_params(policy_id, *, decision_id=None, **overrides):
    issued_at = "2026-02-10 09:30:00"
    params = {
        "id": decision_id or 9100,
        "decision_uuid": _unique_uuid5(),
        "decision_type": "allow",
        "scope_type": "unattributed",
        "scope_key_hash": None,
        "attribution_status": "missing",
        "verified_attribution": 0,
        "reason_codes": json.dumps(["no_suspicious_evidence"]),
        "explanation": "Advisory-only direct insert.",
        "policy_id": policy_id,
        "evidence_references": json.dumps([]),
        "issued_at": issued_at,
        "expires_at": "2026-02-10 09:35:00",
        "rate_limit": None,
        "rate_limit_window_seconds": None,
        "advisory_only": 1,
        "dedupe_key": "direct-" + uuid.uuid4().hex,
        "created_at": "2026-02-10 09:30:00",
    }
    params.update(overrides)
    return params


def _audit_sql_params(*, event_id=9200, **overrides):
    params = {
        "id": event_id,
        "event_uuid": _unique_uuid5(),
        "event_type": "decision_issued",
        "entity_type": "decision",
        "entity_identifier": "decision-direct",
        "policy_id": None,
        "decision_id": None,
        "actor_hash": None,
        "actor_role": None,
        "details": json.dumps({"decision_type": "allow"}),
        "previous_event_hash": None,
        "event_hash": _VALID_HASH,
        "sequence_no": 1,
        "chain_id": "chain-direct",
        "created_at": "2026-02-10 09:30:00",
    }
    params.update(overrides)
    return params


def _normalize_check(value):
    return "".join(str(value).lower().replace('"', "").split())


def _check_constraints(inspector, table_name):
    return {
        (constraint["name"], _normalize_check(constraint["sqltext"]))
        for constraint in inspector.get_check_constraints(table_name)
    }


def _expected_checks(table):
    return {
        (constraint.name, _normalize_check(constraint.sqltext))
        for constraint in table.constraints
        if hasattr(constraint, "sqltext")
    }


def _table_fingerprint(inspector, table_name):
    columns = {
        column["name"]: bool(column["nullable"])
        for column in inspector.get_columns(table_name)
    }
    primary_key = set(
        inspector.get_pk_constraint(table_name).get("constrained_columns", []) or []
    )
    indexes = {
        index["name"]: (
            tuple(index.get("column_names") or []),
            bool(index.get("unique")),
        )
        for index in inspector.get_indexes(table_name)
    }
    return columns, primary_key, indexes


def _expected_fingerprint(table):
    return (
        {column.name: bool(column.nullable) for column in table.columns},
        {column.name for column in table.primary_key.columns},
        {
            index.name: (
                tuple(column.name for column in index.columns),
                bool(index.unique),
            )
            for index in table.indexes
        },
    )


def _foreign_keys(inspector, table_name):
    return {
        (
            foreign_key["name"],
            tuple(foreign_key["constrained_columns"]),
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
            (foreign_key.get("options") or {}).get("ondelete"),
        )
        for foreign_key in inspector.get_foreign_keys(table_name)
    }


# ---------------------------------------------------------------------------
# Model behavior
# ---------------------------------------------------------------------------


def test_phase2_models_are_registered_with_stage2b_value_contracts():
    tables = set(Base.metadata.tables)

    assert BASELINE_TABLES.issubset(tables)
    assert PHASE1_TABLES.issubset(tables)
    assert PHASE2_TABLES.issubset(tables)
    assert [member.value for member in MitigationDecisionType] == [
        member.value for member in SchemaDecisionType
    ]
    assert [member.value for member in MitigationScopeType] == [
        member.value for member in SchemaScopeType
    ]
    assert [member.value for member in MitigationAttributionStatus] == [
        member.value for member in SchemaAttributionStatus
    ]
    assert {
        MitigationAuditEventType.ENFORCEMENT_APPLIED_RESERVED.value,
        MitigationAuditEventType.ENFORCEMENT_REMOVED_RESERVED.value,
    }.issubset({member.value for member in MitigationAuditEventType})

    raw_fields = {
        "actor_id",
        "client_ip",
        "api_key",
        "token",
        "credential",
        "cookie",
        "user_agent",
        "query_values",
        "request_body",
        "raw_request_id",
    }
    for table in (MitigationDecision.__table__, MitigationAuditEvent.__table__):
        assert raw_fields.isdisjoint({column.name for column in table.columns})


def test_valid_decision_round_trips_with_advisory_default(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        decision = _decision(policy.id, evidence_references=[_unique_uuid5()])
        assert decision.created_at.tzinfo is timezone.utc
        session.add(decision)
        session.commit()
        session.expire(decision)

        assert decision.id is not None
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            decision.decision_uuid,
        )
        assert decision.decision_type.value == "allow"
        assert decision.scope_type.value == "unattributed"
        assert decision.attribution_status.value == "missing"
        assert decision.verified_attribution is False
        assert decision.reason_codes == ["no_suspicious_evidence"]
        assert decision.evidence_references[0] == decision.evidence_references[0]
        assert len(decision.evidence_references) == 1
        assert decision.advisory_only is True
        assert decision.expires_at > decision.issued_at
        assert session.query(MitigationDecision).count() == 1

        stored = session.execute(
            text(
                "SELECT decision_type, scope_type, attribution_status, advisory_only "
                "FROM mitigation_decisions"
            )
        ).one()
        assert stored == ("allow", "unattributed", "missing", 1)


@pytest.mark.parametrize(
    "field, invalid_value",
    [
        ("decision_type", "deny"),
        ("decision_type", "ALLOW"),
        ("scope_type", "unknown"),
        ("scope_type", "verified-user"),
        ("attribution_status", "trusted"),
        ("attribution_status", "Verified_User"),
    ],
)
def test_invalid_decision_enum_values_are_rejected(field, invalid_value):
    with pytest.raises(ValueError):
        _decision(1, **{field: invalid_value})


def test_all_stage2b_decision_enums_are_accepted():
    for decision_type in MitigationDecisionType:
        assert _decision(1, decision_type=decision_type).decision_type == decision_type.value
    for scope_type in MitigationScopeType:
        assert _decision(1, scope_type=scope_type).scope_type == scope_type.value
    for status in MitigationAttributionStatus:
        assert _decision(1, attribution_status=status).attribution_status == status.value


@pytest.mark.parametrize("valid_hash", [None, _VALID_HASH])
def test_valid_scope_hash_is_accepted(valid_hash):
    decision = _decision(1, scope_key_hash=valid_hash)
    assert decision.scope_key_hash == valid_hash


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "",
        "not-a-hash",
        "sha256:" + "A" * 64,
        "sha512:" + "a" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "203.0.113.44",
        "raw-user-id-42",
        12345,
    ],
)
def test_invalid_scope_hash_is_rejected(invalid_hash):
    with pytest.raises(ValueError):
        _decision(1, scope_key_hash=invalid_hash)


def test_evidence_references_must_be_opaque_uuid5_values():
    valid = [_unique_uuid5(), _unique_uuid5()]
    decision = _decision(1, evidence_references=valid)
    assert decision.evidence_references == valid

    assert _decision(1, evidence_references=None).evidence_references == []
    assert _decision(1, evidence_references=[]).evidence_references == []

    invalid_values = [
        ["raw-request-id-123"],
        [str(uuid.uuid4())],
        [_unique_uuid5().upper()],
        [{"request_id": "raw"}],
        ["not-a-uuid"],
        "not-a-list",
    ]
    for invalid in invalid_values:
        with pytest.raises(ValueError):
            _decision(1, evidence_references=invalid)

    duplicates = [valid[0], valid[0]]
    assert _decision(1, evidence_references=duplicates).evidence_references == [valid[0]]


def test_reason_codes_are_validated_and_deduplicated():
    assert _decision(1, reason_codes=None).reason_codes == []
    assert _decision(
        1, reason_codes=["no_suspicious_evidence", "no_suspicious_evidence"]
    ).reason_codes == ["no_suspicious_evidence"]

    for invalid in (["raw request"], ["has-hyphen"], "no_suspicious_evidence", [123]):
        with pytest.raises(ValueError):
            _decision(1, reason_codes=invalid)


def test_advisory_only_is_enforced_in_application_and_database(session_factory):
    with pytest.raises(ValueError):
        _decision(1, advisory_only=False)

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        session.execute(
            _decision_insert_sql(include_advisory_only=False),
            _decision_sql_params(policy.id, decision_id=9300),
        )
        session.commit()
        assert (
            session.execute(
                text("SELECT advisory_only FROM mitigation_decisions WHERE id = 9300")
            ).scalar()
            == 1
        )

        with pytest.raises(IntegrityError):
            session.execute(
                _decision_insert_sql(include_advisory_only=True),
                _decision_sql_params(
                    policy.id,
                    decision_id=9301,
                    advisory_only=0,
                ),
            )
            session.commit()
        session.rollback()

        assert session.query(MitigationDecision).count() == 1


def test_decision_uuid_and_dedupe_key_are_unique(session_factory):
    shared_uuid = _unique_uuid5()
    shared_dedupe = "shared-dedupe"

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        session.add(
            _decision(
                policy.id,
                decision_uuid=shared_uuid,
                dedupe_key=shared_dedupe,
            )
        )
        session.add(
            _decision(
                policy.id,
                decision_uuid=_unique_uuid5(),
                dedupe_key=shared_dedupe,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(
            _decision(
                policy.id,
                decision_uuid=shared_uuid,
                dedupe_key="uuid-dedupe-1",
            )
        )
        session.add(
            _decision(
                policy.id,
                decision_uuid=shared_uuid,
                dedupe_key="uuid-dedupe-2",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_expiry_rule_and_phase2_indexes(session_factory):
    indexes = {
        index.name: ([column.name for column in index.columns], bool(index.unique))
        for index in MitigationDecision.__table__.indexes
    }
    assert indexes["ix_mitigation_decisions_decision_uuid"] == (["decision_uuid"], True)
    assert indexes["ix_mitigation_decisions_dedupe_key"] == (["dedupe_key"], True)
    for name, column in (
        ("ix_mitigation_decisions_policy_id", "policy_id"),
        ("ix_mitigation_decisions_decision_type", "decision_type"),
        ("ix_mitigation_decisions_scope_type", "scope_type"),
        ("ix_mitigation_decisions_scope_key_hash", "scope_key_hash"),
        ("ix_mitigation_decisions_issued_at", "issued_at"),
        ("ix_mitigation_decisions_expires_at", "expires_at"),
        ("ix_mitigation_decisions_created_at", "created_at"),
    ):
        assert indexes[name] == ([column], False)

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        with pytest.raises(IntegrityError):
            session.execute(
                _decision_insert_sql(include_advisory_only=True),
                _decision_sql_params(
                    policy.id,
                    decision_id=9400,
                    expires_at="2026-02-10 09:20:00",
                ),
            )
            session.commit()
        session.rollback()

        session.execute(
            _decision_insert_sql(include_advisory_only=True),
            _decision_sql_params(policy.id, decision_id=9401),
        )
        session.commit()
        assert (
            session.execute(
                text("SELECT expires_at FROM mitigation_decisions WHERE id = 9401")
            ).scalar()
            is not None
        )


def test_decision_policy_relationship_restricts_deletion(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()
        session.add(_decision(policy.id))
        session.commit()

        session.delete(policy)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_audit_event_lifecycle_and_reserved_vocabulary_round_trip(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()
        decision = _decision(policy.id)
        session.add(decision)
        session.commit()

        events = [
            _audit_event(
                policy_id=policy.id,
                event_type=MitigationAuditEventType.POLICY_ACTIVATED,
                entity_type=MitigationAuditEntityType.POLICY,
                entity_identifier=policy.policy_version,
                sequence_no=1,
                chain_id="lifecycle-chain",
                actor_hash=_VALID_HASH,
                actor_role="analyst",
                details={"policy_version": policy.policy_version},
            ),
            _audit_event(
                policy_id=policy.id,
                decision_id=decision.id,
                event_type=MitigationAuditEventType.DECISION_ISSUED,
                entity_type=MitigationAuditEntityType.DECISION,
                entity_identifier=decision.decision_uuid,
                sequence_no=2,
                chain_id="lifecycle-chain",
                previous_event_hash=_VALID_HASH,
                event_hash=_OTHER_HASH,
                details={"decision_type": "allow"},
            ),
            _audit_event(
                event_type=MitigationAuditEventType.ENFORCEMENT_APPLIED_RESERVED,
                entity_type=MitigationAuditEntityType.DECISION,
                entity_identifier="decision-reserved",
                sequence_no=3,
                chain_id="lifecycle-chain",
            ),
        ]
        session.add_all(events)
        session.commit()

        stored = {
            row[0]
            for row in session.execute(
                text("SELECT event_type FROM mitigation_audit_events")
            ).fetchall()
        }
        assert stored == {
            "policy_activated",
            "decision_issued",
            "enforcement_applied_reserved",
        }
        assert session.query(MitigationAuditEvent).count() == 3


@pytest.mark.parametrize(
    "field, invalid_value",
    [
        ("event_type", "enforcement_applied"),
        ("event_type", "POLICY_ACTIVATED"),
        ("entity_type", "request"),
        ("entity_type", "POLICY"),
        ("entity_identifier", ""),
        ("entity_identifier", "raw-user@example.test"),
        ("actor_hash", "203.0.113.9"),
        ("actor_role", "Admin"),
        ("previous_event_hash", "sha256:" + "A" * 64),
        ("event_hash", "raw-hash"),
        ("event_hash", None),
        ("sequence_no", 0),
        ("sequence_no", -1),
        ("chain_id", ""),
        ("chain_id", "chain with spaces"),
    ],
)
def test_invalid_audit_event_values_are_rejected(field, invalid_value):
    with pytest.raises(ValueError):
        _audit_event(**{field: invalid_value})


def test_audit_event_uuid_must_be_unique_lowercase_uuid5(session_factory):
    shared_uuid = _unique_uuid5()

    with pytest.raises(ValueError):
        _audit_event(event_uuid=str(uuid.uuid4()))
    with pytest.raises(ValueError):
        _audit_event(event_uuid=shared_uuid.upper())

    with session_factory() as session:
        session.add(_audit_event(event_uuid=shared_uuid, sequence_no=1))
        session.add(_audit_event(event_uuid=shared_uuid, sequence_no=2))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_chain_sequence_uniqueness(session_factory):
    indexes = {
        index.name: ([column.name for column in index.columns], bool(index.unique))
        for index in MitigationAuditEvent.__table__.indexes
    }
    assert indexes["uq_mitigation_audit_events_chain_id_sequence_no"] == (
        ["chain_id", "sequence_no"],
        True,
    )
    assert indexes["ix_mitigation_audit_events_event_uuid"] == (["event_uuid"], True)

    with session_factory() as session:
        session.add(_audit_event(chain_id="chain-a", sequence_no=1))
        session.add(_audit_event(chain_id="chain-a", sequence_no=1))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(_audit_event(chain_id="chain-a", sequence_no=1))
        session.add(_audit_event(chain_id="chain-b", sequence_no=1))
        session.commit()
        assert session.query(MitigationAuditEvent).count() == 2


def test_audit_details_are_allowlisted_and_round_trip(session_factory):
    details = {
        "policy_version": "phase2-1.0.0",
        "decision_type": "allow",
        "evidence_reference_count": 2,
        "advisory_only": True,
    }
    assert _audit_event(details=details).details == details
    assert _audit_event(details=None).details is None

    invalid_details = [
        {"client_ip": "203.0.113.8"},
        {"raw": {"nested": True}},
        {"explanation_summary": "x" * 129},
        ["not", "an", "object"],
    ]
    for invalid in invalid_details:
        with pytest.raises(ValueError):
            _audit_event(details=invalid)

    with session_factory() as session:
        event = _audit_event(details=details)
        session.add(event)
        session.commit()
        session.expire(event)
        assert event.details == details


def test_audit_policy_and_decision_foreign_keys_restrict_deletion(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()
        decision = _decision(policy.id)
        session.add(decision)
        session.commit()
        session.add(
            _audit_event(
                policy_id=policy.id,
                decision_id=decision.id,
            )
        )
        session.commit()

        with pytest.raises(IntegrityError):
            session.execute(text("DELETE FROM mitigation_policies WHERE id = :id"), {"id": policy.id})
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                text("DELETE FROM mitigation_decisions WHERE id = :id"),
                {"id": decision.id},
            )
            session.commit()
        session.rollback()


@pytest.mark.parametrize(
    "overrides",
    [
        {"decision_type": "deny"},
        {"scope_type": "raw"},
        {"attribution_status": "trusted"},
        {"scope_key_hash": "sha256:" + "A" * 64},
        {"decision_uuid": str(uuid.uuid4())},
        {"decision_uuid": _unique_uuid5().upper()},
    ],
)
def test_direct_sql_decision_constraint_bypass_attempts_fail(session_factory, overrides):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        with pytest.raises(IntegrityError):
            session.execute(
                _decision_insert_sql(include_advisory_only=True),
                _decision_sql_params(policy.id, decision_id=9500, **overrides),
            )
            session.commit()
        session.rollback()


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_type": "enforcement_applied"},
        {"entity_type": "request"},
        {"event_uuid": str(uuid.uuid4())},
        {"actor_hash": "203.0.113.10"},
        {"previous_event_hash": "sha512:" + "a" * 64},
        {"event_hash": "raw-event-hash"},
        {"sequence_no": 0},
        {"chain_id": ""},
    ],
)
def test_direct_sql_audit_constraint_bypass_attempts_fail(session_factory, overrides):
    with session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(_AUDIT_INSERT_SQL, _audit_sql_params(**overrides))
            session.commit()
        session.rollback()

        session.execute(_AUDIT_INSERT_SQL, _audit_sql_params(event_id=9599))
        session.commit()


def test_phase2_models_create_with_portable_sqlite_schema(session_factory):
    with session_factory() as session:
        inspector = inspect(session.get_bind())

        decision_table = MitigationDecision.__table__
        audit_table = MitigationAuditEvent.__table__
        assert _table_fingerprint(inspector, decision_table.name) == _expected_fingerprint(
            decision_table
        )
        assert _table_fingerprint(inspector, audit_table.name) == _expected_fingerprint(
            audit_table
        )

        for table in (decision_table, audit_table):
            assert _check_constraints(inspector, table.name) == _expected_checks(table)
            for column in table.columns:
                assert "ENUM" not in str(column.type).upper()

        assert _foreign_keys(inspector, "mitigation_decisions") == {
            (
                "fk_mitigation_decision_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            )
        }
        assert _foreign_keys(inspector, "mitigation_audit_events") == {
            (
                "fk_mitigation_audit_event_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            ),
            (
                "fk_mitigation_audit_event_decision",
                ("decision_id",),
                "mitigation_decisions",
                ("id",),
                "RESTRICT",
            ),
        }


def test_model_module_defines_no_service_or_enforcement_workflow():
    source = Path(mitigation_models.__file__).read_text(encoding="utf-8")

    assert "def append_" not in source
    assert "class MitigationDecisionRepository" not in source
    assert "def enforce_" not in source
    assert "ondelete=\"RESTRICT\"" in source
    assert "tamper-proof" in source


# ---------------------------------------------------------------------------
# Alembic migration
# ---------------------------------------------------------------------------


def test_fresh_upgrade_to_head_creates_expected_schema(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")

    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | PHASE2_TABLES | PHASE3_TABLES | {"alembic_version"}
        )

        for table in Base.metadata.sorted_tables:
            assert _table_fingerprint(inspector, table.name) == _expected_fingerprint(
                table
            )

        for table_name in PHASE2_TABLES:
            table = Base.metadata.tables[table_name]
            assert _check_constraints(inspector, table_name) == _expected_checks(table)

        assert _foreign_keys(inspector, "mitigation_decisions") == {
            (
                "fk_mitigation_decision_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            )
        }
        assert _foreign_keys(inspector, "mitigation_audit_events") == {
            (
                "fk_mitigation_audit_event_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            ),
            (
                "fk_mitigation_audit_event_decision",
                ("decision_id",),
                "mitigation_decisions",
                ("id",),
                "RESTRICT",
            ),
        }

        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).fetchall()
            ]
        assert revisions == [HEAD_REVISION]
    finally:
        engine.dispose()


def test_table_progression_across_revisions(alembic_config):
    config, url = alembic_config

    command.upgrade(config, BASELINE_REVISION)
    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == BASELINE_TABLES | {"alembic_version"}
    finally:
        engine.dispose()

    command.upgrade(config, PHASE1_REVISION)
    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | {"alembic_version"}
        )
        assert PHASE2_TABLES.isdisjoint(set(inspector.get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, PHASE2_REVISION)
    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | PHASE2_TABLES | {"alembic_version"}
        )
        assert PHASE3_TABLES.isdisjoint(set(inspector.get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, HEAD_REVISION)
    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | PHASE2_TABLES | PHASE3_TABLES | {"alembic_version"}
        )
    finally:
        engine.dispose()


def test_downgrade_0003_to_0002_drops_only_phase2_objects(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")
    engine, inspector = _inspector(url)
    try:
        preserved = {
            table_name: _table_fingerprint(inspector, table_name)
            for table_name in BASELINE_TABLES | PHASE1_TABLES
        }
    finally:
        engine.dispose()

    command.downgrade(config, PHASE1_REVISION)

    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | {"alembic_version"}
        )
        assert PHASE2_TABLES.isdisjoint(set(inspector.get_table_names()))
        assert PHASE3_TABLES.isdisjoint(set(inspector.get_table_names()))
        assert {
            table_name: _table_fingerprint(inspector, table_name)
            for table_name in BASELINE_TABLES | PHASE1_TABLES
        } == preserved

        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).fetchall()
            ]
        assert revisions == [PHASE1_REVISION]
    finally:
        engine.dispose()


def test_baseline_downgrade_is_still_refused(alembic_config):
    config, url = alembic_config

    command.upgrade(config, BASELINE_REVISION)

    with pytest.raises(RuntimeError, match="not downgradeable"):
        command.downgrade(config, "base")

    engine, inspector = _inspector(url)
    try:
        assert BASELINE_TABLES.issubset(set(inspector.get_table_names()))
        assert PHASE1_TABLES.isdisjoint(set(inspector.get_table_names()))
        assert PHASE2_TABLES.isdisjoint(set(inspector.get_table_names()))
        assert PHASE3_TABLES.isdisjoint(set(inspector.get_table_names()))
    finally:
        engine.dispose()


def test_0003_migration_is_additive_only():
    source = (
        BACKEND_DIR / "alembic" / "versions" / "0003_mitigation_decision_audit.py"
    ).read_text(encoding="utf-8")

    assert 'revision: str = "0003_mitigation_decision_audit"' in source
    assert 'down_revision: Union[str, None] = "0002_mitigation_policy_models"' in source
    assert "op.alter_column" not in source
    assert "op.add_column" not in source
    assert "postgresql" not in source.lower()
    assert source.count('op.create_table(') == 2
    assert 'op.create_table(\n        "mitigation_decisions"' in source
    assert 'op.create_table(\n        "mitigation_audit_events"' in source
    assert source.count('op.drop_table(') == 2
    assert 'op.drop_table("mitigation_decisions")' in source
    assert 'op.drop_table("mitigation_audit_events")' in source
