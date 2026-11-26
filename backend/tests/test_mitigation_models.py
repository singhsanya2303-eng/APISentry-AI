"""Focused Stage 2C Phase 1 model and migration tests.

All databases in this module are isolated in-memory or temporary SQLite
databases. No configured development or production database is contacted.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    MitigationActivationEventType,
    MitigationActivationReasonCode,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
    MitigationPolicyMode,
    MitigationPolicyState,
)
from app.models import mitigation as mitigation_models
from app.schemas.mitigation import MitigationPolicyMode as SchemaMitigationPolicyMode

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
BASELINE_REVISION = "0001_baseline_existing_schema"
HEAD_REVISION = "0004_revoked_tokens"
BASELINE_TABLES = {"api_traffic_logs", "users"}
PHASE1_TABLES = {
    "mitigation_policies",
    "mitigation_policy_state",
    "mitigation_policy_activation_events",
}
PHASE2_TABLES = {"mitigation_decisions", "mitigation_audit_events"}
_VALID_HASH = "sha256:" + "a" * 64


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
    url = "sqlite:///" + (tmp_path / "phase1-private-marker.db").as_posix()
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    return Config(str(ALEMBIC_INI)), url


def _inspector(url):
    engine = create_engine(url)
    try:
        return engine, inspect(engine)
    except Exception:
        engine.dispose()
        raise


def _policy(version="1.0.0", **overrides):
    values = {
        "creator_hash": _VALID_HASH,
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationPolicy(policy_version=version, **values)


def _activation_event(policy_id, **overrides):
    values = {
        "event_uuid": str(uuid.uuid4()),
        "event_type": MitigationActivationEventType.ACTIVATE,
        "reason_code": MitigationActivationReasonCode.INITIAL_ACTIVATION,
        "actor_hash": _VALID_HASH,
        "occurred_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationPolicyActivationEvent(policy_id=policy_id, **values)


def _normalize_check(value):
    return "".join(str(value).lower().replace('"', "").split())


def _check_constraints(inspector, table_name):
    return {
        (
            constraint["name"],
            _normalize_check(constraint["sqltext"]),
        )
        for constraint in inspector.get_check_constraints(table_name)
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


def test_all_models_are_registered_with_existing_models():
    tables = set(Base.metadata.tables)

    assert BASELINE_TABLES.issubset(tables)
    assert PHASE1_TABLES.issubset(tables)
    assert hasattr(mitigation_models, "MitigationPolicy")
    assert hasattr(mitigation_models, "MitigationPolicyState")
    assert hasattr(mitigation_models, "MitigationPolicyActivationEvent")


def test_policy_creation_defaults_and_stage2b_field_mirror(session_factory):
    assert [member.value for member in MitigationPolicyMode] == [
        member.value for member in SchemaMitigationPolicyMode
    ]

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        assert policy.id is not None
        assert policy.policy_version == "1.0.0"
        assert policy.enabled is True
        assert policy.mode.value == "monitor"
        assert policy.monitoring_score_threshold == 25.0
        assert policy.throttling_score_threshold == 75.0
        assert policy.blocking_score_threshold == 90.0
        assert policy.minimum_authentication_failures == 5
        assert policy.require_grouped_brute_force is True
        assert policy.throttle_enabled is False
        assert policy.throttle_limit == 60
        assert policy.throttle_window_seconds == 60
        assert policy.throttle_duration_seconds == 300
        assert policy.block_enabled is False
        assert policy.block_duration_seconds == 900
        assert policy.max_block_duration_seconds == 3600
        assert policy.admin_protection_enabled is True
        assert policy.max_evidence_references == 25
        assert policy.creator_hash == _VALID_HASH
        assert session.query(MitigationPolicy).count() == 1


def test_policy_required_fields_are_enforced(session_factory):
    with pytest.raises(ValueError):
        MitigationPolicy(policy_version=None)

    with session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(text("INSERT INTO mitigation_policies (id) VALUES (9001)"))
            session.commit()
        session.rollback()


def test_policy_versions_are_unique(session_factory):
    with session_factory() as session:
        session.add(_policy("duplicate-version"))
        session.add(_policy("duplicate-version"))

        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_policy_version_is_immutable_at_application_interface(session_factory):
    policy = _policy("1.0.0")
    with pytest.raises(ValueError, match="immutable"):
        policy.policy_version = "2.0.0"

    with session_factory() as session:
        session.add(policy)
        session.commit()
        with pytest.raises(ValueError, match="immutable"):
            policy.policy_version = "2.0.0"


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "",
        "not-a-hash",
        "sha256:" + "A" * 64,
        "sha512:" + "a" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "private-user-9c2e@example.test",
        12345,
    ],
)
def test_creator_and_actor_hashes_reject_raw_or_invalid_values(invalid_hash):
    with pytest.raises(ValueError):
        _policy(creator_hash=invalid_hash)
    with pytest.raises(ValueError):
        _activation_event(policy_id=1, actor_hash=invalid_hash)

    assert _policy(creator_hash=_VALID_HASH).creator_hash == _VALID_HASH
    assert _activation_event(policy_id=1, actor_hash=None).actor_hash is None


def test_policy_state_singleton_rules_and_unique_policy_reference(session_factory):
    with pytest.raises(ValueError):
        MitigationPolicyState(id=2)
    with pytest.raises(ValueError):
        MitigationPolicyState(singleton_marker=2)

    indexes = {
        index.name: ([column.name for column in index.columns], bool(index.unique))
        for index in MitigationPolicyState.__table__.indexes
    }
    assert indexes["ix_mitigation_policy_state_policy_id"] == (["policy_id"], True)
    assert indexes["ix_mitigation_policy_state_singleton_marker"] == (
        ["singleton_marker"],
        True,
    )

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        state = MitigationPolicyState(id=1)
        session.add(state)
        session.commit()

        # Direct SQL bypasses ORM validators and must still be rejected.
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO mitigation_policy_state (id, singleton_marker) "
                    "VALUES (2, 1)"
                )
            )
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO mitigation_policy_state (id, singleton_marker) "
                    "VALUES (1, 2)"
                )
            )
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO mitigation_policy_state (id, singleton_marker) "
                    "VALUES (1, 1)"
                )
            )
            session.commit()
        session.rollback()

        state.policy_id = policy.id
        session.commit()

        assert (
            session.execute(text("SELECT COUNT(*) FROM mitigation_policy_state")).scalar()
            == 1
        )


def test_policy_state_relationship_restricts_policy_deletion(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()
        session.add(MitigationPolicyState(id=1, policy_id=policy.id))
        session.commit()

        session.delete(policy)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_activation_event_types_are_validated_and_stored_portably(session_factory):
    with pytest.raises(ValueError):
        _activation_event(policy_id=1, event_type="DELETE")
    with pytest.raises(ValueError):
        _activation_event(policy_id=1, event_type="activate")

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        session.add(_activation_event(policy.id, event_type="ACTIVATE"))
        session.add(
            _activation_event(
                policy.id,
                event_uuid=str(uuid.uuid4()),
                event_type=MitigationActivationEventType.DEACTIVATE,
                reason_code=MitigationActivationReasonCode.POLICY_DEACTIVATION,
            )
        )
        session.commit()

        stored_types = {
            row[0]
            for row in session.execute(
                text("SELECT event_type FROM mitigation_policy_activation_events")
            ).fetchall()
        }
        assert stored_types == {"ACTIVATE", "DEACTIVATE"}

        with pytest.raises(ValueError):
            _activation_event(policy.id, event_type="DELETE")
        with pytest.raises(ValueError):
            _activation_event(
                policy.id, reason_code="free-text-reason-that-is-not-allowlisted"
            )


def test_event_uuid_is_unique(session_factory):
    event_uuid = str(uuid.uuid4())
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        session.add(_activation_event(policy.id, event_uuid=event_uuid))
        session.add(_activation_event(policy.id, event_uuid=event_uuid))

        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_event_json_details_are_allowlisted_and_round_trip(session_factory):
    details = {
        "policy_version": "1.0.0",
        "review_reference": "review-42",
    }
    invalid_details = [
        {"raw_ip": "203.0.113.7"},
        {"nested": {"key": "value"}},
        {"review_reference": "x" * 129},
        ["not", "an", "object"],
    ]
    for candidate in invalid_details:
        with pytest.raises(ValueError):
            _activation_event(policy_id=1, details=candidate)

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        event = _activation_event(policy.id, details=details)
        session.add(event)
        session.commit()
        session.expire(event)

        assert event.details == details
        raw_details = session.execute(
            text("SELECT details FROM mitigation_policy_activation_events")
        ).scalar()
        assert "review_reference" in raw_details


def test_utc_timestamps_are_normalized_without_mutating_inputs():
    offset = timezone(timedelta(hours=5, minutes=30))
    created_at = datetime(2026, 2, 10, 9, 30, tzinfo=offset)
    occurred_at = datetime(2026, 2, 10, 9, 30, tzinfo=offset)

    policy = _policy(created_at=created_at)
    event = _activation_event(policy_id=1, occurred_at=occurred_at)

    expected = datetime(2026, 2, 10, 4, 0, tzinfo=timezone.utc)
    assert policy.created_at == expected
    assert policy.created_at.tzinfo is timezone.utc
    assert event.occurred_at == expected
    assert event.occurred_at.tzinfo is timezone.utc

    # Original inputs are not mutated by validation.
    assert created_at.tzinfo == offset
    assert occurred_at.tzinfo == offset

    naive = datetime(2026, 2, 10, 4, 0)
    assert _policy(created_at=naive).created_at.tzinfo is timezone.utc
    assert _activation_event(policy_id=1, occurred_at=naive).occurred_at.tzinfo is timezone.utc


def test_activation_event_relationship_restricts_policy_deletion(session_factory):
    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()
        session.add(_activation_event(policy.id))
        session.commit()

        session.delete(policy)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_activation_event_required_fields_are_enforced(session_factory):
    with session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO mitigation_policy_activation_events (id) VALUES (9001)"
                )
            )
            session.commit()
        session.rollback()


def test_database_check_constraints_reject_invalid_event_values(session_factory):
    insert_sql = text(
        "INSERT INTO mitigation_policy_activation_events "
        "(id, event_uuid, event_type, policy_id, reason_code, occurred_at) "
        "VALUES (:id, :event_uuid, :event_type, :policy_id, :reason_code, :occurred_at)"
    )
    params = {
        "occurred_at": "2026-02-10 09:30:00",
    }

    with session_factory() as session:
        policy = _policy()
        session.add(policy)
        session.commit()

        # A valid direct insert proves the constraints accept the existing enum values.
        valid_params = {
            **params,
            "id": 9100,
            "event_uuid": str(uuid.uuid4()),
            "event_type": "ACTIVATE",
            "policy_id": policy.id,
            "reason_code": "initial_activation",
        }
        session.execute(insert_sql, valid_params)
        session.commit()

        # Direct SQL bypasses ORM validators and must still reject invalid values.
        invalid_cases = (
            {
                "id": 9101,
                "event_uuid": str(uuid.uuid4()),
                "event_type": "DELETE",
                "policy_id": policy.id,
                "reason_code": "initial_activation",
            },
            {
                "id": 9102,
                "event_uuid": str(uuid.uuid4()),
                "event_type": "ACTIVATE",
                "policy_id": policy.id,
                "reason_code": "free_text_reason",
            },
        )
        for case in invalid_cases:
            with pytest.raises(IntegrityError):
                session.execute(insert_sql, {**params, **case})
                session.commit()
            session.rollback()

        assert (
            session.execute(
                text("SELECT COUNT(*) FROM mitigation_policy_activation_events")
            ).scalar()
            == 1
        )


def test_model_module_defines_no_repository_or_update_delete_workflow():
    source = Path(mitigation_models.__file__).read_text(encoding="utf-8")

    assert "Repository" not in source
    assert "def update_" not in source
    assert "def delete_" not in source
    assert "ON DELETE RESTRICT" not in source or "ondelete=\"RESTRICT\"" in source


# ---------------------------------------------------------------------------
# Alembic migration
# ---------------------------------------------------------------------------


def test_fresh_sqlite_upgrade_to_head_creates_expected_schema(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")

    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == (
            BASELINE_TABLES | PHASE1_TABLES | PHASE2_TABLES | {"revoked_tokens", "alembic_version"}
        )

        for table in Base.metadata.sorted_tables:
            expected_fingerprint = (
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
            assert _table_fingerprint(inspector, table.name) == expected_fingerprint

        assert _foreign_keys(inspector, "mitigation_policies") == set()
        assert _foreign_keys(inspector, "mitigation_policy_state") == {
            (
                "fk_mitigation_policy_state_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            )
        }
        assert _foreign_keys(inspector, "mitigation_policy_activation_events") == {
            (
                "fk_mitigation_activation_event_policy",
                ("policy_id",),
                "mitigation_policies",
                ("id",),
                "RESTRICT",
            )
        }

        assert _check_constraints(inspector, "mitigation_policies") == set()
        assert _check_constraints(inspector, "mitigation_policy_state") == {
            ("ck_mitigation_policy_state_id", "id=1"),
            ("ck_mitigation_policy_state_singleton_marker", "singleton_marker=1"),
        }
        assert _check_constraints(inspector, "mitigation_policy_activation_events") == {
            (
                "ck_mitigation_policy_activation_event_type",
                "event_typein('activate','deactivate')",
            ),
            (
                "ck_mitigation_policy_activation_reason_code",
                "reason_codein('initial_activation','policy_version_change',"
                "'operator_review','configuration_review','policy_deactivation')",
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


def test_downgrade_0002_to_0001_drops_only_phase1_objects(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")
    engine, inspector = _inspector(url)
    try:
        baseline_before = {
            table: _table_fingerprint(inspector, table) for table in BASELINE_TABLES
        }
    finally:
        engine.dispose()

    command.downgrade(config, BASELINE_REVISION)

    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == BASELINE_TABLES | {"alembic_version"}
        assert PHASE1_TABLES.isdisjoint(set(inspector.get_table_names()))
        assert {
            table: _table_fingerprint(inspector, table) for table in BASELINE_TABLES
        } == baseline_before

        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).fetchall()
            ]
        assert revisions == [BASELINE_REVISION]
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
        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).fetchall()
            ]
        assert revisions == [BASELINE_REVISION]
    finally:
        engine.dispose()


def test_0002_migration_is_additive_only():
    source = (
        BACKEND_DIR / "alembic" / "versions" / "0002_mitigation_policy_models.py"
    ).read_text(encoding="utf-8")

    assert 'revision: str = "0002_mitigation_policy_models"' in source
    assert 'down_revision: Union[str, None] = "0001_baseline_existing_schema"' in source
    assert "op.alter_column" not in source
    assert "op.add_column" not in source
    assert 'op.drop_table("users")' not in source
    assert 'op.drop_table("api_traffic_logs")' not in source
    assert "postgresql" not in source.lower()
    for constraint_name in (
        "ck_mitigation_policy_state_id",
        "ck_mitigation_policy_state_singleton_marker",
        "ck_mitigation_policy_activation_event_type",
        "ck_mitigation_policy_activation_reason_code",
    ):
        assert constraint_name in source
