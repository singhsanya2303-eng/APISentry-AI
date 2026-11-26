"""Read-only, revision-aware schema verifier tests using isolated SQLite databases."""

import ast
from pathlib import Path
import subprocess
import sys
import types

import pytest
from sqlalchemy import CheckConstraint, create_engine, inspect, text

from app.db.base import Base
from app.models import (
    APITrafficLog,
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
    MitigationPolicyState,
    User,
)
from app.scripts import verify_baseline
from app.scripts.verify_baseline import (
    _normalized_check_expression,
    _string_column_names,
    main,
    verify_schema,
)

_PHASE0_TABLES = (User.__table__, APITrafficLog.__table__)
_PHASE1_TABLES = (
    MitigationPolicy.__table__,
    MitigationPolicyState.__table__,
    MitigationPolicyActivationEvent.__table__,
)
_PHASE2_TABLES = (
    MitigationDecision.__table__,
    MitigationAuditEvent.__table__,
)
_PHASE1_ALL_TABLES = _PHASE0_TABLES + _PHASE1_TABLES
_ALL_TABLES = _PHASE0_TABLES + _PHASE1_TABLES + _PHASE2_TABLES
_BASELINE_REVISION = "0001_baseline_existing_schema"
_PHASE1_REVISION = "0002_mitigation_policy_models"
_PHASE2_REVISION = "0003_mitigation_decision_audit"

_USERS_COLUMNS = (
    "id INTEGER NOT NULL PRIMARY KEY, "
    "email VARCHAR(255) NOT NULL, "
    "username VARCHAR(100) NOT NULL, "
    "hashed_password VARCHAR(255) NOT NULL, "
    "role VARCHAR(50) NOT NULL, "
    "is_active BOOLEAN NOT NULL, "
    "created_at DATETIME NOT NULL, "
    "updated_at DATETIME NOT NULL"
)

_HEX_DIGITS = "0123456789abcdef"


def _pg_in(column, values):
    elements = ", ".join(f"'{value}'::character varying" for value in values)
    return f"{column}::text = ANY (ARRAY[{elements}]::text[])"


def _pg_between(column, lower, upper):
    return f"length({column}::text) >= {lower} AND length({column}::text) <= {upper}"


def _pg_sha256(column, *, nullable):
    body = f"substr({column}::text, 8)"
    for digit in _HEX_DIGITS:
        body = f"replace({body}, '{digit}'::text, ''::text)"
    value_check = (
        f"length({column}::text) = 71 "
        f"AND substr({column}::text, 1, 7) = 'sha256:'::text "
        f"AND lower({column}::text) = {column}::text "
        f"AND length({body}) = 0"
    )
    return f"{column} IS NULL OR {value_check}" if nullable else value_check


def _pg_uuid5(column):
    compact = f"replace({column}::text, '-'::text, ''::text)"
    stripped = compact
    for digit in _HEX_DIGITS:
        stripped = f"replace({stripped}, '{digit}'::text, ''::text)"
    return (
        f"length({column}::text) = 36 "
        f"AND lower({column}::text) = {column}::text "
        f"AND substr({column}::text, 9, 1) = '-'::text "
        f"AND substr({column}::text, 14, 1) = '-'::text "
        f"AND substr({column}::text, 19, 1) = '-'::text "
        f"AND substr({column}::text, 24, 1) = '-'::text "
        f"AND substr({compact}, 13, 1) = '5'::text "
        f"AND (substr({compact}, 17, 1) = ANY "
        f"(ARRAY['8'::text, '9'::text, 'a'::text, 'b'::text])) "
        f"AND length({stripped}) = 0"
    )


# Reflected expressions observed during Phase 5I-B against PostgreSQL 17.10.
# Values are vocabulary/hash-format literals only; no traffic or identity data.
_POSTGRES_REFLECTED_CHECKS = {
    "mitigation_policy_activation_events": {
        "ck_mitigation_policy_activation_event_type": _pg_in(
            "event_type", ("ACTIVATE", "DEACTIVATE")
        ),
        "ck_mitigation_policy_activation_reason_code": _pg_in(
            "reason_code",
            (
                "initial_activation",
                "policy_version_change",
                "operator_review",
                "configuration_review",
                "policy_deactivation",
            ),
        ),
    },
    "mitigation_decisions": {
        "ck_mitigation_decision_decision_type": _pg_in(
            "decision_type", ("allow", "monitor", "throttle", "block")
        ),
        "ck_mitigation_decision_scope_type": _pg_in(
            "scope_type",
            ("verified_user", "api_key_principal", "network_ip", "unattributed"),
        ),
        "ck_mitigation_decision_attribution_status": _pg_in(
            "attribution_status",
            (
                "verified_user",
                "api_key_principal",
                "network_ip",
                "inferred",
                "missing",
            ),
        ),
        "ck_mitigation_decision_scope_key_hash": _pg_sha256(
            "scope_key_hash", nullable=True
        ),
        "ck_mitigation_decision_decision_uuid_format": _pg_uuid5("decision_uuid"),
    },
    "mitigation_audit_events": {
        "ck_mitigation_audit_event_type": _pg_in(
            "event_type",
            (
                "policy_activated",
                "policy_deactivated",
                "policy_version_changed",
                "decision_issued",
                "decision_expired",
                "enforcement_applied_reserved",
                "enforcement_removed_reserved",
            ),
        ),
        "ck_mitigation_audit_entity_type": _pg_in(
            "entity_type", ("policy", "decision")
        ),
        "ck_mitigation_audit_event_uuid_format": _pg_uuid5("event_uuid"),
        "ck_mitigation_audit_actor_hash": _pg_sha256("actor_hash", nullable=True),
        "ck_mitigation_audit_previous_event_hash": _pg_sha256(
            "previous_event_hash", nullable=True
        ),
        "ck_mitigation_audit_event_hash": _pg_sha256("event_hash", nullable=False),
        "ck_mitigation_audit_chain_id_length": _pg_between("chain_id", 1, 64),
        "ck_mitigation_audit_entity_identifier_length": _pg_between(
            "entity_identifier", 1, 64
        ),
    },
}

_PHASE5IB_CASES = [
    (table_name, constraint_name, expression)
    for table_name, checks in _POSTGRES_REFLECTED_CHECKS.items()
    for constraint_name, expression in checks.items()
]


def _table_by_name(name):
    return next(table for table in _ALL_TABLES if table.name == name)


def _normalized(table, expression):
    return _normalized_check_expression(expression, _string_column_names(table))


def _model_check_expression(table, constraint_name):
    return str(
        next(
            constraint.sqltext
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint)
            and str(constraint.name) == constraint_name
        )
    )


@pytest.fixture
def sqlite_url(tmp_path):
    return "sqlite:///" + (tmp_path / "verifier-private-marker.db").as_posix()


@pytest.fixture
def baseline_engine(sqlite_url):
    engine = create_engine(sqlite_url)
    Base.metadata.create_all(engine, tables=list(_PHASE0_TABLES))
    yield engine
    engine.dispose()


@pytest.fixture
def phase1_engine(sqlite_url):
    engine = create_engine(sqlite_url)
    Base.metadata.create_all(engine, tables=list(_PHASE1_ALL_TABLES))
    yield engine
    engine.dispose()


@pytest.fixture
def phase2_engine(sqlite_url):
    engine = create_engine(sqlite_url)
    Base.metadata.create_all(engine, tables=list(_ALL_TABLES))
    yield engine
    engine.dispose()


def _codes(result):
    return {finding.code for finding in result.findings}


def _mode(result):
    return {
        finding.detail
        for finding in result.findings
        if finding.code == "VERIFICATION_MODE"
    }


def _table_names(engine):
    try:
        return set(inspect(engine).get_table_names())
    finally:
        pass


def _create_tables(engine, tables):
    Base.metadata.create_all(engine, tables=list(tables))


def _set_revisions(engine, revisions):
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        )
        for revision in revisions:
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )


def _set_revision(engine, revision):
    _set_revisions(engine, [revision])


def _create_empty_revision_table(engine):
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        )


def _create_malformed_revision_table(engine):
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (wrong_column VARCHAR(32) NOT NULL)")
        )


def _row_count(engine, table_name):
    with engine.connect() as connection:
        return connection.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()


def _recreate_users(engine, columns, indexes=True):
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE users"))
        connection.execute(text(f"CREATE TABLE users ({columns})"))
        if indexes:
            connection.execute(
                text("CREATE UNIQUE INDEX ix_users_email ON users (email)")
            )
            connection.execute(text("CREATE INDEX ix_users_id ON users (id)"))
            connection.execute(
                text("CREATE INDEX ix_users_is_active ON users (is_active)")
            )
            connection.execute(text("CREATE INDEX ix_users_role ON users (role)"))
            connection.execute(
                text("CREATE UNIQUE INDEX ix_users_username ON users (username)")
            )


def test_verifier_passes_on_reviewed_schema(baseline_engine, sqlite_url):
    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert "SCHEMA_MATCHES_BASELINE" in _codes(result)
    assert "DATA_CHECKSUM_DEFERRED" in _codes(result)
    assert _mode(result) == {"unversioned-existing-schema"}
    assert "alembic_version" not in _table_names(baseline_engine)


def test_unversioned_phase0_only_database_passes(baseline_engine, sqlite_url):
    assert set(inspect(baseline_engine).get_table_names()) == {
        "users",
        "api_traffic_logs",
    }

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _mode(result) == {"unversioned-existing-schema"}


def test_revision_0001_with_phase0_only_database_passes(baseline_engine, sqlite_url):
    _set_revision(baseline_engine, _BASELINE_REVISION)

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _mode(result) == {"revision-0001-baseline"}
    assert "SCHEMA_MATCHES_BASELINE" in _codes(result)


def test_revision_0001_with_missing_phase0_object_fails(baseline_engine, sqlite_url):
    _set_revision(baseline_engine, _BASELINE_REVISION)
    with baseline_engine.begin() as connection:
        connection.execute(text("DROP TABLE users"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_TABLE" in _codes(result)
    assert any("users is missing" in finding.detail for finding in result.findings)


def test_revision_0002_with_all_application_tables_passes(phase1_engine, sqlite_url):
    _set_revision(phase1_engine, _PHASE1_REVISION)

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _mode(result) == {"revision-0002-mitigation-policy"}
    assert "SCHEMA_MATCHES_BASELINE" in _codes(result)
    assert {"users", "api_traffic_logs"} | {
        table.name for table in _PHASE1_TABLES
    } <= _table_names(phase1_engine)


def test_revision_0002_with_missing_mitigation_table_fails(phase1_engine, sqlite_url):
    _set_revision(phase1_engine, _PHASE1_REVISION)
    with phase1_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_policy_state"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_TABLE" in _codes(result)
    assert any(
        "mitigation_policy_state is missing" in finding.detail
        for finding in result.findings
    )


def test_revision_0002_with_missing_phase1_check_constraint_fails(
    phase1_engine, sqlite_url
):
    _set_revision(phase1_engine, _PHASE1_REVISION)
    with phase1_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_policy_state"))
        connection.execute(
            text(
                "CREATE TABLE mitigation_policy_state ("
                "id INTEGER DEFAULT 1 NOT NULL, "
                "policy_id INTEGER, "
                "singleton_marker INTEGER DEFAULT 1 NOT NULL, "
                "CONSTRAINT ck_mitigation_policy_state_id CHECK (id = 1), "
                "CONSTRAINT fk_mitigation_policy_state_policy FOREIGN KEY (policy_id) "
                "REFERENCES mitigation_policies (id) ON DELETE RESTRICT, "
                "PRIMARY KEY (id)"
                ")"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX ix_mitigation_policy_state_policy_id "
                "ON mitigation_policy_state (policy_id)"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX ix_mitigation_policy_state_singleton_marker "
                "ON mitigation_policy_state (singleton_marker)"
            )
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_CHECK_CONSTRAINT" in _codes(result)
    assert any(
        "ck_mitigation_policy_state_singleton_marker" in finding.detail
        for finding in result.findings
    )


def test_revision_0003_with_all_application_tables_passes(phase2_engine, sqlite_url):
    _set_revision(phase2_engine, _PHASE2_REVISION)

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _mode(result) == {"revision-0003-mitigation-decision-audit"}
    assert "SCHEMA_MATCHES_BASELINE" in _codes(result)
    assert {"mitigation_decisions", "mitigation_audit_events"} <= _table_names(
        phase2_engine
    )


def test_revision_0003_with_missing_phase2_table_fails(phase2_engine, sqlite_url):
    _set_revision(phase2_engine, _PHASE2_REVISION)
    with phase2_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_audit_events"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_TABLE" in _codes(result)
    assert any(
        "mitigation_audit_events is missing" in finding.detail
        for finding in result.findings
    )


def test_revision_0003_with_missing_phase2_check_constraint_fails(
    phase2_engine, sqlite_url
):
    _set_revision(phase2_engine, _PHASE2_REVISION)
    with phase2_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_decisions"))
        connection.execute(
            text(
                "CREATE TABLE mitigation_decisions ("
                "id INTEGER NOT NULL, "
                "decision_uuid VARCHAR(36) NOT NULL, "
                "decision_type VARCHAR(8) NOT NULL, "
                "scope_type VARCHAR(18) NOT NULL, "
                "scope_key_hash VARCHAR(71), "
                "attribution_status VARCHAR(18) NOT NULL, "
                "verified_attribution BOOLEAN NOT NULL, "
                "reason_codes JSON NOT NULL, "
                "explanation VARCHAR(2000) NOT NULL, "
                "policy_id INTEGER NOT NULL, "
                "evidence_references JSON NOT NULL, "
                "issued_at DATETIME NOT NULL, "
                "expires_at DATETIME, "
                "rate_limit INTEGER, "
                "rate_limit_window_seconds INTEGER, "
                "advisory_only BOOLEAN DEFAULT 1 NOT NULL, "
                "dedupe_key VARCHAR(128) NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "CONSTRAINT fk_mitigation_decision_policy FOREIGN KEY (policy_id) "
                "REFERENCES mitigation_policies (id) ON DELETE RESTRICT, "
                "PRIMARY KEY (id)"
                ")"
            )
        )
        for statement in (
            "CREATE UNIQUE INDEX ix_mitigation_decisions_decision_uuid "
            "ON mitigation_decisions (decision_uuid)",
            "CREATE UNIQUE INDEX ix_mitigation_decisions_dedupe_key "
            "ON mitigation_decisions (dedupe_key)",
            "CREATE INDEX ix_mitigation_decisions_policy_id "
            "ON mitigation_decisions (policy_id)",
            "CREATE INDEX ix_mitigation_decisions_decision_type "
            "ON mitigation_decisions (decision_type)",
            "CREATE INDEX ix_mitigation_decisions_scope_type "
            "ON mitigation_decisions (scope_type)",
            "CREATE INDEX ix_mitigation_decisions_scope_key_hash "
            "ON mitigation_decisions (scope_key_hash)",
            "CREATE INDEX ix_mitigation_decisions_issued_at "
            "ON mitigation_decisions (issued_at)",
            "CREATE INDEX ix_mitigation_decisions_expires_at "
            "ON mitigation_decisions (expires_at)",
            "CREATE INDEX ix_mitigation_decisions_created_at "
            "ON mitigation_decisions (created_at)",
        ):
            connection.execute(text(statement))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_CHECK_CONSTRAINT" in _codes(result)
    assert any(
        "ck_mitigation_decision_advisory_only" in finding.detail
        for finding in result.findings
    )


def test_revision_0003_with_missing_phase1_table_fails(phase2_engine, sqlite_url):
    _set_revision(phase2_engine, _PHASE2_REVISION)
    with phase2_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_policy_state"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_TABLE" in _codes(result)
    assert any(
        "mitigation_policy_state is missing" in finding.detail
        for finding in result.findings
    )


def test_revision_0002_with_phase2_tables_fails(phase2_engine, sqlite_url):
    _set_revision(phase2_engine, _PHASE1_REVISION)

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "UNEXPECTED_TABLE" in _codes(result)
    assert _mode(result) == {"revision-0002-mitigation-policy"}
    assert any(
        table.name in finding.detail for table in _PHASE2_TABLES for finding in result.findings
    )


def test_revision_0002_with_altered_phase1_foreign_key_fails(
    phase1_engine, sqlite_url
):
    _set_revision(phase1_engine, _PHASE1_REVISION)
    with phase1_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_policy_activation_events"))
        connection.execute(
            text(
                "CREATE TABLE mitigation_policy_activation_events ("
                "id INTEGER NOT NULL, "
                "event_uuid VARCHAR(36) NOT NULL, "
                "event_type VARCHAR(16) NOT NULL, "
                "policy_id INTEGER NOT NULL, "
                "actor_hash VARCHAR(71), "
                "reason_code VARCHAR(32) NOT NULL, "
                "occurred_at DATETIME NOT NULL, "
                "details JSON, "
                "CONSTRAINT fk_mitigation_activation_event_policy FOREIGN KEY (policy_id) "
                "REFERENCES mitigation_policies (id) ON DELETE CASCADE, "
                "PRIMARY KEY (id), "
                "CONSTRAINT ck_mitigation_policy_activation_event_type "
                "CHECK (event_type IN ('ACTIVATE', 'DEACTIVATE')), "
                "CONSTRAINT ck_mitigation_policy_activation_reason_code "
                "CHECK (reason_code IN ('initial_activation', 'policy_version_change', "
                "'operator_review', 'configuration_review', 'policy_deactivation'))"
                ")"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_mitigation_policy_activation_events_event_type "
                "ON mitigation_policy_activation_events (event_type)"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX ix_mitigation_policy_activation_events_event_uuid "
                "ON mitigation_policy_activation_events (event_uuid)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_mitigation_policy_activation_events_occurred_at "
                "ON mitigation_policy_activation_events (occurred_at)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_mitigation_policy_activation_events_policy_id "
                "ON mitigation_policy_activation_events (policy_id)"
            )
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "FOREIGN_KEY_DEFINITION_MISMATCH" in _codes(result)


def test_unknown_revision_fails(baseline_engine, sqlite_url):
    _set_revision(baseline_engine, "9999_unknown_revision")

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "UNKNOWN_REVISION" in _codes(result)
    assert "VERIFICATION_MODE" not in _codes(result)


def test_empty_revision_state_fails(baseline_engine, sqlite_url):
    _create_empty_revision_table(baseline_engine)

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "EMPTY_REVISION_STATE" in _codes(result)
    assert "VERIFICATION_MODE" not in _codes(result)


def test_malformed_revision_state_fails(baseline_engine, sqlite_url):
    _create_malformed_revision_table(baseline_engine)

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MALFORMED_REVISION_STATE" in _codes(result)
    assert "VERIFICATION_MODE" not in _codes(result)


def test_multiple_inconsistent_revision_rows_fail(baseline_engine, sqlite_url):
    _set_revisions(
        baseline_engine, [_PHASE1_REVISION, _PHASE2_REVISION]
    )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MULTIPLE_REVISION_ROWS" in _codes(result)
    assert "VERIFICATION_MODE" not in _codes(result)


def test_unversioned_database_with_unexplained_mitigation_tables_fails(
    baseline_engine, sqlite_url
):
    _create_tables(baseline_engine, _PHASE1_TABLES)

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "UNEXPECTED_TABLE" in _codes(result)
    assert any(
        table.name in finding.detail for table in _PHASE1_TABLES for finding in result.findings
    )


def test_verifier_detects_missing_table(baseline_engine, sqlite_url):
    with baseline_engine.begin() as connection:
        connection.execute(text("DROP TABLE users"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_TABLE" in _codes(result)


def test_verifier_detects_missing_column(baseline_engine, sqlite_url):
    without_role = _USERS_COLUMNS.replace("role VARCHAR(50) NOT NULL, ", "")
    _recreate_users(baseline_engine, without_role, indexes=False)
    with baseline_engine.begin() as connection:
        connection.execute(text("CREATE INDEX ix_users_id ON users (id)"))
        connection.execute(
            text("CREATE INDEX ix_users_is_active ON users (is_active)")
        )
        connection.execute(
            text("CREATE UNIQUE INDEX ix_users_email ON users (email)")
        )
        connection.execute(
            text("CREATE UNIQUE INDEX ix_users_username ON users (username)")
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_COLUMN" in _codes(result)
    assert any("users.role" in finding.detail for finding in result.findings)


def test_verifier_detects_unexpected_column(baseline_engine, sqlite_url):
    with baseline_engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE api_traffic_logs ADD COLUMN unexpected_probe VARCHAR(20)")
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "UNEXPECTED_COLUMN" in _codes(result)


def test_verifier_detects_type_and_nullability_mismatch(baseline_engine, sqlite_url):
    altered = _USERS_COLUMNS.replace(
        "username VARCHAR(100) NOT NULL", "username VARCHAR(100)"
    ).replace("created_at DATETIME NOT NULL", "created_at VARCHAR(50) NOT NULL")
    _recreate_users(baseline_engine, altered)

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "COLUMN_TYPE_MISMATCH" in _codes(result)
    assert "COLUMN_NULLABILITY_MISMATCH" in _codes(result)


def test_verifier_detects_missing_index(baseline_engine, sqlite_url):
    with baseline_engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_users_role"))

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "MISSING_INDEX" in _codes(result)


def test_verifier_detects_unexpected_index(baseline_engine, sqlite_url):
    with baseline_engine.begin() as connection:
        connection.execute(
            text("CREATE INDEX ix_unexpected_probe ON api_traffic_logs (path)")
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "UNEXPECTED_INDEX" in _codes(result)


def test_verifier_accepts_known_baseline_revision_table(baseline_engine, sqlite_url):
    _set_revision(baseline_engine, _BASELINE_REVISION)

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert "UNEXPECTED_TABLE" not in _codes(result)
    assert _mode(result) == {"revision-0001-baseline"}


def test_verifier_is_read_only(phase1_engine, sqlite_url):
    _set_revision(phase1_engine, _PHASE1_REVISION)
    with phase1_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users "
                "(email, username, hashed_password, role, is_active, created_at, updated_at) "
                "VALUES ('private-user@example.test', 'private-user', 'private-hash', "
                "'viewer', 1, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )

    before_tables = _table_names(phase1_engine)
    before_users = _row_count(phase1_engine, "users")
    with phase1_engine.connect() as connection:
        before_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _table_names(phase1_engine) == before_tables
    assert _row_count(phase1_engine, "users") == before_users
    with phase1_engine.connect() as connection:
        after_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()
    assert after_revision == before_revision

    source = Path(verify_baseline.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "op.create_table",
        "op.drop_table",
        "command.upgrade",
        "command.downgrade",
        "command.stamp",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
    ):
        assert forbidden not in source


def test_verifier_is_read_only_at_revision_0003(phase2_engine, sqlite_url):
    _set_revision(phase2_engine, _PHASE2_REVISION)

    before_tables = _table_names(phase2_engine)
    before_decisions = _row_count(phase2_engine, "mitigation_decisions")
    before_events = _row_count(phase2_engine, "mitigation_audit_events")
    with phase2_engine.connect() as connection:
        before_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()

    result = verify_schema(sqlite_url)

    assert result.passed is True
    assert _table_names(phase2_engine) == before_tables
    assert _row_count(phase2_engine, "mitigation_decisions") == before_decisions
    assert _row_count(phase2_engine, "mitigation_audit_events") == before_events
    with phase2_engine.connect() as connection:
        after_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()
    assert after_revision == before_revision


def test_verifier_report_never_exposes_sensitive_values(baseline_engine, sqlite_url):
    secrets = {
        "email": "private-victim-4b1d@example.test",
        "username": "private-user-9c2e",
        "password_hash": "private-hash-7a3f",
        "client_ip": "203.0.113.77",
        "request_id": "private-request-2e8b",
    }
    with baseline_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users "
                "(email, username, hashed_password, role, is_active, created_at, updated_at) "
                "VALUES (:email, :username, :password_hash, 'viewer', 1, :ts, :ts)"
            ),
            {**secrets, "ts": "2026-01-01 00:00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO api_traffic_logs "
                "(request_id, timestamp, method, path, query_params, client_ip, "
                "status_code, response_time_ms) "
                "VALUES (:request_id, :ts, 'GET', '/private', '{}', :client_ip, 200, 1.0)"
            ),
            {**secrets, "ts": "2026-01-01 00:00:00"},
        )
        connection.execute(
            text("ALTER TABLE api_traffic_logs ADD COLUMN unexpected_probe VARCHAR(20)")
        )

    report = verify_schema(sqlite_url).render()

    assert "SCHEMA_VERIFICATION: FAIL" in report
    for value in secrets.values():
        assert value not in report
    assert sqlite_url not in report
    assert "verifier-private-marker" not in report


def test_verifier_failure_is_actionable_and_masks_inspection_errors():
    unsafe_marker = "apisentry-private-marker-6d4c"
    result = verify_schema(f"sqlite:////missing-directory/{unsafe_marker}/verify.db")

    assert result.passed is False
    assert "DATABASE_INSPECTION_FAILED" in _codes(result)
    report = result.render()
    assert unsafe_marker not in report
    assert "sqlite:///" not in report


def test_verifier_cli_exit_codes(baseline_engine, sqlite_url, capsys):
    assert main(["--database-url", sqlite_url]) == 0
    captured = capsys.readouterr()
    assert "SCHEMA_VERIFICATION: PASS" in captured.out

    with baseline_engine.begin() as connection:
        connection.execute(text("DROP TABLE users"))
    assert main(["--database-url", sqlite_url]) == 1
    captured = capsys.readouterr()
    assert "SCHEMA_VERIFICATION: FAIL" in captured.out


@pytest.mark.parametrize(
    "table_name,constraint_name,postgres_expression", _PHASE5IB_CASES
)
def test_phase5ib_postgres_check_expressions_normalize(
    table_name, constraint_name, postgres_expression
):
    table = _table_by_name(table_name)
    model_expression = _model_check_expression(table, constraint_name)

    assert _normalized(table, postgres_expression) == _normalized(
        table, model_expression
    )


def test_phase5ib_fixture_covers_fifteen_constraints():
    assert len(_PHASE5IB_CASES) == 15


def test_safe_text_cast_on_string_column_is_ignored():
    table = _table_by_name("mitigation_decisions")

    assert _normalized(table, "decision_uuid::text = 'x'") == _normalized(
        table, "decision_uuid = 'x'"
    )


def test_postgres_normalization_accepts_literal_any_array_as_in():
    table = _table_by_name("mitigation_decisions")
    model_expression = "decision_type IN ('allow', 'monitor')"
    postgres_expression = (
        "decision_type::text = ANY "
        "(ARRAY['allow'::character varying, 'monitor'::character varying]::text[])"
    )

    assert _normalized(table, model_expression) == _normalized(
        table, postgres_expression
    )


def test_postgres_normalization_accepts_expanded_inclusive_between():
    table = _table_by_name("mitigation_audit_events")
    model_expression = "length(chain_id) BETWEEN 1 AND 64"
    postgres_expression = (
        "length(chain_id::text) >= 1 AND length(chain_id::text) <= 64"
    )

    assert _normalized(table, model_expression) == _normalized(
        table, postgres_expression
    )


def test_postgres_normalization_accepts_redundant_grouping():
    table = _table_by_name("mitigation_decisions")

    assert _normalized(table, "(decision_type IN ('allow'))") == _normalized(
        table, "decision_type IN ('allow')"
    )


def test_postgres_normalization_rejects_different_array_elements():
    table = _table_by_name("mitigation_policy_activation_events")
    expected = "event_type IN ('ACTIVATE', 'DEACTIVATE')"
    actual = _pg_in("event_type", ("ACTIVATE", "OTHER"))

    assert _normalized(table, expected) != _normalized(table, actual)


def test_postgres_normalization_rejects_different_comparison_operator():
    table = _table_by_name("mitigation_decisions")

    assert _normalized(table, "rate_limit > 0") != _normalized(
        table, "rate_limit >= 0"
    )


def test_postgres_normalization_rejects_non_membership_any():
    table = _table_by_name("mitigation_decisions")
    values = ("allow", "monitor", "throttle", "block")
    expected = _pg_in("decision_type", values)
    actual = _pg_in("decision_type", values).replace(" = ANY", " <> ANY", 1)

    assert _normalized(table, expected) != _normalized(table, actual)


def test_postgres_normalization_rejects_exclusive_range():
    table = _table_by_name("mitigation_audit_events")
    inclusive = "length(chain_id) BETWEEN 1 AND 64"
    exclusive = "length(chain_id) > 1 AND length(chain_id) < 64"

    assert _normalized(table, inclusive) != _normalized(table, exclusive)


def test_postgres_normalization_preserves_semantic_cast_on_integer_column():
    table = _table_by_name("mitigation_decisions")

    assert _normalized(table, "value::text = '1'") != _normalized(
        table, "value = '1'"
    )


def test_sqlite_merged_check_reflection_is_expanded_without_loss():
    # SQLAlchemy's SQLite reflection greedily merges same-line named CHECK
    # clauses into one ``name``. Both real constraints must be recovered.
    reflected = {
        "name": (
            "ck_mitigation_policy_state_id CHECK (id = 2), CONSTRAINT "
            "ck_mitigation_policy_state_singleton_marker"
        ),
        "sqltext": "singleton_marker = 1",
    }

    assert verify_baseline._expand_reflected_checks(reflected) == [
        ("ck_mitigation_policy_state_id", "id = 2"),
        ("ck_mitigation_policy_state_singleton_marker", "singleton_marker = 1"),
    ]


def test_postgres_normalization_rejects_different_literals_or_operands():
    table = _table_by_name("mitigation_audit_events")

    assert _normalized(table, "length(chain_id) BETWEEN 1 AND 64") != _normalized(
        table, "length(chain_id) BETWEEN 1 AND 63"
    )
    assert _normalized(
        table, "length(substr(decision_uuid, 8)) = 0"
    ) != _normalized(table, "length(substr(decision_uuid, 9)) = 0")


def test_verifier_does_not_convert_genuine_check_mismatch_into_pass(
    phase1_engine, sqlite_url
):
    _set_revision(phase1_engine, _PHASE1_REVISION)
    with phase1_engine.begin() as connection:
        connection.execute(text("DROP TABLE mitigation_policy_state"))
        connection.execute(
            text(
                "CREATE TABLE mitigation_policy_state ("
                "id INTEGER DEFAULT 1 NOT NULL, "
                "policy_id INTEGER, "
                "singleton_marker INTEGER DEFAULT 1 NOT NULL, "
                "CONSTRAINT ck_mitigation_policy_state_id CHECK (id = 2), "
                "CONSTRAINT ck_mitigation_policy_state_singleton_marker "
                "CHECK (singleton_marker = 1), "
                "CONSTRAINT fk_mitigation_policy_state_policy FOREIGN KEY (policy_id) "
                "REFERENCES mitigation_policies (id) ON DELETE RESTRICT, "
                "PRIMARY KEY (id)"
                ")"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX ix_mitigation_policy_state_policy_id "
                "ON mitigation_policy_state (policy_id)"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX ix_mitigation_policy_state_singleton_marker "
                "ON mitigation_policy_state (singleton_marker)"
            )
        )

    result = verify_schema(sqlite_url)

    assert result.passed is False
    assert "CHECK_CONSTRAINT_DEFINITION_MISMATCH" in _codes(result)
    assert any(
        "ck_mitigation_policy_state_id" in finding.detail
        for finding in result.findings
    )


def _settings_import_nodes(module_relative_path, function_name):
    module_path = Path(__file__).resolve().parents[1] / module_relative_path
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    module_level = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "app.core.config"
    ]
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    in_function = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.ImportFrom) and node.module == "app.core.config"
    ]
    return module_level, in_function


def test_verify_baseline_defers_settings_import_to_main():
    module_level, in_function = _settings_import_nodes(
        "app/scripts/verify_baseline.py", "main"
    )
    assert module_level == []
    assert len(in_function) == 1


def test_verify_exact_structure_defers_settings_import():
    module_level, in_function = _settings_import_nodes(
        "app/scripts/verify_exact_structure.py", "verify_exact_structure"
    )
    assert module_level == []
    assert len(in_function) == 1


def test_verify_baseline_cli_still_uses_settings_when_needed():
    backend_dir = Path(__file__).resolve().parents[1]
    script = """
import sys
import types

module = types.ModuleType('app.core.config')

class _Settings:
    DEBUG = False
    ENVIRONMENT = 'test'

    def get_database_url(self):
        print('SETTINGS_CALLED')
        return 'sqlite:///:memory:'

module.settings = _Settings()
sys.modules['app.core.config'] = module

from app.scripts import verify_baseline
verify_baseline.main([])
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=backend_dir,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "SETTINGS_CALLED" in result.stdout


def _run_isolated_script(script):
    backend_dir = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=backend_dir,
        capture_output=True,
        text=True,
    )


_IMPORT_ISOLATION_GUARD = """
import sys
import sqlalchemy


def _block_engine(*args, **kwargs):
    raise AssertionError("ENGINE_CREATION_ATTEMPTED")


sqlalchemy.create_engine = _block_engine


class _BlockConfigImport:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "app.core.config":
            raise AssertionError("CONFIG_IMPORT_ATTEMPTED")


sys.meta_path.insert(0, _BlockConfigImport())
"""

_IMPORT_ISOLATION_ASSERTIONS = """
assert "app.core.config" not in sys.modules
assert "app.db.session" not in sys.modules
assert "engine" not in sys.modules["app.db"].__dict__
assert "SessionLocal" not in sys.modules["app.db"].__dict__
print("ISOLATION_OK")
"""


def test_baseline_verifier_import_is_fully_isolated():
    result = _run_isolated_script(
        _IMPORT_ISOLATION_GUARD
        + "import app.scripts.verify_baseline\n"
        + _IMPORT_ISOLATION_ASSERTIONS
    )
    assert result.returncode == 0, result.stderr
    assert "ISOLATION_OK" in result.stdout


def test_exact_verifier_import_is_fully_isolated():
    result = _run_isolated_script(
        _IMPORT_ISOLATION_GUARD
        + "import app.scripts.verify_exact_structure\n"
        + _IMPORT_ISOLATION_ASSERTIONS
    )
    assert result.returncode == 0, result.stderr
    assert "ISOLATION_OK" in result.stdout


def test_combined_verifier_imports_are_fully_isolated():
    result = _run_isolated_script(
        _IMPORT_ISOLATION_GUARD
        + "import app.scripts.verify_baseline\n"
        + "import app.scripts.verify_exact_structure\n"
        + _IMPORT_ISOLATION_ASSERTIONS
    )
    assert result.returncode == 0, result.stderr
    assert "ISOLATION_OK" in result.stdout


def test_cli_explicit_database_url_takes_precedence_over_settings():
    script = """
import sys
import types

module = types.ModuleType("app.core.config")


class _Settings:
    DEBUG = False
    ENVIRONMENT = "test"

    def get_database_url(self):
        print("SETTINGS_CALLED")
        return "sqlite:///:memory:"


module.settings = _Settings()
sys.modules["app.core.config"] = module

from app.scripts import verify_baseline

default_rc = verify_baseline.main([])
explicit_rc = verify_baseline.main(["--database-url", "sqlite:///:memory:"])
print("RC=" + str(default_rc) + "," + str(explicit_rc))
"""
    result = _run_isolated_script(script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("SETTINGS_CALLED") == 1
    rc_line = next(line for line in result.stdout.splitlines() if line.startswith("RC="))
    default_rc, explicit_rc = rc_line[3:].split(",")
    assert default_rc == explicit_rc
    assert result.stdout.count("SCHEMA_VERIFICATION:") == 2


def test_model_metadata_available_without_settings_or_engine():
    script = """
import sys
import app.models
from app.db.base import Base

expected = {
    "api_traffic_logs",
    "mitigation_audit_events",
    "mitigation_decisions",
    "mitigation_policies",
    "mitigation_policy_activation_events",
    "mitigation_policy_state",
    "revoked_tokens",
    "users",
}
assert set(Base.metadata.tables) == expected
traffic_columns = set(Base.metadata.tables["api_traffic_logs"].columns.keys())
users_columns = set(Base.metadata.tables["users"].columns.keys())
assert {"id", "timestamp", "client_ip", "request_id", "status_code", "method"} <= traffic_columns
assert {"id", "email", "hashed_password", "role", "is_active"} <= users_columns
assert "app.core.config" not in sys.modules
assert "app.db.session" not in sys.modules
assert "engine" not in sys.modules["app.db"].__dict__
print("MODEL_METADATA_OK")
"""
    result = _run_isolated_script(script)
    assert result.returncode == 0, result.stderr
    assert "MODEL_METADATA_OK" in result.stdout


def test_explicit_init_db_path_works_with_mocked_engine():
    script = """
import socket
import sys
import types
from unittest.mock import MagicMock


def _block_connect(self, address):
    raise AssertionError("SOCKET_CONNECT_ATTEMPTED")


socket.socket.connect = _block_connect

config = types.ModuleType("app.core.config")


class _Settings:
    DEBUG = False
    ENVIRONMENT = "test"


config.settings = _Settings()
sys.modules["app.core.config"] = config

fake_engine = MagicMock(name="engine")
fake_engine.begin.return_value.__enter__.return_value.dialect.name = "postgresql"
session_module = types.ModuleType("app.db.session")
session_module.engine = fake_engine
session_module.SessionLocal = MagicMock(name="SessionLocal")
session_module.get_db = lambda: None
sys.modules["app.db.session"] = session_module

import app.db
from app.db.base import Base
from app.db.init_db import init_db

public_export = getattr(app.db, "init_db")
resolved_export = getattr(public_export, "init_db", public_export)
assert callable(resolved_export)

create_all_calls = []
original_create_all = Base.metadata.create_all
Base.metadata.create_all = lambda bind=None, **kwargs: create_all_calls.append(bind is fake_engine)
try:
    init_db()
finally:
    Base.metadata.create_all = original_create_all

assert create_all_calls == [True]
assert not fake_engine.connect.called
print("INIT_DB_MOCK_OK")
"""
    result = _run_isolated_script(script)
    assert result.returncode == 0, result.stderr
    assert "INIT_DB_MOCK_OK" in result.stdout
