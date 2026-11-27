"""Focused tests for the one-off users-only baseline correction artifact.

No configured database is contacted. PostgreSQL-specific runtime behaviour is
verified by dialect compilation and unit checks only; SQLite is used solely to
exercise transaction rollback and repeat-execution refusal.
"""

from dataclasses import replace
import importlib
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, types as sa_types
from sqlalchemy.dialects import postgresql
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import CreateIndex, CreateTable

from app.models.traffic import APITrafficLog
from app.models.user import User
import app.scripts.apply_users_baseline_correction as correction


def _valid_identity() -> correction.DatabaseIdentity:
    return correction.DatabaseIdentity(
        database=correction.APPROVED_DATABASE,
        version_string="PostgreSQL 17.10 on x86_64-windows, compiled by msvc-19.44.35227, 64-bit",
        server_version_num=correction.APPROVED_SERVER_VERSION_NUM,
        current_schema=correction.APPROVED_SCHEMA,
    )


def _valid_traffic_schema() -> correction.TableSchema:
    expected = correction._expected_table_schema(APITrafficLog.__table__)
    return replace(
        expected,
        sequences=frozenset({correction.TRAFFIC_SEQUENCE}),
        id_default="nextval('api_traffic_logs_id_seq'::regclass)",
    )


def _valid_traffic_safety() -> correction.TrafficSafety:
    return correction.TrafficSafety(
        sequence_names=frozenset({correction.TRAFFIC_SEQUENCE}),
        sequence_associations=correction.EXPECTED_SEQUENCE_OWNERSHIP,
        user_triggers=frozenset(),
        non_internal_rules=frozenset(),
        event_triggers=frozenset(),
        generated_columns=frozenset(),
        identity_columns=frozenset(),
    )


def _valid_snapshot(**overrides) -> correction.PreflightSnapshot:
    values = {
        "identity": _valid_identity(),
        "tables": frozenset({correction.TRAFFIC_TABLE}),
        "traffic": _valid_traffic_schema(),
        "fingerprint": correction.approved_fingerprint(),
        "traffic_safety": _valid_traffic_safety(),
    }
    values.update(overrides)
    return correction.PreflightSnapshot(**values)


def _valid_users_post_state() -> correction.UsersPostState:
    expected = correction._expected_table_schema(User.__table__)
    return correction.UsersPostState(
        columns=expected.columns,
        primary_key=expected.primary_key,
        indexes=correction.EXPECTED_USERS_INDEXES,
        check_constraints=(),
        foreign_keys=(),
        unique_constraints=(),
        triggers=(),
        sequences=frozenset({correction.USERS_SEQUENCE}),
        id_default="nextval('users_id_seq'::regclass)",
        sequence_owned=True,
        row_count=0,
    )


def _compiled_ddl() -> list[str]:
    dialect = postgresql.dialect()
    return [str(item.compile(dialect=dialect)).strip() for item in correction.build_users_ddl()]


def _reflected_traffic_schema(timestamp_type: object) -> correction.TableSchema:
    """Model the traffic schema as SQLAlchemy reflection reports it.

    Reflection returns a TIMESTAMP type object rather than the model's DateTime
    object; only the timestamp column is swapped so every other column stays at
    its already-matching expected value.
    """
    baseline = _valid_traffic_schema()
    columns = frozenset(
        ("timestamp", correction._normalize_type(timestamp_type), False)
        if name == "timestamp"
        else (name, normalized, nullable)
        for name, normalized, nullable in baseline.columns
    )
    return replace(baseline, columns=columns)


def _valid_post_traffic_schema() -> correction.TableSchema:
    """Traffic schema after the expected users_id_seq addition."""
    return replace(
        _valid_traffic_schema(),
        sequences=frozenset({correction.TRAFFIC_SEQUENCE, correction.USERS_SEQUENCE}),
    )


@pytest.fixture
def sqlite_public_engine():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _attach_public(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("ATTACH DATABASE ':memory:' AS public")
        cursor.close()

    yield engine
    engine.dispose()


def test_valid_snapshot_is_ready():
    assert correction.validate_preflight(_valid_snapshot()) == ()


def test_refuses_when_users_already_exists():
    snapshot = _valid_snapshot(tables=frozenset({correction.TRAFFIC_TABLE, "users"}))
    assert "USERS_TABLE_ALREADY_EXISTS" in correction.validate_preflight(snapshot)


def test_refuses_when_alembic_version_exists():
    snapshot = _valid_snapshot(tables=frozenset({correction.TRAFFIC_TABLE, "alembic_version"}))
    assert "ALEMBIC_VERSION_TABLE_EXISTS" in correction.validate_preflight(snapshot)


def test_refuses_when_mitigation_tables_exist():
    snapshot = _valid_snapshot(
        tables=frozenset({correction.TRAFFIC_TABLE, "mitigation_policies"})
    )
    assert "MITIGATION_TABLE_EXISTS" in correction.validate_preflight(snapshot)


def test_refuses_when_traffic_table_absent():
    snapshot = _valid_snapshot(tables=frozenset(), traffic=None, fingerprint=None)
    errors = correction.validate_preflight(snapshot)
    assert "TRAFFIC_TABLE_MISSING" in errors


def test_refuses_when_traffic_schema_differs():
    drifted = replace(_valid_traffic_schema(), primary_key=frozenset({"wrong_id"}))
    snapshot = _valid_snapshot(traffic=drifted)
    assert "TRAFFIC_PRIMARY_KEY_MISMATCH" in correction.validate_preflight(snapshot)


def test_reflected_postgresql_timestamptz_normalizes_to_timestamptz():
    # psycopg v3 reflection returns TIMESTAMP(timezone=True), whose str() is
    # "TIMESTAMP" (the timezone flag is lost); it must still normalize to the
    # same family as the model's DateTime(timezone=True).
    for timestamp_type in (
        postgresql.TIMESTAMP(timezone=True),
        sa_types.TIMESTAMP(timezone=True),
    ):
        assert str(timestamp_type) == "TIMESTAMP"
        assert correction._normalize_type(timestamp_type) == "timestamptz"


def test_reflected_postgresql_naive_timestamp_stays_naive():
    for timestamp_type in (
        postgresql.TIMESTAMP(timezone=False),
        sa_types.TIMESTAMP(timezone=False),
    ):
        assert correction._normalize_type(timestamp_type) == "timestamp"


def test_existing_string_based_type_normalization_is_preserved():
    assert correction._normalize_type("TIMESTAMP WITH TIME ZONE") == "timestamptz"
    assert correction._normalize_type("timestamptz") == "timestamptz"
    assert correction._normalize_type("timestamp with time zone") == "timestamptz"
    assert correction._normalize_type("timestamp without time zone") == "timestamp"
    assert correction._normalize_type("DATETIME") == "timestamptz"
    assert correction._normalize_type("character varying(255)") == "varchar(255)"
    assert correction._normalize_type("double precision") == "double_precision"
    assert correction._normalize_type("float") == "double_precision"
    assert correction._normalize_type("INTEGER") == "integer"


def test_traffic_schema_accepts_reflected_timestamptz_but_rejects_wrong_types():
    reflected = _reflected_traffic_schema(postgresql.TIMESTAMP(timezone=True))
    assert correction.validate_preflight(_valid_snapshot(traffic=reflected)) == ()

    naive = _reflected_traffic_schema(postgresql.TIMESTAMP(timezone=False))
    assert "TRAFFIC_SCHEMA_MISMATCH" in correction.validate_preflight(
        _valid_snapshot(traffic=naive)
    )

    wrong_type = _reflected_traffic_schema(postgresql.VARCHAR(64))
    assert "TRAFFIC_SCHEMA_MISMATCH" in correction.validate_preflight(
        _valid_snapshot(traffic=wrong_type)
    )


def test_refuses_when_traffic_fingerprint_differs():
    drifted = replace(correction.approved_fingerprint(), rows=18967)
    snapshot = _valid_snapshot(fingerprint=drifted)
    assert "TRAFFIC_FINGERPRINT_MISMATCH" in correction.validate_preflight(snapshot)


def test_refuses_when_database_identity_is_not_approved():
    identity = replace(_valid_identity(), database="some_other_db")
    snapshot = _valid_snapshot(identity=identity)
    assert "DATABASE_IDENTITY_MISMATCH" in correction.validate_preflight(snapshot)


def test_refuses_when_postgres_version_is_not_1710():
    identity = replace(
        _valid_identity(),
        version_string="PostgreSQL 16.1 on x86_64-windows",
        server_version_num="160001",
    )
    snapshot = _valid_snapshot(identity=identity)
    assert "UNSUPPORTED_POSTGRES_VERSION" in correction.validate_preflight(snapshot)


def test_refuses_when_schema_is_not_public():
    identity = replace(_valid_identity(), current_schema="other")
    snapshot = _valid_snapshot(identity=identity)
    assert "UNEXPECTED_SCHEMA" in correction.validate_preflight(snapshot)


def test_refuses_without_explicit_confirmation(capsys):
    assert correction.validate_confirmation(None, None) == (
        "CONFIRM_DATABASE_REQUIRED",
        "CONFIRM_OPERATION_REQUIRED",
    )
    assert correction.validate_confirmation(
        "some_other_db", "upgrade-head"
    ) == ("CONFIRM_DATABASE_MISMATCH", "CONFIRM_OPERATION_MISMATCH")
    assert correction.validate_confirmation(
        correction.APPROVED_DATABASE, correction.CONFIRM_OPERATION
    ) == ()
    assert correction.main([]) == 2
    captured = capsys.readouterr()
    assert (
        "REFUSED: CONFIRM_DATABASE_REQUIRED, CONFIRM_OPERATION_REQUIRED"
        in captured.out
    )


def test_creation_ddl_matches_current_user_metadata():
    statements = correction.build_users_ddl()
    assert len(statements) == 1 + len(User.__table__.indexes)
    assert isinstance(statements[0], CreateTable)
    assert statements[0].element is User.__table__
    index_statements = statements[1:]
    assert all(isinstance(item, CreateIndex) for item in index_statements)
    assert {item.element.name for item in index_statements} == {
        index.name for index in User.__table__.indexes
    }
    for statement in index_statements:
        expected = next(
            index for index in User.__table__.indexes
            if index.name == statement.element.name
        )
        assert [column.name for column in statement.element.columns] == [
            column.name for column in expected.columns
        ]
        assert statement.element.unique == expected.unique


def test_all_eight_expected_columns_are_present():
    create_sql = _compiled_ddl()[0]
    assert len(User.__table__.columns) == 8
    for fragment in (
        "id SERIAL NOT NULL",
        "email VARCHAR(255) NOT NULL",
        "username VARCHAR(100) NOT NULL",
        "hashed_password VARCHAR(255) NOT NULL",
        "role VARCHAR(50) NOT NULL",
        "is_active BOOLEAN NOT NULL",
        "created_at TIMESTAMP WITH TIME ZONE NOT NULL",
        "updated_at TIMESTAMP WITH TIME ZONE NOT NULL",
        "PRIMARY KEY (id)",
    ):
        assert fragment in create_sql


def test_all_five_indexes_and_uniqueness_are_present():
    index_sql = _compiled_ddl()[1:]
    assert len(index_sql) == 5
    expected = (
        "CREATE UNIQUE INDEX ix_users_email ON users (email)",
        "CREATE INDEX ix_users_id ON users (id)",
        "CREATE INDEX ix_users_is_active ON users (is_active)",
        "CREATE INDEX ix_users_role ON users (role)",
        "CREATE UNIQUE INDEX ix_users_username ON users (username)",
    )
    for statement in expected:
        assert statement in index_sql


def test_serial_sequence_and_autoincrement_are_generated_for_postgresql():
    create_sql = _compiled_ddl()[0]
    assert "id SERIAL NOT NULL" in create_sql
    assert "PRIMARY KEY (id)" in create_sql
    assert "AUTOINCREMENT" not in create_sql


def test_no_ddl_is_generated_for_traffic_table():
    assert "api_traffic_logs" not in "\n".join(_compiled_ddl())


def test_correction_source_contains_no_traffic_mutation_or_create_all():
    source = Path(correction.__file__).read_text(encoding="utf-8")
    forbidden = (
        "DROP TABLE api_traffic_logs",
        "TRUNCATE api_traffic_logs",
        "ALTER TABLE api_traffic_logs",
        "INSERT INTO api_traffic_logs",
        "DELETE FROM api_traffic_logs",
        "UPDATE api_traffic_logs",
        "create_all(",
        "command.stamp",
        "command.upgrade",
        "command.downgrade",
    )
    for token in forbidden:
        assert token not in source


def test_transaction_rolls_back_on_post_check_failure(sqlite_public_engine, monkeypatch):
    # SQLite in this environment does not roll back DDL, so rollback is verified
    # through SQLAlchemy transaction events rather than physical table absence.
    events: list[str] = []

    @event.listens_for(sqlite_public_engine, "begin")
    def _on_begin(_connection):
        events.append("begin")

    @event.listens_for(sqlite_public_engine, "commit")
    def _on_commit(_connection):
        events.append("commit")

    @event.listens_for(sqlite_public_engine, "rollback")
    def _on_rollback(_connection):
        events.append("rollback")

    monkeypatch.setattr(correction, "gather_snapshot", lambda _conn: _valid_snapshot())
    monkeypatch.setattr(
        correction, "read_users_post_state", lambda _conn: _valid_users_post_state()
    )
    monkeypatch.setattr(
        correction,
        "validate_users_post_state",
        lambda _state: ("FORCED_POST_CHECK_FAILURE",),
    )
    with pytest.raises(correction.CorrectionPostCheckFailed):
        correction.apply_users_correction(sqlite_public_engine)
    assert events.count("begin") == 1
    assert events.count("rollback") == 1
    assert "commit" not in events


def test_refuses_repeat_execution(sqlite_public_engine, monkeypatch):
    monkeypatch.setattr(correction, "gather_snapshot", lambda _conn: _valid_snapshot())
    monkeypatch.setattr(
        correction, "read_users_post_state", lambda _conn: _valid_users_post_state()
    )
    monkeypatch.setattr(
        correction, "validate_traffic_post_state", lambda _conn, _before: ()
    )
    result = correction.apply_users_correction(sqlite_public_engine)
    assert result.tables_created == ("users",)
    assert result.indexes_created == tuple(
        sorted(item[0] for item in correction.EXPECTED_USERS_INDEXES)
    )
    with pytest.raises(correction.CorrectionRefused, match="USERS_TABLE_ALREADY_EXISTS"):
        correction.apply_users_correction(sqlite_public_engine)


def test_no_user_records_are_inserted(sqlite_public_engine, monkeypatch):
    monkeypatch.setattr(correction, "gather_snapshot", lambda _conn: _valid_snapshot())
    monkeypatch.setattr(
        correction, "read_users_post_state", lambda _conn: _valid_users_post_state()
    )
    monkeypatch.setattr(
        correction, "validate_traffic_post_state", lambda _conn, _before: ()
    )
    correction.apply_users_correction(sqlite_public_engine)
    with sqlite_public_engine.connect() as connection:
        # Unqualified name resolves to public.users under the verified PostgreSQL
        # search path; in the disposable SQLite harness it resolves to main.users.
        assert connection.exec_driver_sql(
            "SELECT count(*) FROM users"
        ).scalar_one() == 0
    invalid = replace(_valid_users_post_state(), row_count=1)
    assert "UNEXPECTED_USER_RECORDS" in correction.validate_users_post_state(invalid)


def test_importing_module_has_no_side_effects(monkeypatch):
    import sqlalchemy

    def forbidden_create_engine(*_args, **_kwargs):
        raise AssertionError("create_engine called during module import")

    monkeypatch.setattr(sqlalchemy, "create_engine", forbidden_create_engine)
    assert importlib.reload(correction) is correction


def test_post_check_detects_traffic_schema_and_fingerprint_change(monkeypatch):
    monkeypatch.setattr(
        correction, "read_table_schema", lambda _conn, _name: _valid_post_traffic_schema()
    )
    monkeypatch.setattr(correction, "read_sequence_ownership", lambda *_args, **_kwargs: True)
    changed = replace(correction.approved_fingerprint(), rows=18967)
    monkeypatch.setattr(correction, "read_traffic_fingerprint", lambda _conn: changed)
    errors = correction.validate_traffic_post_state(None, _valid_snapshot())
    assert "TRAFFIC_FINGERPRINT_CHANGED" in errors

    monkeypatch.setattr(
        correction,
        "read_table_schema",
        lambda _conn, _name: replace(_valid_post_traffic_schema(), id_default=""),
    )
    errors = correction.validate_traffic_post_state(None, _valid_snapshot())
    assert "TRAFFIC_SCHEMA_CHANGED" in errors


def _wire_post_check(monkeypatch, schema=None, owned=True):
    """Point the post-check readers at a controlled schema without any database."""
    monkeypatch.setattr(
        correction,
        "read_table_schema",
        lambda _conn, _name: (
            schema if schema is not None else _valid_post_traffic_schema()
        ),
    )
    monkeypatch.setattr(
        correction, "read_sequence_ownership", lambda *_args, **_kwargs: owned
    )
    monkeypatch.setattr(
        correction,
        "read_traffic_fingerprint",
        lambda _conn: correction.approved_fingerprint(),
    )


def test_expected_users_sequence_addition_does_not_fail_traffic_post_check(monkeypatch):
    _wire_post_check(monkeypatch)
    assert correction.validate_traffic_post_state(None, _valid_snapshot()) == ()


def test_traffic_sequence_remains_present_and_unchanged(monkeypatch):
    before = _valid_snapshot()
    assert correction.TRAFFIC_SEQUENCE in before.traffic.sequences
    assert correction.TRAFFIC_SEQUENCE in before.traffic.id_default

    missing = replace(
        _valid_post_traffic_schema(),
        sequences=frozenset({correction.USERS_SEQUENCE}),
    )
    _wire_post_check(monkeypatch, schema=missing)
    errors = correction.validate_traffic_post_state(None, before)
    assert "UNEXPECTED_SEQUENCE_CHANGE" in errors
    assert "TRAFFIC_SEQUENCE_MISSING" in errors


def test_unexpected_extra_public_sequence_is_rejected(monkeypatch):
    extra = replace(
        _valid_post_traffic_schema(),
        sequences=frozenset(
            {correction.TRAFFIC_SEQUENCE, correction.USERS_SEQUENCE, "rogue_sequence"}
        ),
    )
    _wire_post_check(monkeypatch, schema=extra)
    errors = correction.validate_traffic_post_state(None, _valid_snapshot())
    assert "UNEXPECTED_SEQUENCE_CHANGE" in errors


def test_altered_traffic_sequence_default_is_rejected(monkeypatch):
    altered = replace(_valid_post_traffic_schema(), id_default="")
    _wire_post_check(monkeypatch, schema=altered)
    errors = correction.validate_traffic_post_state(None, _valid_snapshot())
    assert "TRAFFIC_SCHEMA_CHANGED" in errors


def test_altered_traffic_column_index_or_primary_key_is_rejected(monkeypatch):
    base = _valid_post_traffic_schema()
    before = _valid_snapshot()
    drifted_columns = replace(
        base,
        columns=frozenset(
            ("status_code", "integer", True) if item[0] == "status_code" else item
            for item in base.columns
        ),
    )
    for drifted in (
        drifted_columns,
        replace(base, indexes=frozenset()),
        replace(base, primary_key=frozenset({"wrong_id"})),
    ):
        _wire_post_check(monkeypatch, schema=drifted)
        assert "TRAFFIC_SCHEMA_CHANGED" in correction.validate_traffic_post_state(
            None, before
        )


def test_traffic_sequence_ownership_is_enforced(monkeypatch):
    _wire_post_check(monkeypatch, owned=False)
    errors = correction.validate_traffic_post_state(None, _valid_snapshot())
    assert "TRAFFIC_SEQUENCE_OWNERSHIP_MISMATCH" in errors


def test_traffic_ownership_check_targets_traffic_sequence_and_table(monkeypatch):
    calls: list[dict] = []
    _wire_post_check(monkeypatch)
    monkeypatch.setattr(
        correction,
        "read_sequence_ownership",
        lambda _conn, **kwargs: calls.append(kwargs) or True,
    )
    assert correction.validate_traffic_post_state(None, _valid_snapshot()) == ()
    assert calls == [
        {
            "sequence_name": correction.TRAFFIC_SEQUENCE,
            "table_name": correction.TRAFFIC_TABLE,
        }
    ]


def test_users_sequence_ownership_and_default_are_validated():
    valid = _valid_users_post_state()
    assert correction.validate_users_post_state(valid) == ()
    assert "USERS_SEQUENCE_OWNERSHIP_MISMATCH" in correction.validate_users_post_state(
        replace(valid, sequence_owned=False)
    )
    assert "USERS_SEQUENCE_MISSING" in correction.validate_users_post_state(
        replace(valid, sequences=frozenset({correction.TRAFFIC_SEQUENCE}))
    )
    assert "USERS_ID_DEFAULT_MISMATCH" in correction.validate_users_post_state(
        replace(valid, id_default="")
    )


def test_exact_expected_sequence_inventory_is_ready():
    safety = _valid_traffic_safety()
    assert safety.sequence_names == correction.EXPECTED_SEQUENCES
    assert correction.validate_preflight(_valid_snapshot(traffic_safety=safety)) == ()


def test_unexpected_orphan_sequence_causes_refusal():
    safety = replace(
        _valid_traffic_safety(),
        sequence_names=frozenset({correction.TRAFFIC_SEQUENCE, "rogue_sequence"}),
    )
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "UNEXPECTED_SEQUENCE" in errors


def test_existing_users_sequence_causes_refusal():
    safety = replace(
        _valid_traffic_safety(),
        sequence_names=frozenset({correction.TRAFFIC_SEQUENCE, correction.USERS_SEQUENCE}),
        sequence_associations=frozenset(
            {
                (correction.TRAFFIC_SEQUENCE, correction.TRAFFIC_TABLE, "id"),
                (correction.USERS_SEQUENCE, correction.USERS_TABLE, "id"),
            }
        ),
    )
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "USERS_SEQUENCE_ALREADY_EXISTS" in errors
    assert "UNEXPECTED_SEQUENCE" in errors


def test_missing_traffic_sequence_causes_refusal():
    safety = replace(
        _valid_traffic_safety(),
        sequence_names=frozenset(),
        sequence_associations=frozenset(),
    )
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "TRAFFIC_SEQUENCE_MISSING" in errors
    assert "UNEXPECTED_SEQUENCE_ASSOCIATION" in errors


def test_unexpected_sequence_association_causes_refusal():
    safety = replace(
        _valid_traffic_safety(),
        sequence_associations=frozenset(
            {(correction.TRAFFIC_SEQUENCE, "unexpected_table", "id")}
        ),
    )
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "UNEXPECTED_SEQUENCE_ASSOCIATION" in errors


def test_user_defined_traffic_trigger_causes_refusal():
    safety = replace(_valid_traffic_safety(), user_triggers=frozenset({"traffic_audit"}))
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "UNEXPECTED_TRAFFIC_TRIGGER" in errors


def test_non_internal_traffic_rule_causes_refusal():
    safety = replace(_valid_traffic_safety(), non_internal_rules=frozenset({"reroute"}))
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "UNEXPECTED_TRAFFIC_RULE" in errors


def test_event_trigger_and_column_features_cause_refusal():
    safety = replace(
        _valid_traffic_safety(),
        event_triggers=frozenset({"block_ddl"}),
        generated_columns=frozenset({"path"}),
        identity_columns=frozenset({"id"}),
    )
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=safety))
    assert "UNEXPECTED_EVENT_TRIGGER" in errors
    assert "UNEXPECTED_GENERATED_COLUMN" in errors
    assert "UNEXPECTED_IDENTITY_COLUMN" in errors


def test_missing_safety_snapshot_fails_closed():
    errors = correction.validate_preflight(_valid_snapshot(traffic_safety=None))
    assert "SEQUENCE_INVENTORY_UNAVAILABLE" in errors


def test_search_path_hardening_statement_is_exact():
    class _RecordingConnection:
        dialect = type("Dialect", (), {"name": "postgresql"})()

        def __init__(self):
            self.statements = []

        def execute(self, statement, params=None):
            self.statements.append(str(statement))
            return self

    connection = _RecordingConnection()
    correction.set_transaction_search_path(connection)
    assert connection.statements == [correction.SET_TRANSACTION_SEARCH_PATH]
    assert connection.statements[0] == "SET LOCAL search_path TO public"


def test_search_path_hardening_runs_before_users_ddl(
    sqlite_public_engine, monkeypatch
):
    events: list[str] = []

    @event.listens_for(sqlite_public_engine, "before_cursor_execute")
    def _record(_conn, _cursor, statement, _params, _context, _executemany):
        if "CREATE TABLE users" in statement:
            events.append("ddl")

    monkeypatch.setattr(correction, "gather_snapshot", lambda _conn: _valid_snapshot())
    monkeypatch.setattr(
        correction, "read_users_post_state", lambda _conn: _valid_users_post_state()
    )
    monkeypatch.setattr(
        correction, "validate_traffic_post_state", lambda _conn, _before: ()
    )
    monkeypatch.setattr(
        correction,
        "set_transaction_search_path",
        lambda _conn: events.append("search_path"),
    )
    correction.apply_users_correction(sqlite_public_engine)
    assert events == ["search_path", "ddl"]


def test_operational_error_produces_controlled_nonzero_cli_result(capsys):
    def _failing_engine_factory():
        raise RuntimeError("postgres://secret-host:secret-password@secret/db")

    exit_code = correction.main(
        [
            "--confirm-database",
            correction.APPROVED_DATABASE,
            "--confirm-operation",
            correction.CONFIRM_OPERATION,
        ],
        engine_factory=_failing_engine_factory,
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "FAILED: RuntimeError" in captured.out
    assert "secret-host" not in captured.out
    assert "secret-password" not in captured.out


def test_refused_preflight_message_is_actionable_and_safe(capsys, monkeypatch):
    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class _Engine:
        def connect(self):
            return _Connection()

        def dispose(self):
            return None

    monkeypatch.setattr(
        correction, "gather_snapshot", lambda _conn: _valid_snapshot(
            traffic_safety=replace(
                _valid_traffic_safety(),
                sequence_names=frozenset(
                    {correction.TRAFFIC_SEQUENCE, "unexpected_sequence"}
                ),
            )
        )
    )
    exit_code = correction.main(
        [
            "--confirm-database",
            correction.APPROVED_DATABASE,
            "--confirm-operation",
            correction.CONFIRM_OPERATION,
        ],
        engine_factory=_Engine,
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "REFUSED: UNEXPECTED_SEQUENCE" in captured.out
