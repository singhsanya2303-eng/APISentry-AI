"""Unit tests for the read-only exact structural verifier.

No PostgreSQL server, Docker container, or configured database is used. All
observations are supplied as isolated snapshots, and CLI failure paths use
injected engine factories or monkeypatched verifier functions.
"""

from dataclasses import replace
from pathlib import Path
import re

import pytest
from sqlalchemy import CheckConstraint

from app.scripts import verify_exact_structure as verifier
from app.scripts.verify_exact_structure import (
    APPROVED_DATABASE,
    APPROVED_POSTGRES_VERSION,
    APPROVED_SCHEMA,
    APPROVED_SERVER_VERSION_NUM,
    ColumnFeatureRecord,
    ColumnRecord,
    GrantRecord,
    IdentityRecord,
    IndexRecord,
    MODE_AFTER_MIGRATIONS,
    MODE_CORRECTED_USERS,
    MODE_PRE_CORRECTION,
    ObjectRecord,
    SequenceRecord,
    VerificationResult,
)


def _snapshot(mode: str = MODE_CORRECTED_USERS) -> verifier.SchemaSnapshot:
    expected = verifier.expected_structure(mode)
    columns = []
    primary_keys = {}
    indexes = []
    checks = []
    foreign_keys = []
    model_tables = verifier._model_tables_by_name()
    for table in expected.tables.values():
        for position, column in enumerate(table.columns, start=1):
            columns.append(
                ColumnRecord(
                    table_name=table.name,
                    name=column.name,
                    ordinal=position,
                    data_type=column.data_type,
                    nullable=column.nullable,
                    default=column.default,
                )
            )
        if table.primary_key:
            primary_keys[table.name] = table.primary_key
        for name, (index_columns, unique) in table.indexes.items():
            indexes.append(IndexRecord(table.name, name, index_columns, unique))
        model_table = model_tables.get(table.name)
        for name in table.checks:
            if model_table is None:
                continue
            constraint = next(
                item
                for item in model_table.constraints
                if isinstance(item, CheckConstraint) and str(item.name) == name
            )
            checks.append(
                verifier.CheckRecord(table.name, name, str(constraint.sqltext))
            )
        for key, definition in table.foreign_keys.items():
            foreign_keys.append(verifier.ForeignKeyRecord(table.name, key, definition))

    sequences = tuple(
        SequenceRecord(name, "reviewed_owner", owner_table, owner_column)
        for name, (owner_table, owner_column) in expected.sequence_owners.items()
    )
    table_owners = {name: "reviewed_owner" for name in expected.tables}
    revision_rows = () if expected.revision is None else (expected.revision,)
    return verifier.SchemaSnapshot(
        identity=IdentityRecord(
            database=APPROVED_DATABASE,
            current_schema=APPROVED_SCHEMA,
            version_string=f"PostgreSQL {APPROVED_POSTGRES_VERSION} on reviewed-platform",
            server_version_num=APPROVED_SERVER_VERSION_NUM,
            dialect="postgresql",
        ),
        schemas={APPROVED_SCHEMA: "reviewed_owner"},
        table_names=frozenset(expected.tables),
        relation_names=frozenset(expected.tables),
        columns=tuple(columns),
        primary_keys=primary_keys,
        indexes=tuple(indexes),
        checks=tuple(checks),
        foreign_keys=tuple(foreign_keys),
        sequences=sequences,
        triggers=(),
        rules=(),
        column_features=(),
        table_owners=table_owners,
        grants=(),
        event_triggers=frozenset(),
        revision_rows=revision_rows,
    )


def _codes(result):
    return {finding.category for finding in result.findings if finding.status == "FAIL"}


def _compare(
    snapshot,
    mode: str = MODE_CORRECTED_USERS,
    expected_owner=None,
    expected_schema_owner=None,
):
    return verifier.compare_snapshot(
        snapshot,
        verifier.expected_structure(mode),
        expected_owner,
        expected_schema_owner,
    )


def _replace_column(snapshot, table_name: str, column_name: str, **changes):
    columns = []
    for column in snapshot.columns:
        if column.table_name == table_name and column.name == column_name:
            column = replace(column, **changes)
        columns.append(column)
    return replace(snapshot, columns=tuple(columns))


def test_correct_schema_passes():
    result = _compare(_snapshot())
    assert result.passed
    assert "EXACT_STRUCTURE_MATCH" in {
        finding.category for finding in result.findings if finding.status == "PASS"
    }


def test_modes_are_distinct_and_derived_from_source():
    pre = verifier.expected_structure(MODE_PRE_CORRECTION)
    corrected = verifier.expected_structure(MODE_CORRECTED_USERS)
    final = verifier.expected_structure(MODE_AFTER_MIGRATIONS)
    assert set(pre.tables) == {"api_traffic_logs"}
    assert set(corrected.tables) == {"api_traffic_logs", "users"}
    assert pre.revision is None and corrected.revision is None
    assert final.revision == "0004_revoked_tokens"
    assert "mitigation_audit_events" in final.tables
    assert "revoked_tokens" in final.tables
    assert "revoked_tokens" in verifier._model_tables_by_name()
    assert "alembic_version" in final.tables
    assert "mitigation_policy_state_id_seq" not in final.sequence_owners


def test_after_migrations_snapshot_passes_with_revoked_tokens():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    result = verifier.compare_snapshot(
        snapshot, verifier.expected_structure(MODE_AFTER_MIGRATIONS), None, None
    )

    assert result.passed
    assert "revoked_tokens" in snapshot.table_names


def test_wrong_varchar_length_fails():
    snapshot = _replace_column(
        _snapshot(), "users", "email", data_type="varchar(100)"
    )
    assert "COLUMN_TYPE_MISMATCH" in _codes(_compare(snapshot))


def test_wrong_column_order_fails():
    snapshot = _snapshot()
    users_columns = [
        column for column in snapshot.columns if column.table_name == "users"
    ]
    first, second = users_columns[0], users_columns[1]
    columns = []
    for column in snapshot.columns:
        if column is first:
            column = replace(column, ordinal=second.ordinal)
        elif column is second:
            column = replace(column, ordinal=first.ordinal)
        columns.append(column)
    assert "COLUMN_ORDER_MISMATCH" in _codes(_compare(replace(snapshot, columns=tuple(columns))))


def test_wrong_nullability_fails():
    snapshot = _replace_column(_snapshot(), "users", "email", nullable=True)
    assert "COLUMN_NULLABILITY_MISMATCH" in _codes(_compare(snapshot))


def test_missing_index_fails():
    snapshot = _snapshot()
    indexes = tuple(
        index for index in snapshot.indexes if not (
            index.table_name == "users" and index.name == "ix_users_email"
        )
    )
    assert "MISSING_INDEX" in _codes(_compare(replace(snapshot, indexes=indexes)))


def test_incorrect_index_uniqueness_fails():
    snapshot = _snapshot()
    indexes = tuple(
        replace(index, unique=True)
        if index.table_name == "users" and index.name == "ix_users_id"
        else index
        for index in snapshot.indexes
    )
    assert "INDEX_DEFINITION_MISMATCH" in _codes(
        _compare(replace(snapshot, indexes=indexes))
    )


def test_unexpected_sequence_fails():
    snapshot = _snapshot()
    sequences = snapshot.sequences + (
        SequenceRecord("rogue_sequence", "reviewed_owner", None, None),
    )
    assert "UNEXPECTED_SEQUENCE" in _codes(_compare(replace(snapshot, sequences=sequences)))


def test_incorrect_sequence_ownership_fails():
    snapshot = _snapshot()
    sequences = tuple(
        replace(sequence, owner_table="unexpected_table")
        if sequence.name == "users_id_seq"
        else sequence
        for sequence in snapshot.sequences
    )
    assert "SEQUENCE_OWNERSHIP_MISMATCH" in _codes(
        _compare(replace(snapshot, sequences=sequences))
    )


def test_unexpected_trigger_fails():
    snapshot = _snapshot()
    assert "UNEXPECTED_TRIGGER" in _codes(
        _compare(replace(snapshot, triggers=(ObjectRecord("users", "audit_trigger"),)))
    )


def test_unexpected_rule_fails():
    snapshot = _snapshot()
    assert "UNEXPECTED_RULE" in _codes(
        _compare(replace(snapshot, rules=(ObjectRecord("users", "reroute"),)))
    )


def test_incorrect_default_fails():
    snapshot = _replace_column(_snapshot(), "users", "id", default=None)
    assert "COLUMN_DEFAULT_MISMATCH" in _codes(_compare(snapshot))


def test_unexpected_generated_and_identity_configuration_fails():
    snapshot = _snapshot()
    features = (
        ColumnFeatureRecord("users", "email", generated=True, identity=False),
        ColumnFeatureRecord("users", "id", generated=False, identity=True),
    )
    codes = _codes(_compare(replace(snapshot, column_features=features)))
    assert "UNEXPECTED_GENERATED_COLUMN" in codes
    assert "UNEXPECTED_IDENTITY_COLUMN" in codes


def test_incorrect_check_constraint_definition_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    checks = tuple(
        replace(check, expression="id = 2")
        if check.name == "ck_mitigation_policy_state_id"
        else check
        for check in snapshot.checks
    )
    assert "CHECK_DEFINITION_MISMATCH" in _codes(
        _compare(replace(snapshot, checks=checks), MODE_AFTER_MIGRATIONS)
    )


def test_incorrect_foreign_key_definition_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    foreign_keys = []
    for item in snapshot.foreign_keys:
        if item.key[1] == ("policy_id",) and item.table_name == "mitigation_policy_state":
            columns, referred_table, referred_columns, ondelete = item.definition
            item = replace(
                item,
                definition=(columns, referred_table, referred_columns, "CASCADE"),
            )
        foreign_keys.append(item)
    assert "FOREIGN_KEY_DEFINITION_MISMATCH" in _codes(
        _compare(
            replace(snapshot, foreign_keys=tuple(foreign_keys)),
            MODE_AFTER_MIGRATIONS,
        )
    )


def test_unexpected_table_and_schema_object_fail():
    snapshot = _snapshot()
    drifted = replace(
        snapshot,
        table_names=snapshot.table_names | {"orphan_table"},
        relation_names=snapshot.relation_names | {"orphan_view"},
    )
    codes = _codes(_compare(drifted))
    assert "UNEXPECTED_TABLE" in codes
    assert "UNEXPECTED_SCHEMA_OBJECT" in codes


def test_unexpected_event_trigger_and_grant_fail():
    snapshot = replace(
        _snapshot(),
        event_triggers=frozenset({"block_ddl"}),
        grants=(
            GrantRecord("users", "PUBLIC", "INSERT", grantable=False),
        ),
    )
    codes = _codes(_compare(snapshot))
    assert "UNEXPECTED_EVENT_TRIGGER" in codes
    assert "UNEXPECTED_GRANT" in codes


def test_revision_mismatch_fails():
    snapshot = replace(_snapshot(MODE_AFTER_MIGRATIONS), revision_rows=("0001_baseline",))
    assert "REVISION_MISMATCH" in _codes(
        _compare(snapshot, MODE_AFTER_MIGRATIONS)
    )


def test_owner_enforcement_is_optional_but_exact_when_requested():
    snapshot = _snapshot()
    assert _compare(snapshot).passed
    assert "TABLE_OWNER_MISMATCH" in _codes(_compare(snapshot, expected_owner="other_owner"))


def test_all_sql_statements_are_read_only():
    forbidden = re.compile(
        r"\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|"
        r"COMMIT|ROLLBACK|SAVEPOINT)\b",
        re.IGNORECASE,
    )
    assert verifier.SQL
    for key, sql in verifier.SQL.items():
        assert sql.lstrip().upper().startswith("SELECT"), key
        assert forbidden.search(sql) is None, key


def test_verifier_source_contains_no_mutation_or_migration_commands():
    source = Path(verifier.__file__).read_text(encoding="utf-8")
    for token in (
        "engine.begin(",
        ".commit()",
        ".rollback()",
        "command.stamp",
        "command.upgrade",
        "command.downgrade",
        "CREATE TABLE",
        "INSERT INTO",
        "DELETE FROM",
    ):
        assert token not in source


def test_inspection_failure_returns_failure_result_and_nonzero_cli(monkeypatch, capsys):
    def _failing_engine_factory():
        raise OSError("postgres://secret-host:secret-password@secret/db")

    result = verifier.verify_exact_structure(
        mode=MODE_CORRECTED_USERS, engine_factory=_failing_engine_factory
    )
    assert not result.passed
    assert "INSPECTION_FAILED" in _codes(result)
    assert "secret-host" not in result.render()

    monkeypatch.setattr(verifier, "verify_exact_structure", lambda *_args, **_kwargs: result)
    assert verifier.main(["--mode", MODE_CORRECTED_USERS]) == 1
    captured = capsys.readouterr()
    assert "EXACT_STRUCTURE_VERIFICATION: FAIL" in captured.out
    assert "secret-password" not in captured.out


def test_read_snapshot_uses_only_the_centralized_read_only_queries():
    executed = []

    class _FakeConnection:
        dialect = type("Dialect", (), {"name": "postgresql"})()

        def execute(self, statement, params=None):
            executed.append(str(statement))
            return self

        def one(self):
            return (
                APPROVED_DATABASE,
                APPROVED_SCHEMA,
                f"PostgreSQL {APPROVED_POSTGRES_VERSION}",
                APPROVED_SERVER_VERSION_NUM,
            )

        def fetchall(self):
            return []

    snapshot = verifier.read_snapshot(_FakeConnection())
    assert snapshot.identity.database == APPROVED_DATABASE
    assert executed
    assert all(item.lstrip().upper().startswith("SELECT") for item in executed)


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_each_mode_accepts_its_own_snapshot(mode):
    result = _compare(_snapshot(mode), mode)
    assert result.mode == mode
    assert result.passed


def test_using_the_wrong_mode_fails_closed():
    pre_correction = _snapshot(MODE_PRE_CORRECTION)
    codes = _codes(_compare(pre_correction, MODE_CORRECTED_USERS))
    assert "MISSING_TABLE" in codes
    assert "MISSING_SEQUENCE" in codes

    after_migrations = _snapshot(MODE_AFTER_MIGRATIONS)
    codes = _codes(_compare(after_migrations, MODE_CORRECTED_USERS))
    assert "UNEXPECTED_TABLE" in codes
    assert "UNEXPECTED_REVISION_STATE" in codes


@pytest.mark.parametrize(
    ("field", "value", "category"),
    (
        ("dialect", "sqlite", "DIALECT_MISMATCH"),
        ("database", "unreviewed_database", "DATABASE_IDENTITY_MISMATCH"),
        ("version_string", "PostgreSQL 16.0 on reviewed-platform", "POSTGRES_VERSION_MISMATCH"),
        ("server_version_num", "160000", "POSTGRES_VERSION_MISMATCH"),
        ("current_schema", "unreviewed_schema", "CURRENT_SCHEMA_MISMATCH"),
    ),
)
def test_wrong_environment_identity_fails(field, value, category):
    snapshot = _snapshot()
    snapshot = replace(snapshot, identity=replace(snapshot.identity, **{field: value}))
    assert category in _codes(_compare(snapshot))


def test_missing_column_fails():
    columns = tuple(
        column
        for column in _snapshot().columns
        if not (column.table_name == "users" and column.name == "email")
    )
    assert "MISSING_COLUMN" in _codes(_compare(replace(_snapshot(), columns=columns)))


def test_unexpected_column_fails():
    columns = _snapshot().columns + (
        ColumnRecord("users", "rogue_column", 9, "integer", True, None),
    )
    assert "UNEXPECTED_COLUMN" in _codes(_compare(replace(_snapshot(), columns=columns)))


def test_primary_key_mismatch_fails():
    primary_keys = dict(_snapshot().primary_keys)
    primary_keys["users"] = ("email",)
    assert "PRIMARY_KEY_MISMATCH" in _codes(
        _compare(replace(_snapshot(), primary_keys=primary_keys))
    )


def test_unexpected_index_fails():
    indexes = _snapshot().indexes + (
        verifier.IndexRecord("users", "ix_rogue", ("email",), False),
    )
    assert "UNEXPECTED_INDEX" in _codes(_compare(replace(_snapshot(), indexes=indexes)))


def test_missing_check_constraint_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    checks = tuple(
        check
        for check in snapshot.checks
        if check.name != "ck_mitigation_policy_state_id"
    )
    assert "MISSING_CHECK_CONSTRAINT" in _codes(
        _compare(replace(snapshot, checks=checks), MODE_AFTER_MIGRATIONS)
    )


def test_unexpected_check_constraint_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    checks = snapshot.checks + (
        verifier.CheckRecord("users", "ck_rogue", "1 = 1"),
    )
    assert "UNEXPECTED_CHECK_CONSTRAINT" in _codes(
        _compare(replace(snapshot, checks=checks), MODE_AFTER_MIGRATIONS)
    )


def test_missing_foreign_key_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    foreign_keys = tuple(
        item
        for item in snapshot.foreign_keys
        if not (
            item.table_name == "mitigation_policy_state"
            and item.key[1] == ("policy_id",)
        )
    )
    assert "MISSING_FOREIGN_KEY" in _codes(
        _compare(replace(snapshot, foreign_keys=foreign_keys), MODE_AFTER_MIGRATIONS)
    )


def test_unexpected_foreign_key_fails():
    snapshot = _snapshot(MODE_AFTER_MIGRATIONS)
    foreign_keys = snapshot.foreign_keys + (
        verifier.ForeignKeyRecord(
            "users",
            ("fk_rogue", ("id",)),
            (("id",), "users", ("id",), "RESTRICT"),
        ),
    )
    assert "UNEXPECTED_FOREIGN_KEY" in _codes(
        _compare(replace(snapshot, foreign_keys=foreign_keys), MODE_AFTER_MIGRATIONS)
    )


def test_missing_sequence_fails():
    sequences = tuple(
        sequence
        for sequence in _snapshot().sequences
        if sequence.name != "users_id_seq"
    )
    assert "MISSING_SEQUENCE" in _codes(
        _compare(replace(_snapshot(), sequences=sequences))
    )


def test_sequence_role_owner_is_enforced_when_requested():
    snapshot = _snapshot()
    sequences = tuple(
        replace(sequence, role_owner="unreviewed_owner")
        if sequence.name == "users_id_seq"
        else sequence
        for sequence in snapshot.sequences
    )
    assert "SEQUENCE_ROLE_OWNER_MISMATCH" in _codes(
        _compare(replace(snapshot, sequences=sequences), expected_owner="reviewed_owner")
    )


def _with_split_owners(snapshot, *, schema_owner, application_owner):
    return replace(
        snapshot,
        schemas={APPROVED_SCHEMA: schema_owner},
        table_owners={
            name: application_owner for name in snapshot.table_owners
        },
        sequences=tuple(
            replace(sequence, role_owner=application_owner)
            for sequence in snapshot.sequences
        ),
    )


def test_cli_engine_creation_path_uses_imported_create_engine(monkeypatch, capsys):
    calls = []

    class _FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class _FakeEngine:
        def __init__(self):
            self.disposed = False
            self.connections = []

        def connect(self):
            connection = _FakeConnection()
            self.connections.append(connection)
            return connection

        def dispose(self):
            self.disposed = True

    engine = _FakeEngine()
    observed = {}

    def _fake_create_engine(url):
        calls.append(url)
        return engine

    def _fake_verify_structure(
        connection, mode, expected_owner=None, expected_schema_owner=None
    ):
        observed.update(
            connection=connection,
            mode=mode,
            expected_owner=expected_owner,
            expected_schema_owner=expected_schema_owner,
        )
        return VerificationResult(
            mode=mode,
            findings=(
                verifier.Finding(
                    verifier.STATUS_PASS,
                    "EXACT_STRUCTURE_MATCH",
                    "schema",
                    "all required structural checks passed",
                ),
            ),
        )

    monkeypatch.setattr(verifier, "create_engine", _fake_create_engine)
    monkeypatch.setattr(verifier, "verify_structure", _fake_verify_structure)

    fake_url = "mock://user:hidden-password@target/db"
    exit_code = verifier.main(
        [
            "--mode",
            MODE_PRE_CORRECTION,
            "--database-url",
            fake_url,
            "--expected-owner",
            "postgres",
            "--expected-schema-owner",
            "pg_database_owner",
        ]
    )

    assert exit_code == 0
    assert calls == [fake_url]
    assert observed["connection"] is engine.connections[0]
    assert observed["mode"] == MODE_PRE_CORRECTION
    assert observed["expected_owner"] == "postgres"
    assert observed["expected_schema_owner"] == "pg_database_owner"
    assert engine.disposed
    captured = capsys.readouterr()
    assert "EXACT_STRUCTURE_VERIFICATION: PASS" in captured.out
    assert "hidden-password" not in captured.out


def test_engine_creation_failure_returns_controlled_non_sensitive_result(monkeypatch):
    fake_url = "mock://user:hidden-password@target/db"

    def _failing_create_engine(_url):
        raise RuntimeError("engine creation failed")

    monkeypatch.setattr(verifier, "create_engine", _failing_create_engine)
    result = verifier.verify_exact_structure(fake_url, mode=MODE_PRE_CORRECTION)

    assert not result.passed
    assert "INSPECTION_FAILED" in _codes(result)
    rendered = result.render()
    assert "RuntimeError" in rendered
    assert "hidden-password" not in rendered
    assert "target/db" not in rendered


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_split_schema_and_application_owners_pass_when_both_are_configured(mode):
    snapshot = _with_split_owners(
        _snapshot(mode),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    result = _compare(
        snapshot,
        mode,
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert result.passed
    assert not _codes(result)


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_expected_owner_only_does_not_imply_schema_owner(mode):
    snapshot = _with_split_owners(
        _snapshot(mode),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    result = _compare(snapshot, mode, expected_owner="postgres")

    assert result.passed
    assert not _codes(result)
    informational = [
        finding
        for finding in result.findings
        if finding.status == verifier.STATUS_INFO
        and finding.category == "SCHEMA_OWNER_ENFORCEMENT_NOT_CONFIGURED"
    ]
    assert len(informational) == 1
    assert APPROVED_SCHEMA in informational[0].object_name
    assert "pg_database_owner" in informational[0].detail
    assert "not configured" in informational[0].detail
    assert not any(
        finding.status == verifier.STATUS_PASS
        and "SCHEMA_OWNER" in finding.category
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_explicit_incorrect_schema_owner_fails_in_all_modes(mode):
    snapshot = _with_split_owners(
        _snapshot(mode),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    result = _compare(
        snapshot,
        mode,
        expected_owner="postgres",
        expected_schema_owner="postgres",
    )

    assert "SCHEMA_OWNER_MISMATCH" in _codes(result)


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_incorrect_table_owner_fails_in_all_modes(mode):
    snapshot = _with_split_owners(
        _snapshot(mode),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    table_owners = dict(snapshot.table_owners)
    table_owners[next(iter(table_owners))] = "unreviewed_table_owner"
    result = _compare(
        replace(snapshot, table_owners=table_owners),
        mode,
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert "TABLE_OWNER_MISMATCH" in _codes(result)


@pytest.mark.parametrize(
    "mode", (MODE_PRE_CORRECTION, MODE_CORRECTED_USERS, MODE_AFTER_MIGRATIONS)
)
def test_incorrect_sequence_owner_fails_in_all_modes(mode):
    snapshot = _with_split_owners(
        _snapshot(mode),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    sequences = tuple(
        replace(sequence, role_owner="unreviewed_sequence_owner")
        if sequence is snapshot.sequences[0]
        else sequence
        for sequence in snapshot.sequences
    )
    result = _compare(
        replace(snapshot, sequences=sequences),
        mode,
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert "SEQUENCE_ROLE_OWNER_MISMATCH" in _codes(result)


def test_missing_table_owner_metadata_fails_closed_when_required():
    snapshot = _with_split_owners(
        _snapshot(),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    table_owners = dict(snapshot.table_owners)
    table_owners[next(iter(table_owners))] = None
    result = _compare(
        replace(snapshot, table_owners=table_owners),
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert "OWNER_INFORMATION_UNAVAILABLE" in _codes(result)


def test_missing_sequence_owner_metadata_fails_closed_when_required():
    snapshot = _with_split_owners(
        _snapshot(),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    first = snapshot.sequences[0]
    sequences = tuple(
        replace(sequence, role_owner=None) if sequence is first else sequence
        for sequence in snapshot.sequences
    )
    result = _compare(
        replace(snapshot, sequences=sequences),
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert "SEQUENCE_ROLE_OWNER_INFORMATION_UNAVAILABLE" in _codes(result)


def test_missing_schema_owner_metadata_fails_closed_when_required():
    snapshot = _with_split_owners(
        _snapshot(),
        schema_owner="pg_database_owner",
        application_owner="postgres",
    )
    result = _compare(
        replace(snapshot, schemas={APPROVED_SCHEMA: None}),
        expected_owner="postgres",
        expected_schema_owner="pg_database_owner",
    )

    assert "SCHEMA_OWNER_INFORMATION_UNAVAILABLE" in _codes(result)
