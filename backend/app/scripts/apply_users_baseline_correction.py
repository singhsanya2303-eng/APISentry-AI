"""Guarded one-off users-only baseline correction artifact.

This is a reviewed, single-use artifact for an existing unversioned APISentry
database that contains ``api_traffic_logs`` but is missing ``users``. It is
deliberately not an Alembic migration: it does not stamp, upgrade, or downgrade,
and it never creates mitigation tables.

Safety contract:
- importing this module has no side effects and performs no I/O;
- no database is contacted unless ``main()`` is explicitly invoked with both
  confirmation arguments;
- the only schema objects it can create are ``users``, its five indexes, and the
  implicit ``users_id_seq`` produced by the SERIAL primary key;
- preflight requires the exact public sequence inventory
  ``{api_traffic_logs_id_seq}`` and refuses unexpected sequence ownership;
- preflight refuses user-defined traffic triggers, non-internal traffic rules,
  event triggers, and generated or identity traffic columns;
- DDL runs under a transaction-local ``SET LOCAL search_path TO public``;
- ``api_traffic_logs`` is read-only throughout;
- there is no force/bypass flag;
- every failure leaves the database unchanged via transaction rollback.

Future, separately authorized usage::

    python -m app.scripts.apply_users_baseline_correction \
        --confirm-database apisentry_db \
        --confirm-operation users-only-baseline-correction
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import FrozenSet, List, Optional, Sequence, Tuple

from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateIndex, CreateTable

APPROVED_DATABASE = "apisentry_db"
APPROVED_POSTGRES_VERSION = "17.10"
APPROVED_SERVER_VERSION_NUM = "170010"
APPROVED_SCHEMA = "public"
CONFIRM_OPERATION = "users-only-baseline-correction"

TRAFFIC_TABLE = "api_traffic_logs"
USERS_TABLE = "users"
VERSION_TABLE = "alembic_version"
TRAFFIC_SEQUENCE = "api_traffic_logs_id_seq"
USERS_SEQUENCE = "users_id_seq"
EXPECTED_SEQUENCES = frozenset({TRAFFIC_SEQUENCE})
EXPECTED_SEQUENCE_OWNERSHIP = frozenset(
    {(TRAFFIC_SEQUENCE, TRAFFIC_TABLE, "id")}
)
SET_TRANSACTION_SEARCH_PATH = "SET LOCAL search_path TO public"
MITIGATION_TABLES = frozenset(
    {
        "mitigation_policies",
        "mitigation_policy_state",
        "mitigation_policy_activation_events",
        "mitigation_decisions",
        "mitigation_audit_events",
    }
)

EXPECTED_USERS_INDEXES = frozenset(
    {
        ("ix_users_email", ("email",), True),
        ("ix_users_id", ("id",), False),
        ("ix_users_is_active", ("is_active",), False),
        ("ix_users_role", ("role",), False),
        ("ix_users_username", ("username",), True),
    }
)

# Explicitly approved Phase 5N baseline. Timestamps are normalized to UTC before
# comparison so a session-timezone difference cannot cause a false mismatch.
APPROVED_FINGERPRINT_ROWS = 18966
APPROVED_FINGERPRINT_REQUEST_IDS = 18729
APPROVED_FINGERPRINT_CLIENTS = 32
APPROVED_FINGERPRINT_MIN = "2026-09-21 11:54:06.388002+05:30"
APPROVED_FINGERPRINT_MAX = "2026-11-20 08:20:59.386339+05:30"
APPROVED_FINGERPRINT_STATUS: Tuple[Tuple[int, int], ...] = (
    (200, 12858),
    (400, 288),
    (401, 994),
    (404, 200),
    (422, 4183),
    (500, 436),
    (503, 7),
)
APPROVED_FINGERPRINT_METHODS: Tuple[Tuple[str, int], ...] = (
    ("GET", 16944),
    ("OPTIONS", 452),
    ("POST", 1570),
)


class CorrectionRefused(RuntimeError):
    """Raised when preflight or confirmation refuses the correction."""


class CorrectionPostCheckFailed(RuntimeError):
    """Raised when post-checks fail; the transaction must be rolled back."""


@dataclass(frozen=True)
class DatabaseIdentity:
    database: str
    version_string: str
    server_version_num: str
    current_schema: str


@dataclass(frozen=True)
class TrafficFingerprint:
    rows: int
    distinct_request_ids: int
    distinct_clients: int
    min_timestamp: str
    max_timestamp: str
    status_counts: Tuple[Tuple[int, int], ...]
    method_counts: Tuple[Tuple[str, int], ...]


@dataclass(frozen=True)
class TableSchema:
    columns: FrozenSet[Tuple[str, str, bool]]
    primary_key: FrozenSet[str]
    indexes: FrozenSet[Tuple[str, Tuple[str, ...], bool]]
    sequences: FrozenSet[str]
    id_default: str


@dataclass(frozen=True)
class TrafficSafety:
    """Read-only, exact inventory of objects that could affect the correction."""

    sequence_names: FrozenSet[str]
    sequence_associations: FrozenSet[Tuple[str, str, str]]
    user_triggers: FrozenSet[str]
    non_internal_rules: FrozenSet[str]
    event_triggers: FrozenSet[str]
    generated_columns: FrozenSet[str]
    identity_columns: FrozenSet[str]


@dataclass(frozen=True)
class PreflightSnapshot:
    identity: DatabaseIdentity
    tables: FrozenSet[str]
    traffic: Optional[TableSchema]
    fingerprint: Optional[TrafficFingerprint]
    traffic_safety: Optional[TrafficSafety] = None


@dataclass(frozen=True)
class UsersPostState:
    columns: FrozenSet[Tuple[str, str, bool]]
    primary_key: FrozenSet[str]
    indexes: FrozenSet[Tuple[str, Tuple[str, ...], bool]]
    check_constraints: Tuple[str, ...]
    foreign_keys: Tuple[str, ...]
    unique_constraints: Tuple[Tuple[str, ...], ...]
    triggers: Tuple[str, ...]
    sequences: FrozenSet[str]
    id_default: str
    sequence_owned: bool
    row_count: int


@dataclass(frozen=True)
class CorrectionResult:
    tables_created: Tuple[str, ...]
    indexes_created: Tuple[str, ...]
    traffic_rows: int


def _normalize_type(rendered: object) -> str:
    """Map model and PostgreSQL type renderings to a canonical family string."""
    value = " ".join(str(rendered).strip().lower().replace('"', "").split())

    # SQLAlchemy type objects stringify to their family name only, discarding the
    # timezone flag: both TIMESTAMP(timezone=True) and TIMESTAMP(timezone=False)
    # render as "TIMESTAMP", and DateTime(timezone=True) renders as "DATETIME".
    # psycopg v3 reflection therefore yields "TIMESTAMP" for a PostgreSQL
    # timestamptz column, so read the flag from the object itself to classify it
    # identically to the timezone-aware DateTime columns in the SQLAlchemy models.
    if value in {"timestamp", "datetime"} and hasattr(rendered, "timezone"):
        return "timestamptz" if rendered.timezone else "timestamp"

    if value.startswith("character varying"):
        value = "varchar" + value[len("character varying") :]
    elif value in {"timestamp with time zone", "timestamptz"}:
        value = "timestamptz"
    elif value == "timestamp without time zone":
        value = "timestamp"
    elif value == "datetime":
        value = "timestamptz"
    elif value in {"double precision", "float"}:
        value = "double_precision"
    return value


def _canonical_timestamp(value: str) -> str:
    """Normalize a timestamptz rendering to a comparable UTC ISO string."""
    parsed = datetime.fromisoformat(str(value).strip())
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _expected_table_schema(table: object) -> TableSchema:
    """Derive the expected schema from SQLAlchemy metadata, never from literals."""
    return TableSchema(
        columns=frozenset(
            (column.name, _normalize_type(str(column.type)), bool(column.nullable))
            for column in table.columns  # type: ignore[attr-defined]
        ),
        primary_key=frozenset(
            column.name
            for column in table.primary_key.columns  # type: ignore[attr-defined]
        ),
        indexes=frozenset(
            (
                index.name,
                tuple(column.name for column in index.columns),
                bool(index.unique),
            )
            for index in table.indexes  # type: ignore[attr-defined]
        ),
        sequences=frozenset(),
        id_default="",
    )


def approved_fingerprint() -> TrafficFingerprint:
    """Return the explicitly approved Phase 5N traffic fingerprint."""
    return TrafficFingerprint(
        rows=APPROVED_FINGERPRINT_ROWS,
        distinct_request_ids=APPROVED_FINGERPRINT_REQUEST_IDS,
        distinct_clients=APPROVED_FINGERPRINT_CLIENTS,
        min_timestamp=APPROVED_FINGERPRINT_MIN,
        max_timestamp=APPROVED_FINGERPRINT_MAX,
        status_counts=APPROVED_FINGERPRINT_STATUS,
        method_counts=APPROVED_FINGERPRINT_METHODS,
    )


def fingerprints_equal(left: TrafficFingerprint, right: TrafficFingerprint) -> bool:
    """Compare fingerprints using UTC-normalized timestamp bounds."""
    return (
        left.rows == right.rows
        and left.distinct_request_ids == right.distinct_request_ids
        and left.distinct_clients == right.distinct_clients
        and _canonical_timestamp(left.min_timestamp)
        == _canonical_timestamp(right.min_timestamp)
        and _canonical_timestamp(left.max_timestamp)
        == _canonical_timestamp(right.max_timestamp)
        and tuple(left.status_counts) == tuple(right.status_counts)
        and tuple(left.method_counts) == tuple(right.method_counts)
    )


def validate_confirmation(
    database: Optional[str], operation: Optional[str]
) -> Tuple[str, ...]:
    """Require explicit confirmation of the approved target and operation."""
    errors: List[str] = []
    if not database:
        errors.append("CONFIRM_DATABASE_REQUIRED")
    elif database != APPROVED_DATABASE:
        errors.append("CONFIRM_DATABASE_MISMATCH")
    if not operation:
        errors.append("CONFIRM_OPERATION_REQUIRED")
    elif operation != CONFIRM_OPERATION:
        errors.append("CONFIRM_OPERATION_MISMATCH")
    return tuple(errors)


def read_identity(connection: object) -> DatabaseIdentity:
    """Read database identity with a single read-only query."""
    row = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT current_database(), current_schema(), version(), "
            "current_setting('server_version_num')"
        )
    ).one()
    return DatabaseIdentity(
        database=str(row[0]),
        current_schema=str(row[1]),
        version_string=str(row[2]),
        server_version_num=str(row[3]),
    )


def read_existing_objects(connection: object) -> FrozenSet[str]:
    """Read non-system table names from the approved schema and search path.

    Preflight confirms that ``current_schema()`` is ``public``. Checking both the
    explicit schema and the effective search path is conservative: a pre-existing
    ``users`` table must cause a refusal, never silent adoption.
    """
    inspector = inspect(connection)  # type: ignore[arg-type]
    return frozenset(inspector.get_table_names(schema=APPROVED_SCHEMA)) | frozenset(
        inspector.get_table_names()
    )


def read_sequence_names(connection: object) -> FrozenSet[str]:
    """Read sequence names from the approved schema without exposing values."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT sequence_name FROM information_schema.sequences "
            "WHERE sequence_schema = 'public'"
        )
    ).fetchall()
    return frozenset(str(row[0]) for row in rows)


def read_sequence_inventory(
    connection: object,
) -> Tuple[FrozenSet[str], FrozenSet[Tuple[str, str, str]]]:
    """Return exact public sequence names and their table/column associations."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT seq.relname, dep_table.relname, dep_attribute.attname "
            "FROM pg_class seq "
            "JOIN pg_namespace ns ON ns.oid = seq.relnamespace "
            "LEFT JOIN pg_depend dep ON dep.objid = seq.oid "
            "AND dep.classid = 'pg_class'::regclass "
            "AND dep.refclassid = 'pg_class'::regclass "
            "AND dep.refobjsubid > 0 "
            "AND dep.deptype IN ('a', 'i') "
            "LEFT JOIN pg_class dep_table ON dep_table.oid = dep.refobjid "
            "LEFT JOIN pg_attribute dep_attribute "
            "ON dep_attribute.attrelid = dep.refobjid "
            "AND dep_attribute.attnum = dep.refobjsubid "
            "WHERE ns.nspname = 'public' AND seq.relkind = 'S'"
        )
    ).fetchall()
    names = frozenset(str(row[0]) for row in rows)
    associations = frozenset(
        (str(row[0]), str(row[1]), str(row[2]))
        for row in rows
        if row[1] is not None and row[2] is not None
    )
    return names, associations


def read_traffic_user_triggers(connection: object) -> FrozenSet[str]:
    """Return non-internal triggers attached to the protected traffic table."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT trg.tgname FROM pg_trigger trg "
            "JOIN pg_class tbl ON tbl.oid = trg.tgrelid "
            "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
            "WHERE ns.nspname = 'public' AND tbl.relname = :table_name "
            "AND NOT trg.tgisinternal"
        ),
        {"table_name": TRAFFIC_TABLE},
    ).fetchall()
    return frozenset(str(row[0]) for row in rows)


def read_traffic_non_internal_rules(connection: object) -> FrozenSet[str]:
    """Return non-internal rewrite rules attached to the traffic table."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT rewrite.rulename FROM pg_rewrite rewrite "
            "JOIN pg_class tbl ON tbl.oid = rewrite.ev_class "
            "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
            "WHERE ns.nspname = 'public' AND tbl.relname = :table_name "
            "AND rewrite.rulename <> '_RETURN'"
        ),
        {"table_name": TRAFFIC_TABLE},
    ).fetchall()
    return frozenset(str(row[0]) for row in rows)


def read_event_triggers(connection: object) -> FrozenSet[str]:
    """Return all database event triggers; any event trigger blocks this DDL."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text("SELECT evtname FROM pg_event_trigger")
    ).fetchall()
    return frozenset(str(row[0]) for row in rows)


def read_traffic_column_features(
    connection: object,
) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    """Return generated and identity columns on the protected traffic table."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT attr.attname, attr.attgenerated, attr.attidentity "
            "FROM pg_attribute attr "
            "JOIN pg_class tbl ON tbl.oid = attr.attrelid "
            "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
            "WHERE ns.nspname = 'public' AND tbl.relname = :table_name "
            "AND attr.attnum > 0 AND NOT attr.attisdropped"
        ),
        {"table_name": TRAFFIC_TABLE},
    ).fetchall()
    generated = frozenset(
        str(row[0]) for row in rows if row[1] is not None and str(row[1]) not in ("", None)
    )
    identity = frozenset(
        str(row[0]) for row in rows if row[2] is not None and str(row[2]) not in ("", None)
    )
    return generated, identity


def read_traffic_safety(connection: object) -> TrafficSafety:
    """Gather exact sequence, trigger, rule, and column-feature facts read-only."""
    sequence_names, sequence_associations = read_sequence_inventory(connection)
    generated_columns, identity_columns = read_traffic_column_features(connection)
    return TrafficSafety(
        sequence_names=sequence_names,
        sequence_associations=sequence_associations,
        user_triggers=read_traffic_user_triggers(connection),
        non_internal_rules=read_traffic_non_internal_rules(connection),
        event_triggers=read_event_triggers(connection),
        generated_columns=generated_columns,
        identity_columns=identity_columns,
    )


def read_table_schema(connection: object, table_name: str) -> TableSchema:
    """Inspect one table read-only and return a sanitized schema description."""
    inspector = inspect(connection)  # type: ignore[arg-type]
    columns = inspector.get_columns(table_name, schema=APPROVED_SCHEMA)
    primary_key = inspector.get_pk_constraint(table_name, schema=APPROVED_SCHEMA)
    indexes = inspector.get_indexes(table_name, schema=APPROVED_SCHEMA)
    id_default = ""
    for column in columns:
        if column["name"] == "id":
            id_default = str(column.get("default") or "")
            break
    return TableSchema(
        columns=frozenset(
            (str(item["name"]), _normalize_type(item["type"]), bool(item["nullable"]))
            for item in columns
        ),
        primary_key=frozenset(
            str(name)
            for name in primary_key.get("constrained_columns", [])
        ),
        indexes=frozenset(
            (
                str(item["name"]),
                tuple(str(name) for name in item.get("column_names", []) if name),
                bool(item.get("unique")),
            )
            for item in indexes
        ),
        sequences=read_sequence_names(connection),
        id_default=id_default,
    )


def read_traffic_fingerprint(connection: object) -> TrafficFingerprint:
    """Capture only aggregate traffic statistics; never read individual rows."""
    rows = connection.execute(  # type: ignore[attr-defined]
        text(f"SELECT count(*) FROM {APPROVED_SCHEMA}.{TRAFFIC_TABLE}")
    ).scalar_one()
    request_ids = connection.execute(  # type: ignore[attr-defined]
        text(
            f"SELECT count(DISTINCT request_id) FROM "
            f"{APPROVED_SCHEMA}.{TRAFFIC_TABLE}"
        )
    ).scalar_one()
    clients = connection.execute(  # type: ignore[attr-defined]
        text(f"SELECT count(DISTINCT client_ip) FROM {APPROVED_SCHEMA}.{TRAFFIC_TABLE}")
    ).scalar_one()
    bounds = connection.execute(  # type: ignore[attr-defined]
        text(
            f"SELECT min(timestamp)::text, max(timestamp)::text "
            f"FROM {APPROVED_SCHEMA}.{TRAFFIC_TABLE}"
        )
    ).one()
    status_rows = connection.execute(  # type: ignore[attr-defined]
        text(
            f"SELECT status_code, count(*) FROM {APPROVED_SCHEMA}.{TRAFFIC_TABLE} "
            "GROUP BY status_code ORDER BY status_code"
        )
    ).fetchall()
    method_rows = connection.execute(  # type: ignore[attr-defined]
        text(
            f"SELECT method, count(*) FROM {APPROVED_SCHEMA}.{TRAFFIC_TABLE} "
            "GROUP BY method ORDER BY method"
        )
    ).fetchall()
    return TrafficFingerprint(
        rows=int(rows),
        distinct_request_ids=int(request_ids),
        distinct_clients=int(clients),
        min_timestamp=str(bounds[0]),
        max_timestamp=str(bounds[1]),
        status_counts=tuple((int(key), int(value)) for key, value in status_rows),
        method_counts=tuple((str(key), int(value)) for key, value in method_rows),
    )


def gather_snapshot(connection: object) -> PreflightSnapshot:
    """Gather every read-only fact needed by preflight validation."""
    tables = read_existing_objects(connection)
    traffic: Optional[TableSchema] = None
    fingerprint: Optional[TrafficFingerprint] = None
    traffic_safety = read_traffic_safety(connection)
    if TRAFFIC_TABLE in tables:
        traffic = read_table_schema(connection, TRAFFIC_TABLE)
        fingerprint = read_traffic_fingerprint(connection)
    return PreflightSnapshot(
        identity=read_identity(connection),
        tables=tables,
        traffic=traffic,
        fingerprint=fingerprint,
        traffic_safety=traffic_safety,
    )


def validate_preflight(snapshot: PreflightSnapshot) -> Tuple[str, ...]:
    """Return every reason the correction must be refused (empty means ready)."""
    from app.models.traffic import APITrafficLog

    errors: List[str] = []
    identity = snapshot.identity
    if identity.database != APPROVED_DATABASE:
        errors.append("DATABASE_IDENTITY_MISMATCH")
    version_match = re.match(r"^PostgreSQL\s+(\d+\.\d+)", identity.version_string)
    if (
        not version_match
        or version_match.group(1) != APPROVED_POSTGRES_VERSION
        or identity.server_version_num != APPROVED_SERVER_VERSION_NUM
    ):
        errors.append("UNSUPPORTED_POSTGRES_VERSION")
    if identity.current_schema != APPROVED_SCHEMA:
        errors.append("UNEXPECTED_SCHEMA")
    if USERS_TABLE in snapshot.tables:
        errors.append("USERS_TABLE_ALREADY_EXISTS")
    if VERSION_TABLE in snapshot.tables:
        errors.append("ALEMBIC_VERSION_TABLE_EXISTS")
    if (snapshot.tables & MITIGATION_TABLES) or any(
        name.startswith("mitigation_") for name in snapshot.tables
    ):
        errors.append("MITIGATION_TABLE_EXISTS")

    safety = snapshot.traffic_safety
    if safety is None:
        errors.append("SEQUENCE_INVENTORY_UNAVAILABLE")
    else:
        if safety.sequence_names != EXPECTED_SEQUENCES:
            if USERS_SEQUENCE in safety.sequence_names:
                errors.append("USERS_SEQUENCE_ALREADY_EXISTS")
            if TRAFFIC_SEQUENCE not in safety.sequence_names:
                errors.append("TRAFFIC_SEQUENCE_MISSING")
            if safety.sequence_names - EXPECTED_SEQUENCES:
                errors.append("UNEXPECTED_SEQUENCE")
        if safety.sequence_associations != EXPECTED_SEQUENCE_OWNERSHIP:
            errors.append("UNEXPECTED_SEQUENCE_ASSOCIATION")
        if safety.user_triggers:
            errors.append("UNEXPECTED_TRAFFIC_TRIGGER")
        if safety.non_internal_rules:
            errors.append("UNEXPECTED_TRAFFIC_RULE")
        if safety.event_triggers:
            errors.append("UNEXPECTED_EVENT_TRIGGER")
        if safety.generated_columns:
            errors.append("UNEXPECTED_GENERATED_COLUMN")
        if safety.identity_columns:
            errors.append("UNEXPECTED_IDENTITY_COLUMN")

    if TRAFFIC_TABLE not in snapshot.tables:
        errors.append("TRAFFIC_TABLE_MISSING")
    else:
        expected = _expected_table_schema(APITrafficLog.__table__)
        traffic = snapshot.traffic
        if traffic is None or traffic.columns != expected.columns:
            errors.append("TRAFFIC_SCHEMA_MISMATCH")
        else:
            if traffic.primary_key != expected.primary_key:
                errors.append("TRAFFIC_PRIMARY_KEY_MISMATCH")
            if traffic.indexes != expected.indexes:
                errors.append("TRAFFIC_INDEX_MISMATCH")
            if TRAFFIC_SEQUENCE not in traffic.sequences:
                errors.append("TRAFFIC_SEQUENCE_MISMATCH")
            if TRAFFIC_SEQUENCE not in traffic.id_default:
                errors.append("TRAFFIC_ID_DEFAULT_MISMATCH")
        if snapshot.fingerprint is None:
            errors.append("TRAFFIC_FINGERPRINT_UNAVAILABLE")
        elif not fingerprints_equal(snapshot.fingerprint, approved_fingerprint()):
            errors.append("TRAFFIC_FINGERPRINT_MISMATCH")
    return tuple(errors)


def build_users_ddl() -> Tuple[object, ...]:
    """Generate users-only DDL from ``User.__table__`` metadata.

    The unqualified table name is intentional: preflight requires
    ``current_schema() = public``. It also preserves the exact index names from
    the reviewed baseline migration.
    """
    from app.models.user import User

    table = User.__table__
    if table.name != USERS_TABLE:
        raise CorrectionRefused("UNEXPECTED_USERS_TABLE_NAME")
    index_names = frozenset(index.name for index in table.indexes)
    if index_names != frozenset(item[0] for item in EXPECTED_USERS_INDEXES):
        raise CorrectionRefused("UNEXPECTED_USERS_INDEXES")
    statements: List[object] = [CreateTable(table)]
    statements.extend(
        CreateIndex(index) for index in sorted(table.indexes, key=lambda item: item.name)
    )
    return tuple(statements)


def read_sequence_ownership(
    connection: object,
    sequence_name: str = USERS_SEQUENCE,
    table_name: str = USERS_TABLE,
) -> bool:
    """Confirm a sequence is owned by the named public table (PostgreSQL only)."""
    row = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT 1 FROM pg_depend d "
            "JOIN pg_class seq ON seq.oid = d.objid "
            "JOIN pg_class tbl ON tbl.oid = d.refobjid "
            "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
            "WHERE ns.nspname = 'public' AND tbl.relname = :table_name "
            "AND seq.relname = :sequence_name AND d.refobjsubid > 0 "
            "AND d.deptype IN ('a', 'i', 'n') LIMIT 1"
        ),
        {"table_name": table_name, "sequence_name": sequence_name},
    ).first()
    return row is not None


def read_users_post_state(connection: object) -> UsersPostState:
    """Inspect the freshly created users table read-only for post-checks."""
    inspector = inspect(connection)  # type: ignore[arg-type]
    columns = inspector.get_columns(USERS_TABLE, schema=APPROVED_SCHEMA)
    primary_key = inspector.get_pk_constraint(USERS_TABLE, schema=APPROVED_SCHEMA)
    indexes = inspector.get_indexes(USERS_TABLE, schema=APPROVED_SCHEMA)
    checks = inspector.get_check_constraints(USERS_TABLE, schema=APPROVED_SCHEMA)
    foreign_keys = inspector.get_foreign_keys(USERS_TABLE, schema=APPROVED_SCHEMA)
    unique_constraints = inspector.get_unique_constraints(
        USERS_TABLE, schema=APPROVED_SCHEMA
    )
    trigger_rows = connection.execute(  # type: ignore[attr-defined]
        text(
            "SELECT trigger_name FROM information_schema.triggers "
            "WHERE event_object_schema = 'public' AND event_object_table = 'users'"
        )
    ).fetchall()
    id_default = ""
    for column in columns:
        if column["name"] == "id":
            id_default = str(column.get("default") or "")
            break
    row_count = connection.execute(  # type: ignore[attr-defined]
        text("SELECT count(*) FROM public.users")
    ).scalar_one()
    return UsersPostState(
        columns=frozenset(
            (str(item["name"]), _normalize_type(item["type"]), bool(item["nullable"]))
            for item in columns
        ),
        primary_key=frozenset(
            str(name)
            for name in primary_key.get("constrained_columns", [])
        ),
        indexes=frozenset(
            (
                str(item["name"]),
                tuple(str(name) for name in item.get("column_names", []) if name),
                bool(item.get("unique")),
            )
            for item in indexes
        ),
        check_constraints=tuple(str(item["name"]) for item in checks),
        foreign_keys=tuple(str(item["name"]) for item in foreign_keys),
        unique_constraints=tuple(
            tuple(str(name) for name in item.get("column_names", []) if name)
            for item in unique_constraints
        ),
        triggers=tuple(str(row[0]) for row in trigger_rows),
        sequences=read_sequence_names(connection),
        id_default=id_default,
        sequence_owned=read_sequence_ownership(connection),
        row_count=int(row_count),
    )


def validate_users_post_state(state: UsersPostState) -> Tuple[str, ...]:
    """Validate the users table against current User metadata."""
    from app.models.user import User

    errors: List[str] = []
    expected = _expected_table_schema(User.__table__)
    if state.columns != expected.columns:
        errors.append("USERS_COLUMNS_MISMATCH")
    if state.primary_key != expected.primary_key:
        errors.append("USERS_PRIMARY_KEY_MISMATCH")
    if state.indexes != EXPECTED_USERS_INDEXES:
        errors.append("USERS_INDEXES_MISMATCH")
    if state.check_constraints or state.foreign_keys or state.unique_constraints:
        errors.append("UNEXPECTED_USERS_CONSTRAINT")
    if state.triggers:
        errors.append("UNEXPECTED_USERS_TRIGGER")
    if USERS_SEQUENCE not in state.sequences:
        errors.append("USERS_SEQUENCE_MISSING")
    if USERS_SEQUENCE not in state.id_default:
        errors.append("USERS_ID_DEFAULT_MISMATCH")
    if not state.sequence_owned:
        errors.append("USERS_SEQUENCE_OWNERSHIP_MISMATCH")
    if state.row_count != 0:
        errors.append("UNEXPECTED_USER_RECORDS")
    return tuple(errors)


def validate_traffic_post_state(
    connection: object, before: PreflightSnapshot
) -> Tuple[str, ...]:
    """Confirm the traffic table schema and fingerprint did not change."""
    errors: List[str] = []
    current = read_table_schema(connection, TRAFFIC_TABLE)
    if before.traffic is None:
        errors.append("TRAFFIC_SCHEMA_CHANGED")
    else:
        # TableSchema.sequences is the whole public schema's sequence set, so the
        # expected users_id_seq creation is not a traffic change. Compare the
        # protected traffic structure independently, then validate the exact
        # sequence delta rather than ignoring sequence changes wholesale.
        if (
            current.columns != before.traffic.columns
            or current.primary_key != before.traffic.primary_key
            or current.indexes != before.traffic.indexes
            or current.id_default != before.traffic.id_default
        ):
            errors.append("TRAFFIC_SCHEMA_CHANGED")
        expected_sequences = before.traffic.sequences | frozenset({USERS_SEQUENCE})
        if current.sequences != expected_sequences:
            errors.append("UNEXPECTED_SEQUENCE_CHANGE")
        if TRAFFIC_SEQUENCE not in current.sequences:
            errors.append("TRAFFIC_SEQUENCE_MISSING")
        if not read_sequence_ownership(
            connection, sequence_name=TRAFFIC_SEQUENCE, table_name=TRAFFIC_TABLE
        ):
            errors.append("TRAFFIC_SEQUENCE_OWNERSHIP_MISMATCH")
    current_fingerprint = read_traffic_fingerprint(connection)
    if before.fingerprint is None or not fingerprints_equal(
        current_fingerprint, before.fingerprint
    ):
        errors.append("TRAFFIC_FINGERPRINT_CHANGED")
    return tuple(errors)


def set_transaction_search_path(connection: object) -> None:
    """Pin the correction transaction to the already-confirmed public schema."""
    dialect_name = getattr(getattr(connection, "dialect", None), "name", "")
    if dialect_name == "postgresql":
        connection.execute(text(SET_TRANSACTION_SEARCH_PATH))  # type: ignore[attr-defined]


def apply_users_correction(
    engine: object, snapshot: Optional[PreflightSnapshot] = None
) -> CorrectionResult:
    """Apply the users-only correction in one transaction, or roll back.

    The caller must have validated explicit confirmation first. This function
    re-validates all preflight conditions inside the transaction and refuses
    immediately if ``users`` appeared between the outer and inner checks.
    """
    connectable = engine.connect()  # type: ignore[attr-defined]
    try:
        baseline = snapshot or gather_snapshot(connectable)
    finally:
        connectable.close()
    errors = validate_preflight(baseline)
    if errors:
        raise CorrectionRefused("PREFLIGHT: " + ", ".join(errors))

    with engine.begin() as connection:  # type: ignore[attr-defined]
        inner_tables = read_existing_objects(connection)
        if USERS_TABLE in inner_tables:
            raise CorrectionRefused("USERS_TABLE_ALREADY_EXISTS")
        inner_errors = validate_preflight(gather_snapshot(connection))
        if inner_errors:
            raise CorrectionRefused("INNER_PREFLIGHT: " + ", ".join(inner_errors))
        set_transaction_search_path(connection)
        for statement in build_users_ddl():
            connection.execute(statement)  # type: ignore[attr-defined]
        post_errors = validate_users_post_state(read_users_post_state(connection))
        if post_errors:
            raise CorrectionPostCheckFailed("POST_CHECK: " + ", ".join(post_errors))
        traffic_errors = validate_traffic_post_state(connection, baseline)
        if traffic_errors:
            raise CorrectionPostCheckFailed(
                "TRAFFIC_POST_CHECK: " + ", ".join(traffic_errors)
            )
        traffic_rows = baseline.fingerprint.rows if baseline.fingerprint else 0
    return CorrectionResult(
        tables_created=(USERS_TABLE,),
        indexes_created=tuple(sorted(item[0] for item in EXPECTED_USERS_INDEXES)),
        traffic_rows=traffic_rows,
    )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    engine_factory: Optional[object] = None,
    database_url: Optional[str] = None,
) -> int:
    """CLI entry point; no database is contacted without exact confirmation."""
    parser = argparse.ArgumentParser(
        description=(
            "One-off users-only baseline correction. Requires explicit "
            "confirmation of the approved database and operation."
        )
    )
    parser.add_argument("--confirm-database", dest="confirm_database")
    parser.add_argument("--confirm-operation", dest="confirm_operation")
    args = parser.parse_args(argv)

    confirmation_errors = validate_confirmation(
        args.confirm_database, args.confirm_operation
    )
    if confirmation_errors:
        print("REFUSED: " + ", ".join(confirmation_errors))
        return 2

    engine = None
    try:
        if engine_factory is not None:
            engine = engine_factory()
        else:
            # Imports are intentionally local so module import remains side-effect
            # free. Callers that inject a factory never cause configuration reads.
            from sqlalchemy import create_engine
            from sqlalchemy.pool import NullPool

            from app.core.config import settings

            target_url = database_url or settings.get_database_url()
            engine = create_engine(target_url, poolclass=NullPool)

        with engine.connect() as connection:  # type: ignore[attr-defined]
            snapshot = gather_snapshot(connection)
        preflight_errors = validate_preflight(snapshot)
        if preflight_errors:
            print("REFUSED: " + ", ".join(preflight_errors))
            return 1
        result = apply_users_correction(engine, snapshot=snapshot)
    except CorrectionRefused as exc:
        print("REFUSED: " + str(exc))
        return 1
    except CorrectionPostCheckFailed as exc:
        print("FAILED: " + str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001 - never emit DSNs or raw diagnostics
        print(
            f"FAILED: {type(exc).__name__}; operation aborted without connection details"
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()  # type: ignore[attr-defined]

    print("USERS_BASELINE_CORRECTION: PASS")
    print(
        "objects_created=users,users_id_seq,"
        + ",".join(result.indexes_created)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
