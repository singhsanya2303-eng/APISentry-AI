"""Read-only exact structural verification for reviewed APISentry schemas.

This verifier never changes schema or data, never stamps a revision, and never
repairs drift. It inspects a PostgreSQL target through catalog queries only and
compares the result with structure derived from the SQLAlchemy models and the
Alembic revision files. It prints object names and reason codes only; database
URLs, credentials, traffic records, and identity data are never emitted.

Three explicit modes are supported:

* ``pre-correction`` -- the original unversioned traffic-only baseline;
* ``corrected-users`` -- traffic plus the guarded users correction result;
* ``after-migrations`` -- the reviewed head-revision schema, including
  ``alembic_version``.

Expected database identity and schema name are reused from the already reviewed
users correction artifact rather than duplicated as new literals. Expected
columns, types, lengths, defaults, indexes, constraints, and sequence ownership
are derived from model metadata. The final revision is derived by loading the
actual files in ``alembic/versions`` and finding the sole head.

Ownership expectations are intentionally split. ``--expected-owner`` applies to
application tables and sequences. ``--expected-schema-owner`` applies only to the
schema and is enforced only when supplied. When it is omitted, the observed
schema owner is reported as informational and schema-owner enforcement is
explicitly reported as not configured; the table owner is never inferred from
the schema owner or vice versa.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql

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
from app.scripts.apply_users_baseline_correction import (
    APPROVED_DATABASE,
    APPROVED_POSTGRES_VERSION,
    APPROVED_SCHEMA,
    APPROVED_SERVER_VERSION_NUM,
)

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_INFO = "INFO"

MODE_PRE_CORRECTION = "pre-correction"
MODE_CORRECTED_USERS = "corrected-users"
MODE_AFTER_MIGRATIONS = "after-migrations"
VALID_MODES: Tuple[str, ...] = (
    MODE_PRE_CORRECTION,
    MODE_CORRECTED_USERS,
    MODE_AFTER_MIGRATIONS,
)

_PG_DIALECT = postgresql.dialect()
_FOREIGN_KEY_KEY = verify_baseline._ForeignKeyKey
_FOREIGN_KEY_DEFINITION = verify_baseline._ForeignKeyDefinition

# Every statement below is read-only. Keeping them centralized lets the tests
# assert that the verifier cannot emit writes or DDL.
SQL: Dict[str, str] = {
    "identity": (
        "SELECT current_database(), current_schema(), version(), "
        "current_setting('server_version_num')"
    ),
    "schemas": (
        "SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
        "WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema'"
    ),
    "tables": (
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
    ),
    "relations": (
        "SELECT c.relname FROM pg_class c "
        "JOIN pg_namespace ns ON ns.oid = c.relnamespace "
        "WHERE ns.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"
    ),
    "columns": (
        "SELECT table_name, column_name, ordinal_position, data_type, "
        "character_maximum_length, is_nullable, column_default "
        "FROM information_schema.columns "
        "WHERE table_schema = 'public' ORDER BY table_name, ordinal_position"
    ),
    "primary_keys": (
        "SELECT tc.table_name, kcu.column_name "
        "FROM information_schema.table_constraints tc "
        "JOIN information_schema.key_column_usage kcu "
        "ON kcu.constraint_catalog = tc.constraint_catalog "
        "AND kcu.constraint_schema = tc.constraint_schema "
        "AND kcu.constraint_name = tc.constraint_name "
        "WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY' "
        "ORDER BY tc.table_name, kcu.ordinal_position"
    ),
    "indexes": (
        "SELECT tbl.relname, idx.relname, "
        "ARRAY(SELECT attr.attname "
        "FROM unnest(idxdef.indkey) WITH ORDINALITY AS key(attnum, position) "
        "JOIN pg_attribute attr ON attr.attrelid = idxdef.indrelid "
        "AND attr.attnum = key.attnum ORDER BY key.position), "
        "idxdef.indisunique "
        "FROM pg_index idxdef "
        "JOIN pg_class idx ON idx.oid = idxdef.indexrelid "
        "JOIN pg_class tbl ON tbl.oid = idxdef.indrelid "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "WHERE ns.nspname = 'public' AND NOT idxdef.indisprimary"
    ),
    "checks": (
        "SELECT tbl.relname, con.conname, "
        "pg_get_expr(con.conbin, con.conrelid) "
        "FROM pg_constraint con "
        "JOIN pg_class tbl ON tbl.oid = con.conrelid "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "WHERE ns.nspname = 'public' AND con.contype = 'c'"
    ),
    "foreign_keys": (
        "SELECT tbl.relname, con.conname, "
        "(SELECT array_agg(attr.attname ORDER BY key.position) "
        "FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, position) "
        "JOIN pg_attribute attr ON attr.attrelid = con.conrelid "
        "AND attr.attnum = key.attnum), "
        "ref.relname, "
        "(SELECT array_agg(attr.attname ORDER BY key.position) "
        "FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, position) "
        "JOIN pg_attribute attr ON attr.attrelid = con.confrelid "
        "AND attr.attnum = key.attnum), "
        "con.confdeltype "
        "FROM pg_constraint con "
        "JOIN pg_class tbl ON tbl.oid = con.conrelid "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "JOIN pg_class ref ON ref.oid = con.confrelid "
        "WHERE ns.nspname = 'public' AND con.contype = 'f'"
    ),
    "sequences": (
        "SELECT seq.relname, pg_get_userbyid(seq.relowner), "
        "dep_table.relname, dep_attribute.attname "
        "FROM pg_class seq "
        "JOIN pg_namespace ns ON ns.oid = seq.relnamespace "
        "LEFT JOIN pg_depend dep ON dep.objid = seq.oid "
        "AND dep.classid = 'pg_class'::regclass "
        "AND dep.refclassid = 'pg_class'::regclass "
        "AND dep.refobjsubid > 0 "
        "AND dep.deptype IN ('a', 'i') "
        "LEFT JOIN pg_class dep_table ON dep_table.oid = dep.refobjid "
        "LEFT JOIN pg_attribute dep_attribute ON dep_attribute.attrelid = dep.refobjid "
        "AND dep_attribute.attnum = dep.refobjsubid "
        "WHERE ns.nspname = 'public' AND seq.relkind = 'S'"
    ),
    "triggers": (
        "SELECT tbl.relname, trg.tgname FROM pg_trigger trg "
        "JOIN pg_class tbl ON tbl.oid = trg.tgrelid "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "WHERE ns.nspname = 'public' AND NOT trg.tgisinternal"
    ),
    "rules": (
        "SELECT tbl.relname, rewrite.rulename FROM pg_rewrite rewrite "
        "JOIN pg_class tbl ON tbl.oid = rewrite.ev_class "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "WHERE ns.nspname = 'public' AND rewrite.rulename <> '_RETURN'"
    ),
    "column_features": (
        "SELECT tbl.relname, attr.attname, attr.attgenerated, attr.attidentity "
        "FROM pg_attribute attr "
        "JOIN pg_class tbl ON tbl.oid = attr.attrelid "
        "JOIN pg_namespace ns ON ns.oid = tbl.relnamespace "
        "WHERE ns.nspname = 'public' AND attr.attnum > 0 "
        "AND NOT attr.attisdropped"
    ),
    "relation_owners": (
        "SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c "
        "JOIN pg_namespace ns ON ns.oid = c.relnamespace "
        "WHERE ns.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"
    ),
    "grants": (
        "SELECT table_name, grantee, privilege_type, is_grantable "
        "FROM information_schema.role_table_grants "
        "WHERE table_schema = 'public' AND grantor <> grantee"
    ),
    "event_triggers": "SELECT evtname FROM pg_event_trigger",
    "revision": "SELECT version_num FROM public.alembic_version",
}

_ON_DELETE_CODES: Dict[str, str] = {
    "a": "NO ACTION",
    "r": "RESTRICT",
    "c": "CASCADE",
    "n": "SET NULL",
    "d": "SET DEFAULT",
}


@dataclass(frozen=True)
class Finding:
    """One safe, categorized structural finding."""

    status: str
    category: str
    object_name: str
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """Aggregated verifier result."""

    mode: str
    findings: Tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        """Return True only when no FAIL finding was produced."""
        return all(finding.status != STATUS_FAIL for finding in self.findings)

    def render(self) -> str:
        """Render a non-sensitive, human-readable report."""
        lines = [
            f"EXACT_STRUCTURE_VERIFICATION: {STATUS_PASS if self.passed else STATUS_FAIL}",
            f"MODE: {self.mode}",
            "FINDINGS:",
        ]
        for finding in self.findings:
            lines.append(
                f"  {finding.status} {finding.category} "
                f"[{finding.object_name}]: {finding.detail}"
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class ExpectedColumn:
    name: str
    data_type: str
    nullable: bool
    default: Optional[str]


@dataclass(frozen=True)
class ExpectedTable:
    name: str
    columns: Tuple[ExpectedColumn, ...]
    primary_key: Tuple[str, ...]
    indexes: Mapping[str, Tuple[Tuple[str, ...], bool]]
    checks: Mapping[str, str]
    foreign_keys: Mapping[_FOREIGN_KEY_KEY, _FOREIGN_KEY_DEFINITION]


@dataclass(frozen=True)
class ExpectedStructure:
    mode: str
    tables: Mapping[str, ExpectedTable]
    sequence_owners: Mapping[str, Tuple[str, str]]
    revision: Optional[str]


@dataclass(frozen=True)
class IdentityRecord:
    database: str
    current_schema: str
    version_string: str
    server_version_num: str
    dialect: str


@dataclass(frozen=True)
class ColumnRecord:
    table_name: str
    name: str
    ordinal: int
    data_type: str
    nullable: bool
    default: Optional[str]


@dataclass(frozen=True)
class SequenceRecord:
    name: str
    role_owner: str
    owner_table: Optional[str]
    owner_column: Optional[str]


@dataclass(frozen=True)
class IndexRecord:
    table_name: str
    name: str
    columns: Tuple[str, ...]
    unique: bool


@dataclass(frozen=True)
class CheckRecord:
    table_name: str
    name: str
    expression: str


@dataclass(frozen=True)
class ForeignKeyRecord:
    table_name: str
    key: _FOREIGN_KEY_KEY
    definition: _FOREIGN_KEY_DEFINITION


@dataclass(frozen=True)
class ColumnFeatureRecord:
    table_name: str
    column_name: str
    generated: bool
    identity: bool


@dataclass(frozen=True)
class ObjectRecord:
    table_name: str
    name: str


@dataclass(frozen=True)
class GrantRecord:
    table_name: str
    grantee: str
    privilege: str
    grantable: bool


@dataclass(frozen=True)
class SchemaSnapshot:
    """All read-only observations needed for one exact comparison."""

    identity: IdentityRecord
    schemas: Mapping[str, str]
    table_names: FrozenSet[str]
    relation_names: FrozenSet[str]
    columns: Tuple[ColumnRecord, ...]
    primary_keys: Mapping[str, Tuple[str, ...]]
    indexes: Tuple[IndexRecord, ...]
    checks: Tuple[CheckRecord, ...]
    foreign_keys: Tuple[ForeignKeyRecord, ...]
    sequences: Tuple[SequenceRecord, ...]
    triggers: Tuple[ObjectRecord, ...]
    rules: Tuple[ObjectRecord, ...]
    column_features: Tuple[ColumnFeatureRecord, ...]
    table_owners: Mapping[str, str]
    grants: Tuple[GrantRecord, ...]
    event_triggers: FrozenSet[str]
    revision_rows: Tuple[str, ...]


def _normalize_model_type(rendered: object) -> str:
    """Normalize a PostgreSQL-rendered SQLAlchemy type to catalog spelling."""
    value = " ".join(str(rendered).strip().upper().replace('"', "").split())
    match = re.fullmatch(r"VARCHAR\((\d+)\)", value)
    if match:
        return f"varchar({match.group(1)})"
    if value == "INTEGER":
        return "integer"
    if value in {"TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ"}:
        return "timestamptz"
    if value == "BOOLEAN":
        return "boolean"
    if value == "FLOAT":
        return "double precision"
    if value == "JSON":
        return "json"
    return value.lower()


def _normalize_actual_type(data_type: object, maximum_length: object) -> str:
    """Normalize one information_schema type row without losing varchar length."""
    value = " ".join(str(data_type).strip().lower().split())
    if value == "character varying":
        if maximum_length is None:
            return "varchar"
        return f"varchar({int(maximum_length)})"
    if value == "timestamp with time zone":
        return "timestamptz"
    if value == "timestamp without time zone":
        return "timestamp"
    if value == "double precision":
        return "double precision"
    return value


def _normalize_default(value: object) -> Optional[str]:
    """Normalize a PostgreSQL column default to a safe comparable string."""
    if value is None:
        return None
    rendered = " ".join(str(value).strip().lower().split())
    if not rendered:
        return None
    sequence_match = re.search(r"nextval\('([^']+)'::regclass\)", rendered)
    if sequence_match:
        return f"nextval('{sequence_match.group(1)}'::regclass)"
    if rendered.startswith("(") and rendered.endswith(")"):
        rendered = rendered[1:-1].strip()
    if re.fullmatch(r"true|false|-?\d+", rendered):
        return rendered
    return rendered


def _expected_default(table, column) -> Optional[str]:
    """Derive a column's expected database default from model metadata."""
    if column.server_default is not None:
        argument = column.server_default.arg
        raw = getattr(argument, "text", str(argument))
        return _normalize_default(raw)
    primary_key_names = {item.name for item in table.primary_key.columns}
    if (
        column.name in primary_key_names
        and column.autoincrement in (True, "auto")
        and _normalize_model_type(column.type.compile(dialect=_PG_DIALECT)) == "integer"
    ):
        return _normalize_default(f"nextval('{table.name}_id_seq'::regclass)")
    return None


def _expected_table(table) -> ExpectedTable:
    """Build exact expected structure for one SQLAlchemy table."""
    return ExpectedTable(
        name=str(table.name),
        columns=tuple(
            ExpectedColumn(
                name=str(column.name),
                data_type=_normalize_model_type(column.type.compile(dialect=_PG_DIALECT)),
                nullable=bool(column.nullable),
                default=_expected_default(table, column),
            )
            for column in table.columns
        ),
        primary_key=tuple(str(column.name) for column in table.primary_key.columns),
        indexes={
            str(index.name): (
                tuple(str(column.name) for column in index.columns),
                bool(index.unique),
            )
            for index in table.indexes
        },
        checks=verify_baseline._expected_check_constraints(table),
        foreign_keys=verify_baseline._expected_foreign_keys(table),
    )


def _alembic_version_table(final_revision: str) -> ExpectedTable:
    """Build the default Alembic version-table expectation from the chain."""
    return ExpectedTable(
        name="alembic_version",
        columns=(
            ExpectedColumn(
                name="version_num",
                data_type="varchar(32)",
                nullable=False,
                default=None,
            ),
        ),
        primary_key=("version_num",),
        indexes={},
        checks={},
        foreign_keys={},
    )


@lru_cache(maxsize=1)
def _revision_metadata() -> Tuple[Tuple[str, Optional[str]], ...]:
    """Read revision identifiers from migration source without executing it."""
    versions_directory = Path(__file__).resolve().parents[2] / "alembic" / "versions"
    metadata: List[Tuple[str, Optional[str]]] = []
    for path in sorted(versions_directory.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        values: Dict[str, Optional[str]] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets = node.targets
                value_node = node.value
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
                value_node = node.value
            else:
                continue
            if value_node is None:
                continue
            for target in targets:
                if not isinstance(target, ast.Name) or target.id not in {
                    "revision",
                    "down_revision",
                }:
                    continue
                if isinstance(value_node, ast.Constant) and (
                    value_node.value is None or isinstance(value_node.value, str)
                ):
                    values[target.id] = value_node.value
        revision = values.get("revision")
        if not isinstance(revision, str):
            raise RuntimeError("REVISION_IDENTIFIER_UNAVAILABLE")
        metadata.append((revision, values.get("down_revision")))
    return tuple(metadata)


@lru_cache(maxsize=1)
def _final_revision() -> str:
    """Derive the sole head revision from migration source definitions."""
    metadata = _revision_metadata()
    revisions = {revision for revision, _ in metadata}
    children = {parent for _, parent in metadata if parent is not None}
    unknown_parents = children - revisions
    if unknown_parents:
        raise RuntimeError("REVISION_CHAIN_INCOMPLETE")
    heads = sorted(revisions - children)
    if len(heads) != 1:
        raise RuntimeError("REVISION_HEAD_NOT_UNIQUE")
    return heads[0]


def expected_structure(mode: str) -> ExpectedStructure:
    """Build the reviewed expectation set for one explicit comparison mode."""
    if mode not in VALID_MODES:
        raise ValueError("INVALID_MODE")
    if mode == MODE_PRE_CORRECTION:
        model_tables = (APITrafficLog.__table__,)
        revision = None
    elif mode == MODE_CORRECTED_USERS:
        model_tables = (APITrafficLog.__table__, User.__table__)
        revision = None
    else:
        model_tables = (
            APITrafficLog.__table__,
            User.__table__,
            MitigationPolicy.__table__,
            MitigationPolicyState.__table__,
            MitigationPolicyActivationEvent.__table__,
            MitigationDecision.__table__,
            MitigationAuditEvent.__table__,
        )
        revision = _final_revision()

    tables: Dict[str, ExpectedTable] = {}
    for table in model_tables:
        built = _expected_table(table)
        tables[built.name] = built
    if revision is not None:
        version_table = _alembic_version_table(revision)
        tables[version_table.name] = version_table

    sequence_owners: Dict[str, Tuple[str, str]] = {}
    for table in tables.values():
        if table.name == "alembic_version":
            continue
        for column in table.columns:
            if column.default is None:
                continue
            match = re.fullmatch(r"nextval\('([^']+)'::regclass\)", column.default)
            if match:
                sequence_owners[match.group(1)] = (table.name, column.name)

    return ExpectedStructure(
        mode=mode,
        tables=tables,
        sequence_owners=sequence_owners,
        revision=revision,
    )


def _yes_no_to_bool(value: object) -> bool:
    """Normalize PostgreSQL boolean and information_schema YES/NO values."""
    return str(value).strip().upper() in {"YES", "TRUE", "T", "1"}


def _as_name_tuple(value: object) -> Tuple[str, ...]:
    """Normalize catalog array/list renderings into ordered column names."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    rendered = str(value).strip()
    if rendered.startswith("{") and rendered.endswith("}"):
        rendered = rendered[1:-1]
    return tuple(
        item.strip().strip('"')
        for item in rendered.split(",")
        if item.strip()
    )


def _rows(connection: object, key: str, params: Optional[Mapping[str, object]] = None):
    """Execute one centralized read-only query."""
    return connection.execute(  # type: ignore[attr-defined]
        text(SQL[key]), dict(params or {})
    ).fetchall()


def read_snapshot(connection: object) -> SchemaSnapshot:
    """Read all structural facts through read-only catalog queries."""
    identity_row = connection.execute(text(SQL["identity"])).one()  # type: ignore[attr-defined]
    identity = IdentityRecord(
        database=str(identity_row[0]),
        current_schema=str(identity_row[1]),
        version_string=str(identity_row[2]),
        server_version_num=str(identity_row[3]),
        dialect=str(getattr(getattr(connection, "dialect", None), "name", "unknown")),
    )

    schemas = {
        str(row[0]): str(row[1]) for row in _rows(connection, "schemas")
    }
    table_names = frozenset(str(row[0]) for row in _rows(connection, "tables"))
    relation_names = frozenset(str(row[0]) for row in _rows(connection, "relations"))

    columns = tuple(
        ColumnRecord(
            table_name=str(row[0]),
            name=str(row[1]),
            ordinal=int(row[2]),
            data_type=_normalize_actual_type(row[3], row[4]),
            nullable=str(row[5]).strip().upper() == "YES",
            default=_normalize_default(row[6]),
        )
        for row in _rows(connection, "columns")
    )

    primary_key_rows: Dict[str, List[str]] = {}
    for row in _rows(connection, "primary_keys"):
        primary_key_rows.setdefault(str(row[0]), []).append(str(row[1]))
    primary_keys = {
        name: tuple(column_names) for name, column_names in primary_key_rows.items()
    }

    indexes = tuple(
        IndexRecord(
            table_name=str(row[0]),
            name=str(row[1]),
            columns=_as_name_tuple(row[2]),
            unique=bool(row[3]),
        )
        for row in _rows(connection, "indexes")
    )
    checks = tuple(
        CheckRecord(str(row[0]), str(row[1]), str(row[2]))
        for row in _rows(connection, "checks")
    )
    foreign_keys = tuple(
        ForeignKeyRecord(
            table_name=str(row[0]),
            key=verify_baseline._foreign_key_key(row[1], _as_name_tuple(row[2])),
            definition=(
                _as_name_tuple(row[2]),
                str(row[3]) if row[3] is not None else None,
                _as_name_tuple(row[4]),
                verify_baseline._normalized_ondelete(
                    _ON_DELETE_CODES.get(str(row[5]).strip().lower(), str(row[5]))
                ),
            ),
        )
        for row in _rows(connection, "foreign_keys")
    )

    sequences = tuple(
        SequenceRecord(
            name=str(row[0]),
            role_owner=str(row[1]),
            owner_table=str(row[2]) if row[2] is not None else None,
            owner_column=str(row[3]) if row[3] is not None else None,
        )
        for row in _rows(connection, "sequences")
    )
    triggers = tuple(
        ObjectRecord(str(row[0]), str(row[1]))
        for row in _rows(connection, "triggers")
    )
    rules = tuple(
        ObjectRecord(str(row[0]), str(row[1]))
        for row in _rows(connection, "rules")
    )
    column_features = tuple(
        ColumnFeatureRecord(
            table_name=str(row[0]),
            column_name=str(row[1]),
            generated=bool(row[2]) and str(row[2]) not in ("", "None"),
            identity=bool(row[3]) and str(row[3]) not in ("", "None"),
        )
        for row in _rows(connection, "column_features")
    )

    owners = {str(row[0]): str(row[1]) for row in _rows(connection, "relation_owners")}
    table_owners = {
        name: owner
        for name, owner in owners.items()
        if name in table_names
    }
    grants = tuple(
        GrantRecord(
            table_name=str(row[0]),
            grantee=str(row[1]),
            privilege=str(row[2]),
            grantable=_yes_no_to_bool(row[3]),
        )
        for row in _rows(connection, "grants")
    )
    event_triggers = frozenset(str(row[0]) for row in _rows(connection, "event_triggers"))
    revision_rows = (
        tuple(str(row[0]) for row in _rows(connection, "revision"))
        if "alembic_version" in table_names
        else ()
    )

    return SchemaSnapshot(
        identity=identity,
        schemas=schemas,
        table_names=table_names,
        relation_names=relation_names,
        columns=columns,
        primary_keys=primary_keys,
        indexes=indexes,
        checks=checks,
        foreign_keys=foreign_keys,
        sequences=sequences,
        triggers=triggers,
        rules=rules,
        column_features=column_features,
        table_owners=table_owners,
        grants=grants,
        event_triggers=event_triggers,
        revision_rows=revision_rows,
    )


def _finding(
    status: str, category: str, object_name: str, detail: str
) -> Finding:
    return Finding(status, category, object_name, detail)


def _compare_identity(
    snapshot: SchemaSnapshot, findings: List[Finding]
) -> None:
    identity = snapshot.identity
    if identity.dialect != "postgresql":
        findings.append(
            _finding(STATUS_FAIL, "DIALECT_MISMATCH", "connection", "PostgreSQL is required")
        )
    if identity.database != APPROVED_DATABASE:
        findings.append(
            _finding(
                STATUS_FAIL,
                "DATABASE_IDENTITY_MISMATCH",
                "connection",
                "target database is not the reviewed application database",
            )
        )
    match = re.match(r"^PostgreSQL\s+(\d+\.\d+)", identity.version_string)
    if (
        not match
        or match.group(1) != APPROVED_POSTGRES_VERSION
        or identity.server_version_num != APPROVED_SERVER_VERSION_NUM
    ):
        findings.append(
            _finding(
                STATUS_FAIL,
                "POSTGRES_VERSION_MISMATCH",
                "connection",
                "server version is not the reviewed PostgreSQL version",
            )
        )
    if identity.current_schema != APPROVED_SCHEMA:
        findings.append(
            _finding(
                STATUS_FAIL,
                "CURRENT_SCHEMA_MISMATCH",
                "connection",
                f"current schema is not {APPROVED_SCHEMA}",
            )
        )
    expected_schemas = frozenset({APPROVED_SCHEMA})
    actual_schemas = frozenset(snapshot.schemas)
    for name in sorted(expected_schemas - actual_schemas):
        findings.append(
            _finding(STATUS_FAIL, "SCHEMA_MISSING", name, "required schema is absent")
        )
    for name in sorted(actual_schemas - expected_schemas):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_SCHEMA",
                name,
                "non-system schema is not part of the reviewed structure",
            )
        )


def _compare_inventory(
    snapshot: SchemaSnapshot, expected: ExpectedStructure, findings: List[Finding]
) -> None:
    expected_names = frozenset(expected.tables)
    for name in sorted(expected_names - snapshot.table_names):
        findings.append(
            _finding(STATUS_FAIL, "MISSING_TABLE", name, "expected table is absent")
        )
    for name in sorted(snapshot.table_names - expected_names):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_TABLE",
                name,
                "table is not part of the reviewed structure",
            )
        )
    for name in sorted(snapshot.relation_names - expected_names):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_SCHEMA_OBJECT",
                name,
                "relation is not part of the reviewed structure",
            )
        )


def _compare_table(
    snapshot: SchemaSnapshot,
    table: ExpectedTable,
    findings: List[Finding],
) -> None:
    actual_columns = sorted(
        (column for column in snapshot.columns if column.table_name == table.name),
        key=lambda item: item.ordinal,
    )
    expected_by_name = {column.name: column for column in table.columns}
    actual_by_name = {column.name: column for column in actual_columns}

    for name in sorted(expected_by_name.keys() - actual_by_name.keys()):
        findings.append(
            _finding(STATUS_FAIL, "MISSING_COLUMN", f"{table.name}.{name}", "column is absent")
        )
    for name in sorted(actual_by_name.keys() - expected_by_name.keys()):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_COLUMN",
                f"{table.name}.{name}",
                "column is not part of the reviewed structure",
            )
        )

    expected_order = tuple(expected_by_name)
    actual_order = tuple(actual_by_name)
    if expected_by_name.keys() == actual_by_name.keys() and expected_order != actual_order:
        findings.append(
            _finding(
                STATUS_FAIL,
                "COLUMN_ORDER_MISMATCH",
                table.name,
                f"expected {','.join(expected_order)}; observed {','.join(actual_order)}",
            )
        )

    for name in sorted(expected_by_name.keys() & actual_by_name.keys()):
        expected_column = expected_by_name[name]
        actual_column = actual_by_name[name]
        object_name = f"{table.name}.{name}"
        if expected_column.data_type != actual_column.data_type:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "COLUMN_TYPE_MISMATCH",
                    object_name,
                    f"expected {expected_column.data_type}; observed {actual_column.data_type}",
                )
            )
        if expected_column.nullable != actual_column.nullable:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "COLUMN_NULLABILITY_MISMATCH",
                    object_name,
                    "nullability differs from model metadata",
                )
            )
        if expected_column.default != actual_column.default:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "COLUMN_DEFAULT_MISMATCH",
                    object_name,
                    "database default differs from model metadata",
                )
            )

    expected_pk = table.primary_key
    actual_pk = snapshot.primary_keys.get(table.name, ())
    if expected_pk != actual_pk:
        findings.append(
            _finding(
                STATUS_FAIL,
                "PRIMARY_KEY_MISMATCH",
                table.name,
                f"expected {','.join(expected_pk) or '<none>'}; "
                f"observed {','.join(actual_pk) or '<none>'}",
            )
        )

    expected_indexes = dict(table.indexes)
    actual_indexes = {
        index.name: (index.columns, index.unique)
        for index in snapshot.indexes
        if index.table_name == table.name
    }
    for name in sorted(expected_indexes.keys() - actual_indexes.keys()):
        findings.append(
            _finding(STATUS_FAIL, "MISSING_INDEX", f"{table.name}.{name}", "index is absent")
        )
    for name in sorted(actual_indexes.keys() - expected_indexes.keys()):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_INDEX",
                f"{table.name}.{name}",
                "index is not part of the reviewed structure",
            )
        )
    for name in sorted(expected_indexes.keys() & actual_indexes.keys()):
        if expected_indexes[name] != actual_indexes[name]:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "INDEX_DEFINITION_MISMATCH",
                    f"{table.name}.{name}",
                    "indexed columns or uniqueness differ from model metadata",
                )
            )

    string_columns = verify_baseline._string_column_names(
        next(
            model_table
            for model_table in _model_tables_by_name().values()
            if model_table.name == table.name
        )
    ) if table.name != "alembic_version" else frozenset()
    expected_checks = dict(table.checks)
    actual_checks = {
        check.name: verify_baseline._normalized_check_expression(
            check.expression, string_columns
        )
        for check in snapshot.checks
        if check.table_name == table.name
    }
    for name in sorted(expected_checks.keys() - actual_checks.keys()):
        findings.append(
            _finding(
                STATUS_FAIL,
                "MISSING_CHECK_CONSTRAINT",
                f"{table.name}.{name}",
                "check constraint is absent",
            )
        )
    for name in sorted(actual_checks.keys() - expected_checks.keys()):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_CHECK_CONSTRAINT",
                f"{table.name}.{name}",
                "check constraint is not part of the reviewed structure",
            )
        )
    for name in sorted(expected_checks.keys() & actual_checks.keys()):
        if expected_checks[name] != actual_checks[name]:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "CHECK_DEFINITION_MISMATCH",
                    f"{table.name}.{name}",
                    "check expression differs from model metadata",
                )
            )

    expected_fks = dict(table.foreign_keys)
    actual_fks = {
        item.key: item.definition
        for item in snapshot.foreign_keys
        if item.table_name == table.name
    }
    for key in sorted(expected_fks.keys() - actual_fks.keys(), key=lambda item: str(item)):
        findings.append(
            _finding(
                STATUS_FAIL,
                "MISSING_FOREIGN_KEY",
                f"{table.name}.{','.join(key[1])}",
                "foreign key is absent",
            )
        )
    for key in sorted(actual_fks.keys() - expected_fks.keys(), key=lambda item: str(item)):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_FOREIGN_KEY",
                f"{table.name}.{','.join(key[1])}",
                "foreign key is not part of the reviewed structure",
            )
        )
    for key in sorted(expected_fks.keys() & actual_fks.keys(), key=lambda item: str(item)):
        if expected_fks[key] != actual_fks[key]:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "FOREIGN_KEY_DEFINITION_MISMATCH",
                    f"{table.name}.{','.join(key[1])}",
                    "foreign key definition differs from model metadata",
                )
            )

    for feature in snapshot.column_features:
        if feature.table_name != table.name:
            continue
        if feature.generated:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_GENERATED_COLUMN",
                    f"{table.name}.{feature.column_name}",
                    "generated columns are not present in the reviewed structure",
                )
            )
        if feature.identity:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_IDENTITY_COLUMN",
                    f"{table.name}.{feature.column_name}",
                    "identity columns are not present in the reviewed structure",
                )
            )

    for trigger in snapshot.triggers:
        if trigger.table_name == table.name:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_TRIGGER",
                    f"{table.name}.{trigger.name}",
                    "user-defined trigger is not part of the reviewed structure",
                )
            )
    for rule in snapshot.rules:
        if rule.table_name == table.name:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_RULE",
                    f"{table.name}.{rule.name}",
                    "non-internal rule is not part of the reviewed structure",
                )
            )


@lru_cache(maxsize=1)
def _model_tables_by_name():
    """Return all reviewed model tables keyed by name."""
    tables = (
        APITrafficLog.__table__,
        User.__table__,
        MitigationPolicy.__table__,
        MitigationPolicyState.__table__,
        MitigationPolicyActivationEvent.__table__,
        MitigationDecision.__table__,
        MitigationAuditEvent.__table__,
    )
    return {table.name: table for table in tables}


def _compare_sequences(
    snapshot: SchemaSnapshot, expected: ExpectedStructure, findings: List[Finding]
) -> None:
    expected_names = frozenset(expected.sequence_owners)
    actual_by_name = {sequence.name: sequence for sequence in snapshot.sequences}
    actual_names = frozenset(actual_by_name)
    for name in sorted(expected_names - actual_names):
        findings.append(
            _finding(STATUS_FAIL, "MISSING_SEQUENCE", name, "expected sequence is absent")
        )
    for name in sorted(actual_names - expected_names):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_SEQUENCE",
                name,
                "sequence is not part of the reviewed structure",
            )
        )
    for name in sorted(expected_names & actual_names):
        expected_owner = expected.sequence_owners[name]
        sequence = actual_by_name[name]
        observed_owner = (sequence.owner_table, sequence.owner_column)
        if observed_owner != expected_owner:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "SEQUENCE_OWNERSHIP_MISMATCH",
                    name,
                    f"expected {expected_owner[0]}.{expected_owner[1]}; "
                    f"observed {observed_owner[0]}.{observed_owner[1]}",
                )
            )


def _compare_revision_state(
    snapshot: SchemaSnapshot, expected: ExpectedStructure, findings: List[Finding]
) -> None:
    if expected.revision is None:
        if snapshot.revision_rows:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_REVISION_STATE",
                    "alembic_version",
                    "this mode requires an unversioned schema",
                )
            )
        return
    if len(snapshot.revision_rows) != 1 or snapshot.revision_rows[0] != expected.revision:
        findings.append(
            _finding(
                STATUS_FAIL,
                "REVISION_MISMATCH",
                "alembic_version",
                f"expected sole revision {expected.revision}",
            )
        )


def _compare_ownership_and_grants(
    snapshot: SchemaSnapshot,
    expected: ExpectedStructure,
    expected_owner: Optional[str],
    findings: List[Finding],
    expected_schema_owner: Optional[str] = None,
) -> None:
    if expected_owner is None:
        findings.append(
            _finding(
                STATUS_INFO,
                "EXPECTED_OWNER_NOT_CONFIGURED",
                "ownership",
                "table and sequence owner enforcement was not configured; "
                "use --expected-owner",
            )
        )
    else:
        for name in sorted(frozenset(expected.tables) - frozenset(snapshot.table_owners)):
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "OWNER_INFORMATION_UNAVAILABLE",
                    name,
                    "table owner could not be inspected",
                )
            )
        for name in sorted(frozenset(expected.tables) & frozenset(snapshot.table_owners)):
            owner = snapshot.table_owners[name]
            if owner is None or not str(owner).strip():
                findings.append(
                    _finding(
                        STATUS_FAIL,
                        "OWNER_INFORMATION_UNAVAILABLE",
                        name,
                        "table owner metadata is unavailable",
                    )
                )
            elif owner != expected_owner:
                findings.append(
                    _finding(
                        STATUS_FAIL,
                        "TABLE_OWNER_MISMATCH",
                        name,
                        "table owner differs from --expected-owner",
                    )
                )

        actual_sequences = {sequence.name: sequence for sequence in snapshot.sequences}
        for name in sorted(expected.sequence_owners):
            sequence = actual_sequences.get(name)
            if sequence is None:
                # MISSING_SEQUENCE already reports the absent object.
                continue
            role_owner = sequence.role_owner
            if role_owner is None or not str(role_owner).strip():
                findings.append(
                    _finding(
                        STATUS_FAIL,
                        "SEQUENCE_ROLE_OWNER_INFORMATION_UNAVAILABLE",
                        name,
                        "sequence role owner metadata is unavailable",
                    )
                )
            elif role_owner != expected_owner:
                findings.append(
                    _finding(
                        STATUS_FAIL,
                        "SEQUENCE_ROLE_OWNER_MISMATCH",
                        name,
                        "sequence owner differs from --expected-owner",
                    )
                )

    observed_schema_owner = snapshot.schemas.get(APPROVED_SCHEMA)
    if expected_schema_owner is None:
        rendered_owner = (
            str(observed_schema_owner).strip()
            if observed_schema_owner is not None and str(observed_schema_owner).strip()
            else "unavailable"
        )
        findings.append(
            _finding(
                STATUS_INFO,
                "SCHEMA_OWNER_ENFORCEMENT_NOT_CONFIGURED",
                APPROVED_SCHEMA,
                f"observed schema owner is {rendered_owner}; "
                "schema-owner enforcement was not configured; "
                "use --expected-schema-owner to enforce it",
            )
        )
    elif observed_schema_owner is None or not str(observed_schema_owner).strip():
        findings.append(
            _finding(
                STATUS_FAIL,
                "SCHEMA_OWNER_INFORMATION_UNAVAILABLE",
                APPROVED_SCHEMA,
                "schema owner could not be inspected",
            )
        )
    elif observed_schema_owner != expected_schema_owner:
        findings.append(
            _finding(
                STATUS_FAIL,
                "SCHEMA_OWNER_MISMATCH",
                APPROVED_SCHEMA,
                "schema owner differs from --expected-schema-owner",
            )
        )

    for grant in snapshot.grants:
        if grant.table_name in expected.tables:
            findings.append(
                _finding(
                    STATUS_FAIL,
                    "UNEXPECTED_GRANT",
                    f"{grant.table_name}.{grant.privilege}",
                    f"explicit grant to {grant.grantee} is not in the reviewed migrations",
                )
            )


def compare_snapshot(
    snapshot: SchemaSnapshot,
    expected: ExpectedStructure,
    expected_owner: Optional[str] = None,
    expected_schema_owner: Optional[str] = None,
) -> VerificationResult:
    """Compare an already-read snapshot with an expected structure."""
    findings: List[Finding] = []
    _compare_identity(snapshot, findings)
    _compare_inventory(snapshot, expected, findings)
    for name in sorted(expected.tables):
        if name in snapshot.table_names:
            _compare_table(snapshot, expected.tables[name], findings)
    _compare_sequences(snapshot, expected, findings)
    _compare_revision_state(snapshot, expected, findings)
    _compare_ownership_and_grants(
        snapshot, expected, expected_owner, findings, expected_schema_owner
    )

    for event_trigger in sorted(snapshot.event_triggers):
        findings.append(
            _finding(
                STATUS_FAIL,
                "UNEXPECTED_EVENT_TRIGGER",
                event_trigger,
                "event trigger is not part of the reviewed structure",
            )
        )
    findings.append(
        _finding(
            STATUS_INFO,
            "CHECK_EXPRESSION_NORMALIZATION",
            "constraints",
            "CHECK expressions use the reviewed conservative normalization grammar",
        )
    )
    findings.append(
        _finding(
            STATUS_INFO,
            "OBJECT_INVENTORY_SCOPE",
            "schema",
            "routines, custom types, and extensions are outside the reviewed object inventory",
        )
    )
    if not any(finding.status == STATUS_FAIL for finding in findings):
        findings.append(
            _finding(
                STATUS_PASS,
                "EXACT_STRUCTURE_MATCH",
                "schema",
                "all required structural checks passed",
            )
        )
    return VerificationResult(mode=expected.mode, findings=tuple(findings))


def verify_structure(
    connection: object,
    mode: str,
    expected_owner: Optional[str] = None,
    expected_schema_owner: Optional[str] = None,
) -> VerificationResult:
    """Read one connection and compare it with the requested expected mode."""
    return compare_snapshot(
        read_snapshot(connection),
        expected_structure(mode),
        expected_owner,
        expected_schema_owner,
    )


def verify_exact_structure(
    database_url: Optional[str] = None,
    *,
    mode: str,
    engine_factory: Optional[object] = None,
    expected_owner: Optional[str] = None,
    expected_schema_owner: Optional[str] = None,
) -> VerificationResult:
    """Run the verifier; the returned result decides the process exit code."""
    if mode not in VALID_MODES:
        return VerificationResult(
            mode=mode,
            findings=(
                _finding(STATUS_FAIL, "INVALID_MODE", "cli", "unsupported verification mode"),
            ),
        )

    engine = None
    try:
        if engine_factory is not None:
            engine = engine_factory()
        else:
            target_url = database_url
            if target_url is None:
                from app.core.config import settings

                target_url = settings.get_database_url()
            engine = create_engine(target_url)
        with engine.connect() as connection:  # type: ignore[attr-defined]
            return verify_structure(
                connection,
                mode,
                expected_owner,
                expected_schema_owner,
            )
    except Exception as exc:  # noqa: BLE001 - never emit raw DSNs or diagnostics
        return VerificationResult(
            mode=mode,
            findings=(
                _finding(
                    STATUS_FAIL,
                    "INSPECTION_FAILED",
                    "connection",
                    f"inspection failed ({type(exc).__name__}); no raw diagnostic emitted",
                ),
            ),
        )
    finally:
        if engine is not None:
            engine.dispose()  # type: ignore[attr-defined]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point. Exits 0 only when every required check passes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=VALID_MODES)
    parser.add_argument(
        "--database-url",
        default=None,
        help="Optional isolated target URL; credentials are never printed",
    )
    parser.add_argument(
        "--expected-owner",
        default=None,
        help=(
            "Optional role that must own reviewed application tables and sequences; "
            "does not enforce schema ownership"
        ),
    )
    parser.add_argument(
        "--expected-schema-owner",
        default=None,
        help=(
            "Optional role that must own the reviewed schema; when omitted, the "
            "observed schema owner is informational and is not enforced"
        ),
    )
    args = parser.parse_args(argv)
    result = verify_exact_structure(
        args.database_url,
        mode=args.mode,
        expected_owner=args.expected_owner,
        expected_schema_owner=args.expected_schema_owner,
    )
    print(result.render())
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
