"""Add mitigation decision and audit persistence tables.

This revision is strictly additive. It creates only the two Phase 2 tables and
their indexes, foreign keys, and portable CHECK constraints. It does not alter
any table created by revision 0001 or 0002, and it is safe to run against an
isolated SQLite database.

The downgrade removes only objects created here. Earlier revisions are never
downgraded by this module.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_mitigation_decision_audit"
down_revision: Union[str, None] = "0002_mitigation_policy_models"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_HEX_DIGITS = "0123456789abcdef"


def _in_clause(column: str, values: Sequence[str]) -> str:
    """Build the same portable CHECK expression used by the model metadata."""
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


def _sha256_check(column: str, *, nullable: bool) -> str:
    """Build a portable CHECK for ``sha256:<64 lowercase hex>`` values."""
    body = f"substr({column}, 8)"
    stripped = body
    for digit in _HEX_DIGITS:
        stripped = f"replace({stripped}, '{digit}', '')"
    value_check = (
        f"length({column}) = 71 "
        f"AND substr({column}, 1, 7) = 'sha256:' "
        f"AND lower({column}) = {column} "
        f"AND length({stripped}) = 0"
    )
    return f"{column} IS NULL OR ({value_check})" if nullable else value_check


def _uuid5_check(column: str) -> str:
    """Build a portable CHECK for a lowercase UUID5 string."""
    compact = f"replace({column}, '-', '')"
    stripped = compact
    for digit in _HEX_DIGITS:
        stripped = f"replace({stripped}, '{digit}', '')"
    return (
        f"length({column}) = 36 "
        f"AND lower({column}) = {column} "
        f"AND substr({column}, 9, 1) = '-' "
        f"AND substr({column}, 14, 1) = '-' "
        f"AND substr({column}, 19, 1) = '-' "
        f"AND substr({column}, 24, 1) = '-' "
        f"AND substr({compact}, 13, 1) = '5' "
        f"AND substr({compact}, 17, 1) IN ('8', '9', 'a', 'b') "
        f"AND length({stripped}) = 0"
    )


def upgrade() -> None:
    """Create the reviewed Phase 2 decision and audit tables and indexes."""
    op.create_table(
        "mitigation_decisions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("decision_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "decision_type",
            sa.Enum(
                "allow",
                "monitor",
                "throttle",
                "block",
                name="mitigation_decision_type",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "scope_type",
            sa.Enum(
                "verified_user",
                "api_key_principal",
                "network_ip",
                "unattributed",
                name="mitigation_scope_type",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("scope_key_hash", sa.String(length=71), nullable=True),
        sa.Column(
            "attribution_status",
            sa.Enum(
                "verified_user",
                "api_key_principal",
                "network_ip",
                "inferred",
                "missing",
                name="mitigation_attribution_status",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("verified_attribution", sa.Boolean(), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.String(length=2000), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("evidence_references", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rate_limit", sa.Integer(), nullable=True),
        sa.Column("rate_limit_window_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "advisory_only",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=False,
        ),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mitigation_policies.id"],
            name="fk_mitigation_decision_policy",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            _in_clause("decision_type", ("allow", "monitor", "throttle", "block")),
            name="ck_mitigation_decision_decision_type",
        ),
        sa.CheckConstraint(
            _in_clause(
                "scope_type",
                ("verified_user", "api_key_principal", "network_ip", "unattributed"),
            ),
            name="ck_mitigation_decision_scope_type",
        ),
        sa.CheckConstraint(
            _in_clause(
                "attribution_status",
                ("verified_user", "api_key_principal", "network_ip", "inferred", "missing"),
            ),
            name="ck_mitigation_decision_attribution_status",
        ),
        sa.CheckConstraint("advisory_only", name="ck_mitigation_decision_advisory_only"),
        sa.CheckConstraint(
            _sha256_check("scope_key_hash", nullable=True),
            name="ck_mitigation_decision_scope_key_hash",
        ),
        sa.CheckConstraint(
            _uuid5_check("decision_uuid"),
            name="ck_mitigation_decision_decision_uuid_format",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > issued_at",
            name="ck_mitigation_decision_expiry_after_issue",
        ),
        sa.CheckConstraint(
            "rate_limit IS NULL OR rate_limit > 0",
            name="ck_mitigation_decision_rate_limit_positive",
        ),
        sa.CheckConstraint(
            "rate_limit_window_seconds IS NULL OR rate_limit_window_seconds > 0",
            name="ck_mitigation_decision_rate_window_positive",
        ),
    )
    op.create_index(
        "ix_mitigation_decisions_created_at",
        "mitigation_decisions",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_decision_type",
        "mitigation_decisions",
        ["decision_type"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_decision_uuid",
        "mitigation_decisions",
        ["decision_uuid"],
        unique=True,
    )
    op.create_index(
        "ix_mitigation_decisions_dedupe_key",
        "mitigation_decisions",
        ["dedupe_key"],
        unique=True,
    )
    op.create_index(
        "ix_mitigation_decisions_expires_at",
        "mitigation_decisions",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_issued_at",
        "mitigation_decisions",
        ["issued_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_policy_id",
        "mitigation_decisions",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_scope_key_hash",
        "mitigation_decisions",
        ["scope_key_hash"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_decisions_scope_type",
        "mitigation_decisions",
        ["scope_type"],
        unique=False,
    )

    op.create_table(
        "mitigation_audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
                "policy_activated",
                "policy_deactivated",
                "policy_version_changed",
                "decision_issued",
                "decision_expired",
                "enforcement_applied_reserved",
                "enforcement_removed_reserved",
                name="mitigation_audit_event_type",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "entity_type",
            sa.Enum(
                "policy",
                "decision",
                name="mitigation_audit_entity_type",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("entity_identifier", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=True),
        sa.Column("decision_id", sa.Integer(), nullable=True),
        sa.Column("actor_hash", sa.String(length=71), nullable=True),
        sa.Column("actor_role", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("previous_event_hash", sa.String(length=71), nullable=True),
        sa.Column("event_hash", sa.String(length=71), nullable=False),
        sa.Column("sequence_no", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["decision_id"],
            ["mitigation_decisions.id"],
            name="fk_mitigation_audit_event_decision",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mitigation_policies.id"],
            name="fk_mitigation_audit_event_policy",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            _in_clause(
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
            name="ck_mitigation_audit_event_type",
        ),
        sa.CheckConstraint(
            _in_clause("entity_type", ("policy", "decision")),
            name="ck_mitigation_audit_entity_type",
        ),
        sa.CheckConstraint(
            _uuid5_check("event_uuid"),
            name="ck_mitigation_audit_event_uuid_format",
        ),
        sa.CheckConstraint(
            _sha256_check("actor_hash", nullable=True),
            name="ck_mitigation_audit_actor_hash",
        ),
        sa.CheckConstraint(
            _sha256_check("previous_event_hash", nullable=True),
            name="ck_mitigation_audit_previous_event_hash",
        ),
        sa.CheckConstraint(
            _sha256_check("event_hash", nullable=False),
            name="ck_mitigation_audit_event_hash",
        ),
        sa.CheckConstraint(
            "sequence_no > 0", name="ck_mitigation_audit_sequence_no_positive"
        ),
        sa.CheckConstraint(
            "length(chain_id) BETWEEN 1 AND 64",
            name="ck_mitigation_audit_chain_id_length",
        ),
        sa.CheckConstraint(
            "length(entity_identifier) BETWEEN 1 AND 64",
            name="ck_mitigation_audit_entity_identifier_length",
        ),
    )
    op.create_index(
        "ix_mitigation_audit_events_actor_hash",
        "mitigation_audit_events",
        ["actor_hash"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_chain_id",
        "mitigation_audit_events",
        ["chain_id"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_created_at",
        "mitigation_audit_events",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_decision_id",
        "mitigation_audit_events",
        ["decision_id"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_entity_type",
        "mitigation_audit_events",
        ["entity_type"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_event_type",
        "mitigation_audit_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_audit_events_event_uuid",
        "mitigation_audit_events",
        ["event_uuid"],
        unique=True,
    )
    op.create_index(
        "ix_mitigation_audit_events_policy_id",
        "mitigation_audit_events",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        "uq_mitigation_audit_events_chain_id_sequence_no",
        "mitigation_audit_events",
        ["chain_id", "sequence_no"],
        unique=True,
    )


def downgrade() -> None:
    """Drop only Phase 2 objects; earlier revision objects are never touched."""
    op.drop_index(
        "uq_mitigation_audit_events_chain_id_sequence_no",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_policy_id",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_event_uuid",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_event_type",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_entity_type",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_decision_id",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_created_at",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_chain_id",
        table_name="mitigation_audit_events",
    )
    op.drop_index(
        "ix_mitigation_audit_events_actor_hash",
        table_name="mitigation_audit_events",
    )
    op.drop_table("mitigation_audit_events")

    op.drop_index(
        "ix_mitigation_decisions_scope_type",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_scope_key_hash",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_policy_id",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_issued_at",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_expires_at",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_dedupe_key",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_decision_uuid",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_decision_type",
        table_name="mitigation_decisions",
    )
    op.drop_index(
        "ix_mitigation_decisions_created_at",
        table_name="mitigation_decisions",
    )
    op.drop_table("mitigation_decisions")
