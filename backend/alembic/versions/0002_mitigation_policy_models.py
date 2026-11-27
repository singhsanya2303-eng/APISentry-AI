"""Add mitigation policy persistence tables.

This revision is strictly additive. It creates only the three Phase 1 tables
and their indexes/foreign keys. It does not alter ``users`` or
``api_traffic_logs``, and it is safe to run against an isolated SQLite database.

The downgrade removes only objects created here. Revisions below 0002 are never
downgraded by this module.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_mitigation_policy_models"
down_revision: Union[str, None] = "0001_baseline_existing_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the reviewed Phase 1 mitigation tables and indexes."""
    op.create_table(
        "mitigation_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "mode",
            sa.Enum(
                "shadow",
                "monitor",
                "enforce",
                name="mitigation_policy_mode",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("monitoring_score_threshold", sa.Float(), nullable=False),
        sa.Column("throttling_score_threshold", sa.Float(), nullable=False),
        sa.Column("blocking_score_threshold", sa.Float(), nullable=False),
        sa.Column("minimum_authentication_failures", sa.Integer(), nullable=False),
        sa.Column("require_grouped_brute_force", sa.Boolean(), nullable=False),
        sa.Column("throttle_enabled", sa.Boolean(), nullable=False),
        sa.Column("throttle_limit", sa.Integer(), nullable=False),
        sa.Column("throttle_window_seconds", sa.Integer(), nullable=False),
        sa.Column("throttle_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("block_enabled", sa.Boolean(), nullable=False),
        sa.Column("block_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("max_block_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("admin_protection_enabled", sa.Boolean(), nullable=False),
        sa.Column("max_evidence_references", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("creator_hash", sa.String(length=71), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mitigation_policies_created_at",
        "mitigation_policies",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_policies_policy_version",
        "mitigation_policies",
        ["policy_version"],
        unique=True,
    )

    op.create_table(
        "mitigation_policy_state",
        sa.Column("id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=True),
        sa.Column(
            "singleton_marker",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mitigation_policies.id"],
            name="fk_mitigation_policy_state_policy",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("id = 1", name="ck_mitigation_policy_state_id"),
        sa.CheckConstraint(
            "singleton_marker = 1", name="ck_mitigation_policy_state_singleton_marker"
        ),
    )
    op.create_index(
        "ix_mitigation_policy_state_policy_id",
        "mitigation_policy_state",
        ["policy_id"],
        unique=True,
    )
    op.create_index(
        "ix_mitigation_policy_state_singleton_marker",
        "mitigation_policy_state",
        ["singleton_marker"],
        unique=True,
    )

    op.create_table(
        "mitigation_policy_activation_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
                "ACTIVATE",
                "DEACTIVATE",
                name="mitigation_activation_event_type",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("actor_hash", sa.String(length=71), nullable=True),
        sa.Column(
            "reason_code",
            sa.Enum(
                "initial_activation",
                "policy_version_change",
                "operator_review",
                "configuration_review",
                "policy_deactivation",
                name="mitigation_activation_reason_code",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mitigation_policies.id"],
            name="fk_mitigation_activation_event_policy",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "event_type IN ('ACTIVATE', 'DEACTIVATE')",
            name="ck_mitigation_policy_activation_event_type",
        ),
        sa.CheckConstraint(
            "reason_code IN ('initial_activation', 'policy_version_change', "
            "'operator_review', 'configuration_review', 'policy_deactivation')",
            name="ck_mitigation_policy_activation_reason_code",
        ),
    )
    op.create_index(
        "ix_mitigation_policy_activation_events_event_type",
        "mitigation_policy_activation_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_policy_activation_events_event_uuid",
        "mitigation_policy_activation_events",
        ["event_uuid"],
        unique=True,
    )
    op.create_index(
        "ix_mitigation_policy_activation_events_occurred_at",
        "mitigation_policy_activation_events",
        ["occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_mitigation_policy_activation_events_policy_id",
        "mitigation_policy_activation_events",
        ["policy_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop only Phase 1 objects; baseline tables are never touched here."""
    op.drop_index(
        "ix_mitigation_policy_activation_events_policy_id",
        table_name="mitigation_policy_activation_events",
    )
    op.drop_index(
        "ix_mitigation_policy_activation_events_occurred_at",
        table_name="mitigation_policy_activation_events",
    )
    op.drop_index(
        "ix_mitigation_policy_activation_events_event_uuid",
        table_name="mitigation_policy_activation_events",
    )
    op.drop_index(
        "ix_mitigation_policy_activation_events_event_type",
        table_name="mitigation_policy_activation_events",
    )
    op.drop_table("mitigation_policy_activation_events")

    op.drop_index(
        "ix_mitigation_policy_state_singleton_marker",
        table_name="mitigation_policy_state",
    )
    op.drop_index(
        "ix_mitigation_policy_state_policy_id",
        table_name="mitigation_policy_state",
    )
    op.drop_table("mitigation_policy_state")

    op.drop_index(
        "ix_mitigation_policies_policy_version",
        table_name="mitigation_policies",
    )
    op.drop_index(
        "ix_mitigation_policies_created_at",
        table_name="mitigation_policies",
    )
    op.drop_table("mitigation_policies")
