"""Baseline: existing users and API traffic log schema.

This revision is a reviewed representation of the current schema assembled from:

- ``app.db.base.Base``
- ``app.models.traffic.APITrafficLog``
- ``app.models.user.User``
- ``app.db.init_db.init_db()`` documented ad hoc index creation

It is additive only. It does not create mitigation tables. Existing databases
must pass the read-only schema verifier before this revision is stamped; never
stamp an unverified database.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_baseline_existing_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the reviewed baseline schema on a fresh database."""
    op.create_table(
        "api_traffic_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=100), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("query_params", sa.JSON(), nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=False),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response_time_ms", sa.Float(), nullable=False),
        sa.Column("actor_id", sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_api_traffic_logs_actor_id", "api_traffic_logs", ["actor_id"], unique=False
    )
    op.create_index(
        "ix_api_traffic_logs_client_ip", "api_traffic_logs", ["client_ip"], unique=False
    )
    op.create_index("ix_api_traffic_logs_id", "api_traffic_logs", ["id"], unique=False)
    op.create_index("ix_api_traffic_logs_path", "api_traffic_logs", ["path"], unique=False)
    op.create_index(
        "ix_api_traffic_logs_request_id", "api_traffic_logs", ["request_id"], unique=False
    )
    op.create_index(
        "ix_api_traffic_logs_status_code", "api_traffic_logs", ["status_code"], unique=False
    )
    op.create_index(
        "ix_api_traffic_logs_timestamp", "api_traffic_logs", ["timestamp"], unique=False
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_is_active", "users", ["is_active"], unique=False)
    op.create_index("ix_users_role", "users", ["role"], unique=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    """Refuse automatic baseline downgrade.

    The baseline represents pre-Alembic schema. Reverting it would mean dropping
    existing application tables, so recovery must be an explicit restore or a
    separately reviewed corrective procedure.
    """
    raise RuntimeError(
        "Baseline revision 0001_baseline_existing_schema is deliberately not "
        "downgradeable; restore from a verified backup or use a reviewed correction."
    )
