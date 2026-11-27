from sqlalchemy import text

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine


def _production_environment_detected() -> bool:
    """Fail closed if either the normalized environment or safety property says production.

    The environment check keeps this guard compatible with isolated tests that
    supply a minimal settings stub without the full Settings interface.
    """
    environment_is_production = (
        str(getattr(settings, "ENVIRONMENT", "")).strip().lower() == "production"
    )
    return environment_is_production or bool(getattr(settings, "is_production", False))


def init_db() -> None:
    """
    Development/test-only initializer to create database tables and indexes.

    Production must use explicit, reviewed Alembic migrations instead. This
    guard is defence in depth even if a caller accidentally invokes init_db().
    """
    if _production_environment_detected():
        raise RuntimeError(
            "Automatic schema creation is disabled in production; use reviewed Alembic migrations."
        )

    # Import models only when initializing the database, so they are
    # registered with Base.metadata without creating a package import cycle.
    from app.models.mitigation import (  # noqa: F401
        MitigationAuditEvent,
        MitigationDecision,
        MitigationPolicy,
        MitigationPolicyActivationEvent,
        MitigationPolicyState,
    )
    from app.models.revoked_token import RevokedToken  # noqa: F401
    from app.models.traffic import APITrafficLog  # noqa: F401
    from app.models.user import User  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Ensure any newly defined model columns and indexes exist on existing tables.
    with engine.begin() as conn:
        dialect = engine.dialect.name
        if dialect == "postgresql":
            conn.execute(
                text(
                    "ALTER TABLE api_traffic_logs ADD COLUMN IF NOT EXISTS actor_id VARCHAR(100);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_api_traffic_logs_actor_id "
                    "ON api_traffic_logs (actor_id);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_users_email "
                    "ON users (email);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_users_role "
                    "ON users (role);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_users_is_active "
                    "ON users (is_active);"
                )
            )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_api_traffic_logs_client_ip "
                "ON api_traffic_logs (client_ip);"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_api_traffic_logs_status_code "
                "ON api_traffic_logs (status_code);"
            )
        )
