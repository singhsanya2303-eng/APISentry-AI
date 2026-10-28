
from sqlalchemy import text

from app.db.base import Base
from app.db.session import engine


def init_db() -> None:
    """
    Lightweight MVP initializer to create database tables and indexes.
    Note: For production deployments, migration tooling (e.g. Alembic) should be used.
    """
    # Import models only when initializing the database, so they are
    # registered with Base.metadata without creating a package import cycle.
    from app.models.traffic import APITrafficLog  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # Ensure any newly defined model indexes exist on existing tables.
    with engine.begin() as conn:
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
