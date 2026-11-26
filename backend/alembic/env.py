"""Alembic environment for APISentry Phase 0.

Database URL policy:
    The only URL source is ``app.core.config.settings.get_database_url()``.
    Credentials and DSNs are never logged or printed.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models import APITrafficLog, User  # noqa: E402,F401

config = context.config

if config.config_file_name is not None:
    # Preserve application loggers (and test log capture) configured elsewhere.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Percent signs must be escaped for ConfigParser interpolation.
config.set_main_option("sqlalchemy.url", settings.get_database_url().replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Render migration SQL without connecting to a database."""
    context.configure(
        url=settings.get_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using an explicit, short-lived Alembic connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
