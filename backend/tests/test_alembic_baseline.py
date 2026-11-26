"""Isolated Alembic baseline tests.

Every database used here is a temporary SQLite file. No configured development or
production database is ever contacted, migrated, or stamped.
"""

import re
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app.core.config import settings
from app.db.base import Base
from app.models import APITrafficLog, User  # noqa: F401
from app.scripts.verify_baseline import verify_schema

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
BASELINE_REVISION = "0001_baseline_existing_schema"
HEAD_REVISION = "0004_revoked_tokens"


@pytest.fixture
def alembic_config(tmp_path, monkeypatch):
    """Point Alembic at an isolated SQLite file via the settings URL source."""
    url = "sqlite:///" + (tmp_path / "private-dsn-marker.db").as_posix()
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    return Config(str(ALEMBIC_INI)), url


def _inspector(url):
    engine = create_engine(url)
    try:
        return engine, inspect(engine)
    except Exception:
        engine.dispose()
        raise


def test_fresh_sqlite_upgrade_creates_expected_schema(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")

    engine, inspector = _inspector(url)
    try:
        assert set(inspector.get_table_names()) == {
            "api_traffic_logs",
            "users",
            "mitigation_policies",
            "mitigation_policy_state",
            "mitigation_policy_activation_events",
            "mitigation_decisions",
            "mitigation_audit_events",
            "revoked_tokens",
            "alembic_version",
        }

        for table in Base.metadata.sorted_tables:
            actual_columns = {
                column["name"]: bool(column["nullable"])
                for column in inspector.get_columns(table.name)
            }
            expected_columns = {column.name: bool(column.nullable) for column in table.columns}
            assert actual_columns == expected_columns

            actual_pk = tuple(
                inspector.get_pk_constraint(table.name).get("constrained_columns", []) or []
            )
            expected_pk = tuple(column.name for column in table.primary_key.columns)
            assert set(actual_pk) == set(expected_pk)

            actual_indexes = {
                index["name"]: (
                    tuple(index.get("column_names", []) or []),
                    bool(index.get("unique")),
                )
                for index in inspector.get_indexes(table.name)
            }
            expected_indexes = {
                index.name: (
                    tuple(column.name for column in index.columns),
                    bool(index.unique),
                )
                for index in table.indexes
            }
            assert actual_indexes == expected_indexes

        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).fetchall()
            ]
        assert revisions == [HEAD_REVISION]
    finally:
        engine.dispose()


def test_fresh_sqlite_upgrade_matches_metadata_and_verifier(alembic_config):
    config, url = alembic_config

    command.upgrade(config, "head")

    result = verify_schema(url)
    assert result.passed is True
    assert any(finding.code == "SCHEMA_MATCHES_BASELINE" for finding in result.findings)
    assert any(finding.code == "DATA_CHECKSUM_DEFERRED" for finding in result.findings)


def test_baseline_downgrade_is_refused_without_dropping_schema(alembic_config):
    config, url = alembic_config
    command.upgrade(config, BASELINE_REVISION)

    with pytest.raises(RuntimeError, match="not downgradeable"):
        command.downgrade(config, "base")

    engine, inspector = _inspector(url)
    try:
        assert {"api_traffic_logs", "users", "alembic_version"}.issubset(
            set(inspector.get_table_names())
        )
        assert {
            "mitigation_policies",
            "mitigation_policy_state",
            "mitigation_policy_activation_events",
        }.isdisjoint(set(inspector.get_table_names()))
    finally:
        engine.dispose()


def test_alembic_config_has_no_embedded_dsn():
    ini_text = ALEMBIC_INI.read_text(encoding="utf-8")
    assert "sqlalchemy.url" not in ini_text
    assert "script_location = %(here)s/alembic" in ini_text

    config = Config(str(ALEMBIC_INI))
    assert "alembic" in config.get_main_option("script_location")

    env_source = (BACKEND_DIR / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "settings.get_database_url()" in env_source
    assert "target_metadata = Base.metadata" in env_source
    assert "from app.models import" in env_source
    assert "render_as_batch=True" in env_source

    migration_source = (
        BACKEND_DIR / "alembic" / "versions" / "0001_baseline_existing_schema.py"
    ).read_text(encoding="utf-8")
    assert 'revision: str = "0001_baseline_existing_schema"' in migration_source
    assert "raise RuntimeError(" in migration_source


def test_migration_output_does_not_contain_database_url(alembic_config, capfd):
    config, url = alembic_config

    command.upgrade(config, "head")

    captured = capfd.readouterr()
    combined = captured.out + captured.err
    assert url not in combined
    assert "private-dsn-marker" not in combined


def test_every_revision_id_fits_postgresql_default_version_column():
    config = Config(str(ALEMBIC_INI))
    scripts = ScriptDirectory.from_config(config)
    revisions = list(scripts.walk_revisions())
    assert len(revisions) == 4

    for script in revisions:
        assert len(script.revision) <= 32, (
            f"revision {script.revision!r} exceeds VARCHAR(32)"
        )

    chain = [script.revision for script in reversed(revisions)]
    assert chain == [
        "0001_baseline_existing_schema",
        "0002_mitigation_policy_models",
        "0003_mitigation_decision_audit",
        "0004_revoked_tokens",
    ]
    assert [scripts.get_revision(rev).down_revision for rev in chain] == [
        None,
        "0001_baseline_existing_schema",
        "0002_mitigation_policy_models",
        "0003_mitigation_decision_audit",
    ]


def test_later_migrations_do_not_target_traffic_table():
    versions_dir = BACKEND_DIR / "alembic" / "versions"
    later_migrations = (
        versions_dir / "0002_mitigation_policy_models.py",
        versions_dir / "0003_mitigation_decision_audit.py",
    )
    ddl_operations = (
        "create_table",
        "drop_table",
        "alter_column",
        "add_column",
        "drop_column",
        "create_index",
        "drop_index",
    )
    for path in later_migrations:
        source = path.read_text(encoding="utf-8")
        for operation in ddl_operations:
            assert f'op.{operation}(\n        "api_traffic_logs"' not in source
            assert f'op.{operation}("api_traffic_logs"' not in source
        assert 'table_name="api_traffic_logs"' not in source


def test_postgresql_offline_upgrade_emits_only_short_revision_markers(
    monkeypatch, capsys
):
    # Synthetic, credential-free URL on an unused loopback port: offline mode
    # renders SQL only and must never open a connection.
    monkeypatch.setattr(
        settings,
        "DATABASE_URL",
        "postgresql+psycopg2://offline@127.0.0.1:1/offline_only",
    )
    config = Config(str(ALEMBIC_INI))

    command.upgrade(config, "0001_baseline_existing_schema:head", sql=True)
    sql = capsys.readouterr().out

    markers = re.findall(r"UPDATE alembic_version SET version_num='([^']+)'", sql)
    assert markers == [
        "0002_mitigation_policy_models",
        "0003_mitigation_decision_audit",
        "0004_revoked_tokens",
    ]
    assert all(len(marker) <= 32 for marker in markers)
    assert markers[-1] == HEAD_REVISION

    created_tables = set(re.findall(r"^CREATE TABLE (\w+) \(", sql, flags=re.MULTILINE))
    assert created_tables == {
        "mitigation_policies",
        "mitigation_policy_state",
        "mitigation_policy_activation_events",
        "mitigation_decisions",
        "mitigation_audit_events",
        "revoked_tokens",
    }
    assert "api_traffic_logs" not in sql
