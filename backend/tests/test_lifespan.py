import importlib
import secrets
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import _auto_create_schema_enabled, app

init_db_module = importlib.import_module("app.db.init_db")


def _set_schema_gate(monkeypatch, environment="development", enabled=True):
    monkeypatch.setattr("app.main.settings.ENVIRONMENT", environment)
    monkeypatch.setattr("app.main.settings.AUTO_CREATE_SCHEMA", enabled)


def test_lifespan_triggers_init_db_without_connecting(monkeypatch):
    """
    Verify that FastAPI lifespan startup executes init_db() exactly once,
    safely isolated from PostgreSQL using monkeypatch.
    """
    mock_init_db = MagicMock()
    monkeypatch.setattr("app.main.init_db", mock_init_db)
    _set_schema_gate(monkeypatch)

    with TestClient(app) as client:
        mock_init_db.assert_called_once()
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


def test_lifespan_skips_init_db_when_auto_create_disabled(monkeypatch):
    mock_init_db = MagicMock()
    monkeypatch.setattr("app.main.init_db", mock_init_db)
    _set_schema_gate(monkeypatch, enabled=False)

    with TestClient(app) as client:
        mock_init_db.assert_not_called()
        assert client.get("/health").status_code == 200


def test_production_startup_never_calls_init_db(monkeypatch):
    """Production is protected even if AUTO_CREATE_SCHEMA is left enabled."""
    mock_init_db = MagicMock()
    monkeypatch.setattr("app.main.init_db", mock_init_db)
    _set_schema_gate(monkeypatch, environment="production", enabled=True)

    with TestClient(app) as client:
        mock_init_db.assert_not_called()
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize(
    ("environment", "enabled", "expected"),
    [
        ("development", True, True),
        ("development", False, False),
        ("test", True, True),
        (" PRODUCTION ", True, False),
        ("production", False, False),
    ],
)
def test_auto_create_schema_enabled_helper(monkeypatch, environment, enabled, expected):
    _set_schema_gate(monkeypatch, environment=environment, enabled=enabled)
    assert _auto_create_schema_enabled() is expected


def test_init_db_refuses_production_before_any_schema_operation(monkeypatch):
    fake_engine = MagicMock()
    mock_create_all = MagicMock()
    monkeypatch.setattr(init_db_module, "engine", fake_engine)
    monkeypatch.setattr(init_db_module.Base.metadata, "create_all", mock_create_all)
    monkeypatch.setattr(init_db_module.settings, "ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="production"):
        init_db_module.init_db()

    mock_create_all.assert_not_called()
    fake_engine.begin.assert_not_called()


def test_production_settings_force_auto_create_schema_off():
    configured = Settings(
        ENVIRONMENT=" production ",
        JWT_SECRET_KEY=secrets.token_urlsafe(32),
        AUTO_CREATE_SCHEMA=True,
    )

    assert configured.ENVIRONMENT == "production"
    assert configured.AUTO_CREATE_SCHEMA is False


def test_development_settings_keep_auto_create_schema_enabled():
    configured = Settings(ENVIRONMENT="development", AUTO_CREATE_SCHEMA=True)

    assert configured.AUTO_CREATE_SCHEMA is True
