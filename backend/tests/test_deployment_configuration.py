"""WP13 deployment configuration, structured logging and health checks."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.operational_logging import format_log_event, log_operation
from app.main import app, create_app

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_env_example_is_present_and_contains_no_real_secret() -> None:
    example = REPO_ROOT / "backend" / ".env.example"
    assert example.exists()
    text = example.read_text(encoding="utf-8")
    for key in (
        "ENVIRONMENT=",
        "JWT_SECRET_KEY=",
        "CORS_ORIGINS=",
        "MAX_REQUEST_BODY_BYTES=",
        "AUTH_RATE_LIMIT_ENABLED=",
        "AUTO_CREATE_SCHEMA=",
        "APISENTRY_ENABLE_PUBLIC_REGISTRATION=",
    ):
        assert key in text
    assert "REPLACE_WITH_" in text
    assert "postgres://" not in text
    assert "postgresql://" not in text


def test_settings_reject_unbounded_runtimes_and_invalid_origins() -> None:
    with pytest.raises(ValidationError, match="MAX_REQUEST_BODY_BYTES"):
        Settings(MAX_REQUEST_BODY_BYTES=16, _env_file=None)
    with pytest.raises(ValidationError, match="JWT_ACCESS_TOKEN_EXPIRE_MINUTES"):
        Settings(JWT_ACCESS_TOKEN_EXPIRE_MINUTES=0, _env_file=None)
    with pytest.raises(ValidationError, match="AUTH_RATE_LIMIT_REQUESTS"):
        Settings(AUTH_RATE_LIMIT_REQUESTS=0, _env_file=None)
    with pytest.raises(ValidationError, match="AUTH_RATE_LIMIT_WINDOW_SECONDS"):
        Settings(AUTH_RATE_LIMIT_WINDOW_SECONDS=0, _env_file=None)
    with pytest.raises(ValidationError, match="http"):
        Settings(CORS_ORIGINS=["app.example.com"], _env_file=None)


def test_deployment_summary_never_contains_secret_values() -> None:
    configured = Settings(
        JWT_SECRET_KEY="a-local-only-secret-value-that-is-long-enough-123456789",
        API_KEY="service-key-value",
        DATABASE_URL="postgresql://user:db-password@db.internal:5432/appdb",
        _env_file=None,
    )
    text = json.dumps(configured.deployment_summary())
    assert "a-local-only-secret" not in text
    assert "service-key-value" not in text
    assert "db-password" not in text
    assert "postgresql://" not in text
    assert configured.deployment_summary()["enforcement_mode"] == "advisory_only"
    assert configured.deployment_summary()["production_request_middleware_registered"] is False


def test_structured_events_are_json_and_redact_sensitive_fields(caplog: pytest.LogCaptureFixture) -> None:
    parsed = json.loads(
        format_log_event(
            "app.test",
            password="supersecret",
            api_key="key-value",
            database_url="postgresql://u:p@h/db",
            safe_field="visible",
        )
    )
    assert parsed["event"] == "app.test"
    assert parsed["safe_field"] == "visible"
    assert parsed["password"] == "***REDACTED***"
    assert parsed["api_key"] == "***REDACTED***"
    assert parsed["database_url"] == "***REDACTED***"

    logger = logging.getLogger("apisentry.operations")
    with caplog.at_level(logging.INFO, logger="apisentry.operations"):
        log_operation(logger, "app.test", token="must-not-appear", status="ok")
    record = caplog.records[-1]
    emitted = json.loads(record.message)
    assert emitted["event"] == "app.test"
    assert emitted["status"] == "ok"
    assert "must-not-appear" not in record.getMessage()


def test_health_reports_advisory_only_enforcement() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["enforcement"]["mode"] == "advisory_only"
    assert body["enforcement"]["production_middleware_registered"] is False
    assert not any(
        getattr(getattr(item, "cls", None), "__name__", "") == "RequestEnforcementMiddleware"
        for item in app.user_middleware
    )


def test_lifespan_emits_startup_and_shutdown_events(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("app.main.init_db", MagicMock())
    local = create_app()
    with caplog.at_level(logging.INFO, logger="apisentry.operations"):
        with TestClient(local):
            pass
    events = []
    for record in caplog.records:
        if record.name == "apisentry.operations":
            parsed = json.loads(record.message)
            if parsed.get("event") in {"app.startup", "app.shutdown"}:
                events.append(parsed)
    startup = [item for item in events if item["event"] == "app.startup"]
    shutdown = [item for item in events if item["event"] == "app.shutdown"]
    assert len(startup) == 1
    assert len(shutdown) == 1
    assert startup[0]["enforcement_mode"] == "advisory_only"
    assert startup[0]["request_enforcement_middleware_registered"] is False
    assert shutdown[0]["request_enforcement_middleware_registered"] is False


def test_readiness_failure_is_structured_and_has_generic_response(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken_session():
        raise RuntimeError("db-password-in-internal-error")

    monkeypatch.setattr("app.db.session.SessionLocal", broken_session)
    with caplog.at_level(logging.INFO, logger="apisentry.operations"):
        response = TestClient(create_app()).get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "unavailable"
    assert "db-password" not in response.text
    failures = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "apisentry.operations" and '"app.readiness_failed"' in record.message
    ]
    assert failures
    assert failures[-1]["checks"]["database"] == "unavailable"
