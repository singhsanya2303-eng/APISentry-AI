"""Regression tests for durable logout revocation in production.

All sessions come from isolated in-memory SQLite fixtures. No real database,
migration, or external service is contacted.
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.main as main_module
from app.core.config import settings
from app.core.security import (
    _REVOKED_TOKEN_EXPIRY,
    _REVOKED_TOKENS,
    create_access_token,
    decode_access_token,
    is_token_revoked,
    revoke_token,
)
from app.db.session import get_db
from app.main import create_app
from sqlalchemy.exc import OperationalError


@pytest.fixture(autouse=True)
def _isolated_revocation_state():
    _REVOKED_TOKENS.clear()
    _REVOKED_TOKEN_EXPIRY.clear()
    yield
    _REVOKED_TOKENS.clear()
    _REVOKED_TOKEN_EXPIRY.clear()


class _MissingTableQuery:
    def filter(self, *args, **kwargs):
        return self

    def first(self):
        raise OperationalError(
            "SELECT 1", {}, Exception("no such table: revoked_tokens")
        )


def test_missing_revocation_store_fails_closed_in_production(
    testing_session_factory, monkeypatch
):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    token = create_access_token(
        subject="prod-revocation-user",
        extra_claims={"username": "prod-revocation-user", "role": "viewer"},
    )
    db = testing_session_factory()
    try:
        monkeypatch.setattr(db, "query", lambda *args, **kwargs: _MissingTableQuery())
        assert is_token_revoked(token, db=db) is True
        with pytest.raises(ValueError, match="revoked"):
            decode_access_token(token, db=db)
    finally:
        db.close()


def test_revoke_token_rejects_failed_persistence_in_production(
    testing_session_factory, monkeypatch
):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    token = create_access_token(
        subject="prod-logout-user",
        extra_claims={"username": "prod-logout-user", "role": "viewer"},
    )
    db = testing_session_factory()
    try:

        def _write_failure(*args, **kwargs):
            raise RuntimeError("revoked_tokens write failed")

        monkeypatch.setattr(db, "add", _write_failure)
        with pytest.raises(HTTPException) as raised:
            revoke_token(token, db=db)
        assert raised.value.status_code == 503
        assert "revocation" in raised.value.detail.lower()
    finally:
        db.close()


def test_logout_route_fails_closed_when_durable_revocation_write_fails(
    testing_session_factory, monkeypatch
):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    token = create_access_token(
        subject="prod-logout-route-user",
        extra_claims={"username": "prod-logout-route-user", "role": "viewer"},
    )
    db = testing_session_factory()

    def _write_failure(*args, **kwargs):
        raise RuntimeError("revoked_tokens write failed")

    monkeypatch.setattr(db, "add", _write_failure)

    def _override_get_db():
        yield db

    production_app = create_app()
    production_app.dependency_overrides[get_db] = _override_get_db
    try:
        response = TestClient(production_app).post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        production_app.dependency_overrides.pop(get_db, None)
        db.close()

    assert response.status_code == 503
    assert "revocation" in str(response.json().get("detail", "")).lower()


def test_readiness_surfaces_unusable_revocation_store(monkeypatch):
    monkeypatch.setattr(
        main_module, "_revocation_store_status", lambda: "unavailable"
    )
    response = TestClient(create_app()).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["revocation_store"] == "unavailable"


def test_revocation_store_probe_reports_query_failure(monkeypatch):
    def broken_session():
        raise RuntimeError("no such table: revoked_tokens")

    monkeypatch.setattr("app.db.session.SessionLocal", broken_session)
    assert main_module._revocation_store_status() == "unavailable"
