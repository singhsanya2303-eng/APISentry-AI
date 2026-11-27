"""Regression tests for the fail-closed public registration policy."""

from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.main import app
from app.services.user_service import get_user_by_email

client = TestClient(app)


def _registration_payload(email: str, username: str, role: str | None = None) -> dict:
    payload = {
        "email": email,
        "username": username,
        "password": "SecurePass123!",
    }
    if role is not None:
        payload["role"] = role
    return payload


def _production_kwargs(**overrides) -> dict:
    configured = {
        "ENVIRONMENT": "production",
        "JWT_SECRET_KEY": secrets.token_urlsafe(32),
        "CORS_ORIGINS": ["https://app.example.test"],
        "DATABASE_URL": "postgresql://app_user:not-a-real-secret@db.example.test:5432/app_db",
        "APISENTRY_ENABLE_PUBLIC_REGISTRATION": False,
        "_env_file": None,
    }
    configured.update(overrides)
    return configured


def test_public_registration_is_disabled_by_default() -> None:
    configured = Settings(_env_file=None)

    assert configured.APISENTRY_ENABLE_PUBLIC_REGISTRATION is False
    assert configured.is_public_registration_enabled is False


def test_registration_is_rejected_when_disabled(
    testing_session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_PUBLIC_REGISTRATION", False)

    response = client.post(
        "/api/v1/auth/register",
        json=_registration_payload("closed@example.com", "closed_user"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Public registration is disabled"

    db = testing_session_factory()
    try:
        assert get_user_by_email(db, "closed@example.com") is None
    finally:
        db.close()


def test_registration_is_enabled_only_by_explicit_configuration(
    testing_session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_PUBLIC_REGISTRATION", True)

    response = client.post(
        "/api/v1/auth/register",
        json=_registration_payload("open@example.com", "open_user", role="admin"),
    )

    assert response.status_code == 201
    assert response.json()["role"] == "viewer"

    db = testing_session_factory()
    try:
        persisted = get_user_by_email(db, "open@example.com")
        assert persisted is not None
        assert persisted.role == "viewer"
    finally:
        db.close()


def test_login_and_profile_still_work_when_registration_is_disabled(
    testing_session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_PUBLIC_REGISTRATION", True)
    registered = client.post(
        "/api/v1/auth/register",
        json=_registration_payload("login@example.com", "login_user"),
    )
    assert registered.status_code == 201

    monkeypatch.setattr(settings, "APISENTRY_ENABLE_PUBLIC_REGISTRATION", False)
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "login_user", "password": "SecurePass123!"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    profile = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert profile.status_code == 200
    assert profile.json()["role"] == "viewer"


def test_production_requires_explicit_registration_setting() -> None:
    kwargs = _production_kwargs()
    kwargs.pop("APISENTRY_ENABLE_PUBLIC_REGISTRATION")

    with pytest.raises(ValidationError, match="APISENTRY_ENABLE_PUBLIC_REGISTRATION"):
        Settings(**kwargs)


def test_production_rejects_registration_opt_in() -> None:
    with pytest.raises(ValidationError, match="APISENTRY_ENABLE_PUBLIC_REGISTRATION"):
        Settings(**_production_kwargs(APISENTRY_ENABLE_PUBLIC_REGISTRATION=True))


def test_production_rejects_invalid_registration_setting() -> None:
    with pytest.raises(ValidationError):
        Settings(**_production_kwargs(APISENTRY_ENABLE_PUBLIC_REGISTRATION="maybe"))


def test_production_registration_is_never_enabled() -> None:
    configured = Settings(**_production_kwargs(APISENTRY_ENABLE_PUBLIC_REGISTRATION=False))

    assert configured.is_production
    assert configured.APISENTRY_ENABLE_PUBLIC_REGISTRATION is False
    assert configured.is_public_registration_enabled is False
