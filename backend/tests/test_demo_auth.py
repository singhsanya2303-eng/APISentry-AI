"""
Tests for Local Demo Authentication Endpoint — Demonstration and Safety Verification.

Covers:
  1. Disabled by default behaviour (returns 404).
  2. Production safety guard (disabled in production even if flag is True).
  3. Deliberately invalid credentials return HTTP 401 Unauthorized.
  4. Valid demo credentials return HTTP 200 OK.
  5. Missing/invalid schema returns HTTP 422.
  6. Middleware integration (X-Request-ID and X-Process-Time attached).
  7. Detector pattern recognition for /demo/auth/login.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import create_app
from app.detection.bruteforce_detector import (
    _DEFAULT_AUTH_PATH_PATTERNS,
    _is_auth_endpoint,
)


@pytest.fixture(autouse=True)
def configure_demo_credentials(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_USERNAME", "demo_user")
    monkeypatch.setattr(settings, "DEMO_PASSWORD", "demo_password123")



def test_demo_auth_disabled_by_default(monkeypatch):
    """When APISENTRY_ENABLE_DEMO_AUTH is False, the endpoint is not registered (404)."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    test_app = create_app()
    client = TestClient(test_app)

    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user", "password": "wrong_password"},
    )
    assert response.status_code == 404


def test_demo_auth_blocked_in_production(monkeypatch):
    """When ENVIRONMENT is production, demo endpoint is strictly disabled (404)."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    assert settings.is_demo_auth_enabled is False

    test_app = create_app()
    client = TestClient(test_app)

    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user", "password": "wrong_password"},
    )
    assert response.status_code == 404


def test_demo_auth_invalid_credentials_returns_401(monkeypatch):
    """When enabled, deliberately invalid credentials return HTTP 401 with WWW-Authenticate header."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    test_app = create_app()
    client = TestClient(test_app)

    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user", "password": "wrong_password_test"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Bearer"
    data = response.json()
    assert "Invalid credentials" in data["detail"]


def test_demo_auth_valid_credentials_returns_200(monkeypatch):
    """When enabled, correct demo credentials return HTTP 200."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    test_app = create_app()
    client = TestClient(test_app)

    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user", "password": "demo_password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is True
    assert data["demo_mode"] is True


def test_demo_auth_validation_error_returns_422(monkeypatch):
    """Malformed payload returns HTTP 422."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    test_app = create_app()
    client = TestClient(test_app)

    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user"},  # missing password
    )
    assert response.status_code == 422


def test_demo_auth_middleware_integration(monkeypatch):
    """Verify that requests pass through RequestLoggingMiddleware and receive tracking headers."""
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_AUTH", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    test_app = create_app()
    client = TestClient(test_app)

    custom_id = "test-req-demo-12345"
    response = client.post(
        "/demo/auth/login",
        json={"username": "demo_user", "password": "wrong_password"},
        headers={"X-Request-ID": custom_id},
    )
    assert response.headers.get("X-Request-ID") == custom_id
    assert "X-Process-Time" in response.headers


def test_demo_auth_path_recognized_by_detector():
    """Verify that /demo/auth/login is recognized by _DEFAULT_AUTH_PATH_PATTERNS."""
    assert "/demo/auth/login" in _DEFAULT_AUTH_PATH_PATTERNS
    assert _is_auth_endpoint("/demo/auth/login", _DEFAULT_AUTH_PATH_PATTERNS) is True
    assert _is_auth_endpoint("/DEMO/AUTH/LOGIN", _DEFAULT_AUTH_PATH_PATTERNS) is True
    assert _is_auth_endpoint("/demo/auth/login/", _DEFAULT_AUTH_PATH_PATTERNS) is True
    # Non-login variants must NOT match
    assert _is_auth_endpoint("/demo/auth", _DEFAULT_AUTH_PATH_PATTERNS) is False
    assert _is_auth_endpoint("/demo/auth/status", _DEFAULT_AUTH_PATH_PATTERNS) is False
