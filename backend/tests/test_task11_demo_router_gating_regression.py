"""Task 11 regression tests for demo control-plane router gating.

Only freshly created in-process FastAPI apps are inspected. No lifespan is
entered, no server is started, and no production enforcement is enabled.
"""

from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, settings
from app.main import create_app

GATE_E_PATHS = (
    "/api/v1/security/mitigation/demo/status",
    "/api/v1/security/mitigation/demo/enable",
    "/api/v1/security/mitigation/demo/disable",
    "/api/v1/security/mitigation/demo/kill-switch",
    "/api/v1/security/mitigation/demo/run",
)
WP9_PATHS = (
    "/api/v1/security/mitigation/request-enforcement-demo/status",
    "/api/v1/security/mitigation/request-enforcement-demo/enable",
    "/api/v1/security/mitigation/request-enforcement-demo/run",
    "/api/v1/security/mitigation/request-enforcement-demo/kill-switch",
    "/api/v1/security/mitigation/request-enforcement-demo/fail-closed",
    "/api/v1/security/mitigation/request-enforcement-demo/evidence",
    "/api/v1/security/mitigation/request-enforcement-demo/disable",
)
NON_DEMO_PATHS = (
    "/api/v1/security/mitigation/analyze",
    "/api/v1/security/mitigation/enforcement/status",
    "/api/v1/health",
)


def _paths(app) -> set[str]:
    return set((app.openapi().get("paths") or {}).keys())


def _configure(monkeypatch, *, environment: str, demo_enabled: bool) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", environment)
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_CONTROL_PLANE", demo_enabled)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", secrets.token_urlsafe(32))


def test_config_gate_is_explicit_and_never_enabled_in_production(monkeypatch) -> None:
    # Conftest opts the test process into demo routes; inspect the real default.
    monkeypatch.delenv("APISENTRY_ENABLE_DEMO_CONTROL_PLANE", raising=False)

    production = Settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY=secrets.token_urlsafe(32),
        APISENTRY_ENABLE_DEMO_CONTROL_PLANE=True,
        _env_file=None,
    )
    development_default = Settings(ENVIRONMENT="development", _env_file=None)
    development_opt_in = Settings(
        ENVIRONMENT="development",
        APISENTRY_ENABLE_DEMO_CONTROL_PLANE=True,
        _env_file=None,
    )

    assert production.is_demo_control_plane_enabled is False
    assert development_default.is_demo_control_plane_enabled is False
    assert development_opt_in.is_demo_control_plane_enabled is True


def test_production_never_mounts_gate_e_or_wp9_demo_routes(monkeypatch) -> None:
    _configure(monkeypatch, environment="production", demo_enabled=True)

    paths = _paths(create_app())

    assert set(GATE_E_PATHS).isdisjoint(paths)
    assert set(WP9_PATHS).isdisjoint(paths)
    assert set(NON_DEMO_PATHS).issubset(paths)


def test_forwarded_loopback_headers_cannot_expose_production_demo_routes(monkeypatch) -> None:
    _configure(monkeypatch, environment="production", demo_enabled=True)
    local_app = create_app()
    client = TestClient(local_app, base_url="http://127.0.0.1")

    for path in (GATE_E_PATHS[0], WP9_PATHS[0]):
        response = client.get(
            path,
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Forwarded-Host": "localhost",
            },
        )
        assert response.status_code == 404


def test_non_production_default_keeps_demo_routes_unmounted(monkeypatch) -> None:
    _configure(monkeypatch, environment="development", demo_enabled=False)

    paths = _paths(create_app())

    assert set(GATE_E_PATHS).isdisjoint(paths)
    assert set(WP9_PATHS).isdisjoint(paths)
    assert set(NON_DEMO_PATHS).issubset(paths)


def test_explicit_non_production_opt_in_mounts_demo_routes(monkeypatch) -> None:
    _configure(monkeypatch, environment="development", demo_enabled=True)

    paths = _paths(create_app())

    assert set(GATE_E_PATHS).issubset(paths)
    assert set(WP9_PATHS).issubset(paths)
    assert set(NON_DEMO_PATHS).issubset(paths)


def test_production_enforcement_stays_disabled(monkeypatch) -> None:
    _configure(monkeypatch, environment="production", demo_enabled=True)
    local_app = create_app()

    health = TestClient(local_app).get("/health").json()
    assert health["enforcement"]["mode"] == "advisory_only"
    assert health["enforcement"]["production_middleware_registered"] is False
    assert not any(
        getattr(getattr(item, "cls", None), "__name__", "") == "RequestEnforcementMiddleware"
        for item in local_app.user_middleware
    )
