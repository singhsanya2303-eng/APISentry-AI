"""Task 12A regression tests for legacy router demo-gating safety.

Only freshly created in-process FastAPI apps are inspected. No lifespan is
entered, no server is started, and no production enforcement is enabled.
"""

from __future__ import annotations

import secrets

from fastapi.testclient import TestClient

from app.api.v1.router import api_router
from app.core.config import settings
from app.main import create_app

_LEGACY_DEMO_PREFIXES = (
    "/security/mitigation/demo",
    "/security/mitigation/request-enforcement-demo",
)
_OPENAPI_DEMO_PREFIXES = tuple("/api/v1" + prefix for prefix in _LEGACY_DEMO_PREFIXES)
_NON_DEMO_PATHS = (
    "/api/v1/security/mitigation/analyze",
    "/api/v1/security/mitigation/enforcement/status",
    "/api/v1/health",
)


def _legacy_router_paths() -> set[str]:
    return {str(getattr(route, "path", "")) for route in api_router.routes}


def _openapi_paths(app) -> set[str]:
    return set((app.openapi().get("paths") or {}).keys())


def _has_demo_route(paths: set[str], prefixes: tuple[str, ...]) -> bool:
    return any(path.startswith(prefixes) for path in paths)


def test_legacy_module_router_never_contains_demo_control_routes() -> None:
    # conftest enables the demo flag before app.api.v1.router is imported, so
    # this proves an import-time demo opt-in is not captured by the legacy
    # compatibility router.
    assert not _has_demo_route(_legacy_router_paths(), _LEGACY_DEMO_PREFIXES)


def test_production_app_cannot_reuse_demo_enabled_app_state(monkeypatch) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "APISENTRY_ENABLE_DEMO_CONTROL_PLANE", True)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", secrets.token_urlsafe(32))

    demo_app = create_app()
    assert _has_demo_route(_openapi_paths(demo_app), _OPENAPI_DEMO_PREFIXES)

    # Same process, same settings object, but a fresh production app must
    # re-evaluate the gate and must not inherit the previous app's demo routes.
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    production_app = create_app()

    assert production_app is not demo_app
    production_paths = _openapi_paths(production_app)
    assert not _has_demo_route(production_paths, _OPENAPI_DEMO_PREFIXES)
    assert set(_NON_DEMO_PATHS).issubset(production_paths)

    health = TestClient(production_app).get("/health")
    assert health.status_code == 200
    assert health.json()["enforcement"]["mode"] == "advisory_only"
    assert health.json()["enforcement"]["production_middleware_registered"] is False
