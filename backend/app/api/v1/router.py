from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.security import require_analyst_or_api_key

from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.users import router as users_router
from app.api.v1.routes.bola import router as bola_router
from app.api.v1.routes.bruteforce import router as bruteforce_router
from app.api.v1.routes.rate_anomaly import router as rate_anomaly_router
from app.api.v1.routes.behavior import router as behavior_router
from app.api.v1.routes.bot_detection import router as bot_detection_router
from app.api.v1.routes.mitigation_analysis import router as mitigation_analysis_router
from app.api.v1.routes.mitigation_policy_admin import router as mitigation_policy_admin_router
from app.api.v1.routes.mitigation_decision_audit import router as mitigation_decision_audit_router
from app.api.v1.routes.mitigation_dry_run import router as mitigation_dry_run_router
from app.api.v1.routes.mitigation_demo import router as mitigation_demo_router
from app.api.v1.routes.request_enforcement_demo import (
    router as request_enforcement_demo_router,
)
from app.api.v1.routes.clustering import router as clustering_router
from app.api.v1.routes.token_classifier import (
    router as token_classifier_router,
)
from app.api.v1.routes.traffic_trends import (
    router as traffic_trends_router,
)
from app.api.v1.routes.http_payload_classifier import (
    router as http_payload_classifier_router,
)


def build_api_router(*, include_demo_routes: bool = True) -> APIRouter:
    """Build the production API router with demo control-plane routes gated.

    Gate E and WP9 demo routers are mounted only when the explicit
    ``APISENTRY_ENABLE_DEMO_CONTROL_PLANE`` flag is set in a non-production
    environment. Production configuration can never mount them, regardless of
    request headers, client address, or ``include_demo_routes``.

    ``include_demo_routes=False`` is used only by the backward-compatible
    module-level router so an import-time snapshot can never expose demo
    control planes. Supported applications call ``create_app()``, which uses
    the default and therefore evaluates per-app configuration at creation time.
    """
    api = APIRouter()

    # Mount end-user authentication and user profile endpoints
    api.include_router(auth_router)

    # Mount user administration endpoints (Admin RBAC protected)
    api.include_router(users_router)

    # Gate C authenticated mitigation administration/history endpoints.
    # Each router declares its own require_admin/require_analyst dependencies.
    api.include_router(mitigation_policy_admin_router)
    api.include_router(mitigation_decision_audit_router)
    api.include_router(mitigation_dry_run_router)

    # Gate E / WP9 isolated demo control planes: explicit non-production opt-in
    # required. Request-time loopback checks remain defence in depth only.
    # ``include_demo_routes=False`` is a permanent opt-out for the legacy
    # import-time router; it cannot override the production settings gate.
    if include_demo_routes and settings.is_demo_control_plane_enabled:
        api.include_router(mitigation_demo_router)
        api.include_router(request_enforcement_demo_router)

    # All security analysis routes
    protected_routers = [
        bola_router,
        bruteforce_router,
        rate_anomaly_router,
        behavior_router,
        bot_detection_router,
        mitigation_analysis_router,
        clustering_router,
        token_classifier_router,
        traffic_trends_router,
        http_payload_classifier_router,
    ]

    # Register each analysis router once with dual authentication:
    # a valid X-API-Key, or a JWT belonging to an admin/analyst user.
    for route_router in protected_routers:
        api.include_router(
            route_router,
            dependencies=[Depends(require_analyst_or_api_key)],
        )

    @api.get("/health", tags=["Health"])
    def health_check():
        """Return API service health."""
        return {
            "status": "healthy",
            "service": settings.PROJECT_NAME,
        }

    return api


# Backward-compatible module-level router. It intentionally excludes demo
# control planes because it is built once at import time. Applications should
# call ``create_app()`` / ``build_api_router()`` so the demo-control-plane gate
# is evaluated at app creation time rather than once at import time.
api_router = build_api_router(include_demo_routes=False)
