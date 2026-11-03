
from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.security import require_api_key

from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.bola import router as bola_router
from app.api.v1.routes.bruteforce import router as bruteforce_router
from app.api.v1.routes.rate_anomaly import router as rate_anomaly_router
from app.api.v1.routes.behavior import router as behavior_router
from app.api.v1.routes.clustering import router as clustering_router
from app.api.v1.routes.token_classifier import (
    router as token_classifier_router,
)
from app.api.v1.routes.traffic_trends import (
    router as traffic_trends_router,
)

api_router = APIRouter()

# Mount end-user authentication and user profile/resource endpoints
api_router.include_router(auth_router)

# All security analysis routes
protected_routers = [
    bola_router,
    bruteforce_router,
    rate_anomaly_router,
    behavior_router,
    clustering_router,
    token_classifier_router,
    traffic_trends_router,
]


# Register each analysis router once with API key authentication
for route_router in protected_routers:
    api_router.include_router(
        route_router,
        dependencies=[Depends(require_api_key)],
    )


@api_router.get("/health", tags=["Health"])
def health_check():
    """Return API service health."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
    }
