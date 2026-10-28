
from fastapi import APIRouter
from fastapi import APIRouter, Depends
from app.core.security import require_api_key
from app.core.config import settings
from app.api.v1.routes.bola import router as bola_router
from app.api.v1.routes.bruteforce import router as bruteforce_router
from app.api.v1.routes.rate_anomaly import router as rate_anomaly_router
from app.api.v1.routes.behavior import router as behavior_router
from app.api.v1.routes.token_classifier import router as token_classifier_router
from app.api.v1.routes.traffic_trends import router as traffic_trends_router
from app.api.v1.routes.clustering import router as clustering_router
api_router = APIRouter()

# Existing security analysis routes
api_router.include_router(
    bola_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    bruteforce_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    rate_anomaly_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    behavior_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    clustering_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    token_classifier_router,
    dependencies=[Depends(require_api_key)],
)
api_router.include_router(
    traffic_trends_router,
    dependencies=[Depends(require_api_key)],
)

# Machine-learning prediction route
api_router.include_router(token_classifier_router)

# Traffic trend anomaly detection using Stacked Autoencoder
api_router.include_router(traffic_trends_router)


@api_router.get("/health", tags=["Health"])
def health_check():
    """V1 API health check endpoint returning service status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
    }
