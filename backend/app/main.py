
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.init_db import init_db
from app.utils.middleware import RequestLoggingMiddleware


def create_app(cors_origins=None):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        yield

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Use supplied origins for tests; otherwise use application settings.
    origins = (
        settings.CORS_ORIGINS
        if cors_origins is None
        else cors_origins
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Request-ID",
        ],
    )

    app.add_middleware(RequestLoggingMiddleware)

    app.include_router(
        api_router,
        prefix=settings.API_V1_STR,
    )

    @app.get("/health", tags=["Health"])
    def health_check():
        """Health check endpoint returning service status."""
        return {
            "status": "healthy",
            "service": settings.PROJECT_NAME,
        }

    @app.get("/", tags=["Root"])
    def root():
        """Root endpoint returning API metadata."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs": "/docs",
            "health": "/health",
        }

    return app


app = create_app()
