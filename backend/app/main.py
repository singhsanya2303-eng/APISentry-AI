
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import build_api_router
from app.core.config import settings
from app.core.operational_logging import log_operation
from app.core.security import cleanup_expired_revoked_tokens, seed_demo_user
from app.db import session as db_session_module
from app.db.init_db import init_db
from app.utils.middleware import (
    RequestLoggingMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)


logger = logging.getLogger("apisentry.operations")


def _auto_create_schema_enabled() -> bool:
    """Return whether startup may create schema objects (never in production)."""
    return bool(settings.AUTO_CREATE_SCHEMA) and not settings.is_production


def _cleanup_expired_revocations() -> None:
    """Run one best-effort startup cleanup; never block app startup on DB failure."""
    cleanup_session = None
    try:
        cleanup_session = db_session_module.SessionLocal()
        cleanup_expired_revoked_tokens(cleanup_session, force=True)
    except Exception:
        logger.warning("startup revocation cleanup skipped after failure", exc_info=True)
    finally:
        if cleanup_session is not None:
            try:
                cleanup_session.close()
            except Exception:
                logger.debug("startup revocation cleanup session close failed", exc_info=True)


def _revocation_store_status() -> str:
    """Report whether the durable logout revocation table is queryable.

    A missing or unusable revoked_tokens table must make readiness fail so an
    operator can apply migration 0004 before routing authenticated traffic.
    """
    try:
        from app.db.session import SessionLocal
        from app.models.revoked_token import RevokedToken

        db = SessionLocal()
        try:
            db.query(RevokedToken.id).limit(1).all()
            return "ok"
        finally:
            db.close()
    except Exception:
        logger.debug("revocation store readiness check failed", exc_info=True)
        return "unavailable"


def _request_enforcement_registered(application: FastAPI) -> bool:
    """Report whether request-time enforcement middleware is registered."""
    return any(
        getattr(getattr(item, "cls", None), "__name__", "") == "RequestEnforcementMiddleware"
        for item in application.user_middleware
    )


def _enforcement_status(application: FastAPI) -> dict[str, object]:
    registered = _request_enforcement_registered(application)
    return {
        "mode": "request_enforcement" if registered else "advisory_only",
        "production_middleware_registered": registered,
        "isolated_demo_available": True,
    }


def create_app(cors_origins=None):
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        log_operation(
            logger,
            "app.startup",
            **settings.deployment_summary(),
            auto_create_schema_enabled=_auto_create_schema_enabled(),
            request_enforcement_middleware_registered=_request_enforcement_registered(application),
        )
        try:
            if _auto_create_schema_enabled():
                init_db()
            _cleanup_expired_revocations()
            yield
        finally:
            log_operation(
                logger,
                "app.shutdown",
                environment=settings.ENVIRONMENT,
                request_enforcement_middleware_registered=_request_enforcement_registered(application),
            )

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Use supplied origins for tests; otherwise use application settings.
    origins = list(
        settings.CORS_ORIGINS
        if cors_origins is None
        else cors_origins
    )
    if not settings.is_production:
        for origin in (
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:5174",
            "http://localhost:5174",
        ):
            if origin not in origins:
                origins.append(origin)

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
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=settings.MAX_REQUEST_BODY_BYTES)

    app.include_router(
        build_api_router(),
        prefix=settings.API_V1_STR,
    )

    # Conditionally mount local demo authentication endpoint (development only)
    if settings.is_demo_auth_enabled:
        seed_demo_user()
        from app.api.v1.routes.demo_auth import router as demo_auth_router

        app.include_router(
            demo_auth_router,
            prefix="/demo/auth",
        )

    @app.get("/health", tags=["Health"])
    def health_check():
        """Liveness endpoint returning service status and enforcement mode."""
        return {
            "status": "healthy",
            "service": settings.PROJECT_NAME,
            "environment": settings.ENVIRONMENT,
            "enforcement": _enforcement_status(app),
        }

    @app.get("/ready", tags=["Health"])
    def readiness_check():
        """Readiness endpoint with minimal dependency checks (no secrets)."""
        checks = {"database": "unknown", "revocation_store": "unknown"}
        try:
            from sqlalchemy import text
            from app.db.session import SessionLocal

            db = SessionLocal()
            try:
                db.execute(text("SELECT 1"))
                checks["database"] = "ok"
            finally:
                db.close()
            checks["revocation_store"] = _revocation_store_status()
        except Exception:
            checks["database"] = "unavailable"
            checks["revocation_store"] = "unavailable"

        ready = all(v == "ok" for v in checks.values())
        payload = {
            "status": "ready" if ready else "not_ready",
            "service": settings.PROJECT_NAME,
            "environment": settings.ENVIRONMENT,
            "enforcement": _enforcement_status(app),
            "checks": checks,
        }
        if not ready:
            log_operation(logger, "app.readiness_failed", environment=settings.ENVIRONMENT, checks=checks)
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=503, content=payload)
        return payload

    @app.get("/", tags=["Root"])
    def root():
        """Root endpoint returning API metadata."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs": "/docs",
            "health": "/health",
        }

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        from fastapi.encoders import jsonable_encoder
        from app.core.security_events import redact_sensitive

        def _loc_has_sensitive(loc) -> bool:
            if not isinstance(loc, (list, tuple)):
                return False
            sensitive_markers = ("password", "token", "secret", "api_key", "authorization", "credential")
            for part in loc:
                p = str(part).lower()
                if any(m in p for m in sensitive_markers):
                    return True
            return False

        errors = []
        for err in exc.errors():
            cleaned = dict(err)
            loc = cleaned.get("loc")
            if "input" in cleaned:
                if _loc_has_sensitive(loc):
                    cleaned["input"] = "***REDACTED***"
                else:
                    cleaned["input"] = redact_sensitive(cleaned["input"])
            ctx = cleaned.get("ctx")
            if isinstance(ctx, dict):
                cleaned["ctx"] = redact_sensitive(ctx)
            errors.append(jsonable_encoder(cleaned))
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Never leak internals; log a structured, redacted server-side record.
        log_operation(
            logger,
            "app.unhandled_error",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            request_id=getattr(request.state, "request_id", None),
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()
