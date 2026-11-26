"""Gate E isolated local enforcement demonstration endpoints.

All endpoints are demo-only, loopback-only, and default OFF. No production
enforcement is exposed here.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import require_admin, require_analyst
from app.db.session import get_db
from app.schemas.mitigation_demo import (
    DemoDisableRequest,
    DemoEnableRequest,
    DemoRunRequest,
    DemoRunResponse,
    DemoStatusResponse,
)
from app.services.mitigation_demo_service import (
    DemoGuardError,
    disable_demo,
    enable_demo,
    get_status,
    kill_switch,
    run_synthetic,
)
from app.api.v1.routes.mitigation_policy_admin import get_lifecycle_service

router = APIRouter(prefix="/security/mitigation/demo", tags=["Mitigation Demo Enforcement"])
logger = logging.getLogger("apisentry.api.mitigation_demo")


def _client_host(request: Request) -> str | None:
    client = request.client
    return client.host if client else None


def _target_host(request: Request) -> str | None:
    return request.url.hostname


def _guard_http(exc: DemoGuardError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "demo_guard_rejected", "message": str(exc)},
    )


@router.get("/status", response_model=DemoStatusResponse)
def demo_status(
    request: Request,
    analyst_user: Any = Depends(require_analyst),
) -> DemoStatusResponse:
    try:
        # status is safe to read; still enforce loopback source for demo control plane
        if _client_host(request) not in {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}:
            raise HTTPException(status_code=403, detail="Loopback-only demo endpoint")
        return DemoStatusResponse(**get_status())
    except HTTPException:
        raise
    except Exception:
        logger.exception("demo status failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/enable", response_model=DemoStatusResponse)
def demo_enable(
    payload: DemoEnableRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DemoStatusResponse:
    try:
        lifecycle = get_lifecycle_service()
        try:
            hydration = lifecycle.hydrate_from_persistence(db)
        except Exception:
            hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
        if not hydration.get("ok", False):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "mitigation_registry_inconsistent",
                    "message": "Mitigation registry consistency cannot be established; demo action rejected (fail-closed).",
                    "consistency_note": str(hydration.get("error") or "inconsistent"),
                },
            )
        status_payload = enable_demo(
            lifecycle=lifecycle,
            client_host=_client_host(request),
            target_host=_target_host(request),
            policy_version=payload.policy_version,
            max_requests=payload.max_requests,
            max_duration_seconds=payload.max_duration_seconds,
        )
        return DemoStatusResponse(**status_payload)
    except DemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("demo enable failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/disable", response_model=DemoStatusResponse)
def demo_disable(
    payload: DemoDisableRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> DemoStatusResponse:
    try:
        status_payload = disable_demo(client_host=_client_host(request), reason=payload.reason)
        return DemoStatusResponse(**status_payload)
    except DemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("demo disable failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/kill-switch", response_model=DemoStatusResponse)
def demo_kill_switch(
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> DemoStatusResponse:
    try:
        status_payload = kill_switch(client_host=_client_host(request))
        return DemoStatusResponse(**status_payload)
    except DemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("demo kill-switch failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/run", response_model=DemoRunResponse)
def demo_run(
    payload: DemoRunRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DemoRunResponse:
    try:
        lifecycle = get_lifecycle_service()
        try:
            hydration = lifecycle.hydrate_from_persistence(db)
        except Exception:
            hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
        if not hydration.get("ok", False):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "mitigation_registry_inconsistent",
                    "message": "Mitigation registry consistency cannot be established; demo action rejected (fail-closed).",
                    "consistency_note": str(hydration.get("error") or "inconsistent"),
                },
            )
        result = run_synthetic(
            lifecycle=lifecycle,
            client_host=_client_host(request),
            target_host=_target_host(request),
            demo_id=payload.demo_id,
            requests=payload.requests,
        )
        return DemoRunResponse(**result)
    except DemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("demo run failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None
