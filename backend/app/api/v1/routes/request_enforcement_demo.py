"""Dedicated isolated request-time enforcement demo endpoints (WP9).

All endpoints are demo-only, default OFF and loopback-only. They build an
in-process synthetic FastAPI harness with the accepted enforcement middleware;
no middleware is registered on the production application and no configured
database or real traffic is used.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from app.core.security import require_admin, require_analyst
from app.schemas.request_enforcement_demo import (
    RequestDemoDisableRequest,
    RequestDemoEnableRequest,
    RequestDemoEvidenceResponse,
    RequestDemoFailClosedResponse,
    RequestDemoRunRequest,
    RequestDemoRunResponse,
    RequestDemoStatusResponse,
)
from app.services.request_enforcement_demo_service import (
    RequestDemoGuardError,
    disable,
    enable,
    evidence,
    fail_closed,
    get_status,
    kill_switch,
    run,
)

router = APIRouter(
    prefix="/security/mitigation/request-enforcement-demo",
    tags=["Isolated Request Enforcement Demo"],
)
logger = logging.getLogger("apisentry.api.request_enforcement_demo")
_LOOPBACK_HOSTS = frozenset(
    {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}
)


def _ensure_loopback(request: Request) -> None:
    if _client_host(request) not in _LOOPBACK_HOSTS:
        raise HTTPException(status_code=403, detail="Loopback-only demo endpoint")


def _client_host(request: Request) -> str | None:
    client = request.client
    return client.host if client else None


def _target_host(request: Request) -> str | None:
    return request.url.hostname


def _guard_http(exc: RequestDemoGuardError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "request_demo_guard_rejected", "message": str(exc)},
    )


@router.get("/status", response_model=RequestDemoStatusResponse)
def demo_status(
    request: Request,
    analyst_user: Any = Depends(require_analyst),
) -> RequestDemoStatusResponse:
    _ensure_loopback(request)
    try:
        if _client_host(request) not in {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}:
            raise HTTPException(status_code=403, detail="Loopback-only demo endpoint")
        return RequestDemoStatusResponse(**get_status())
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo status failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/enable", response_model=RequestDemoStatusResponse)
def demo_enable(
    payload: RequestDemoEnableRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> RequestDemoStatusResponse:
    _ensure_loopback(request)
    try:
        result = enable(
            demo_id=payload.demo_id,
            policy_version=payload.policy_version,
            scenario=payload.scenario,
            client_host=_client_host(request),
            target_host=_target_host(request),
            max_requests=payload.max_requests,
            max_duration_seconds=payload.max_duration_seconds,
        )
        return RequestDemoStatusResponse(**result)
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except ValidationError:
        raise
    except Exception:
        logger.exception("request demo enable failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/run", response_model=RequestDemoRunResponse)
def demo_run(
    payload: RequestDemoRunRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> RequestDemoRunResponse:
    _ensure_loopback(request)
    try:
        result = run(
            demo_id=payload.demo_id,
            request_count=payload.request_count,
            client_host=_client_host(request),
        )
        return RequestDemoRunResponse(**result)
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo run failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/kill-switch", response_model=RequestDemoStatusResponse)
def demo_kill_switch(
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> RequestDemoStatusResponse:
    _ensure_loopback(request)
    try:
        return RequestDemoStatusResponse(**kill_switch(client_host=_client_host(request)))
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo kill switch failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/fail-closed", response_model=RequestDemoFailClosedResponse)
def demo_fail_closed(
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> RequestDemoFailClosedResponse:
    _ensure_loopback(request)
    try:
        return RequestDemoFailClosedResponse(**fail_closed(client_host=_client_host(request)))
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo fail-closed check failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.get("/evidence", response_model=RequestDemoEvidenceResponse)
def demo_evidence(
    request: Request,
    analyst_user: Any = Depends(require_analyst),
) -> RequestDemoEvidenceResponse:
    _ensure_loopback(request)
    try:
        if _client_host(request) not in {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}:
            raise HTTPException(status_code=403, detail="Loopback-only demo endpoint")
        return RequestDemoEvidenceResponse(**evidence(client_host=_client_host(request)))
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo evidence failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None


@router.post("/disable", response_model=RequestDemoStatusResponse)
def demo_disable(
    payload: RequestDemoDisableRequest,
    request: Request,
    admin_user: Any = Depends(require_admin),
) -> RequestDemoStatusResponse:
    _ensure_loopback(request)
    try:
        return RequestDemoStatusResponse(
            **disable(client_host=_client_host(request), reason=payload.reason)
        )
    except RequestDemoGuardError as exc:
        raise _guard_http(exc) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("request demo disable failed")
        raise HTTPException(status_code=500, detail="Internal server error.") from None
