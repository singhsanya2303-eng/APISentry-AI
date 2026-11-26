"""Protected Mitigation Analysis API Route — Stage 2C Phase 4 Stage B.

Endpoint:
    GET /api/v1/security/mitigation/analyze

Combines the accepted Stage 1 bot detection response with advisory-only Stage A
mitigation outcomes. The route owns the outer transaction and commits once after
successful orchestration and audit integration. No enforcement or policy
administration is performed here.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.v1.routes.bot_detection import analyze_bot_traffic
from app.db.session import get_db
from app.schemas.bot_detection import BotDetectionResponse
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationIntegrationResult,
    VerifiedMitigationPrincipal,
)
from app.services.mitigation_audit_integration_service import (
    persist_decision_audit_events,
)
from app.services.mitigation_integration_service import (
    evaluate_and_persist_bot_detection,
)
from app.schemas.mw4_runtime import MW4RuntimeAnalysisResponse
from app.services.mw4_runtime_orchestration_service import orchestrate_mw4_runtime

router = APIRouter(prefix="/security/mitigation", tags=["Mitigation Analysis"])
logger = logging.getLogger("apisentry.api.mitigation_analysis")

_ACTOR_HASH_DOMAIN = "apisentry:mitigation:jwt-actor:v1"
_VERIFIED_ROLES = frozenset({"admin", "analyst", "viewer"})


class MitigationAnalysisResponse(BaseModel):
    """Stage 1 detection plus Stage A advisory mitigation outcomes."""

    detection: BotDetectionResponse
    mitigation: MitigationIntegrationResult
    advisory_only: bool = Field(
        default=True,
        description="Always true; this endpoint never enforces a recommendation.",
    )

    model_config = ConfigDict(frozen=True)


def _verified_actor_key_hash(actor_id: str) -> str:
    """Hash a verified JWT actor ID into the accepted opaque scope-key format."""
    digest = hashlib.sha256(
        f"{_ACTOR_HASH_DOMAIN}:{actor_id}".encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def _resolve_authentication(
    request: Request,
) -> tuple[
    MitigationAuthenticationMode,
    Optional[VerifiedMitigationPrincipal],
]:
    """Resolve Stage A authentication context only from trusted request state.

    The dual-auth dependency populates ``request.state`` for verified JWT users.
    Static API-key requests leave that state unset and are always unattributed.
    """
    user = getattr(request.state, "user", None)
    actor_id = getattr(request.state, "actor_id", None)
    if user is None or actor_id is None:
        return MitigationAuthenticationMode.API_KEY, None

    verified_actor = str(actor_id).strip()
    if not verified_actor:
        return MitigationAuthenticationMode.API_KEY, None

    role_value = getattr(user, "role", None)
    if isinstance(user, dict):
        role_value = user.get("role", role_value)
    role = str(role_value).strip().lower() if role_value is not None else ""
    if role not in _VERIFIED_ROLES:
        return MitigationAuthenticationMode.API_KEY, None

    principal = VerifiedMitigationPrincipal(
        actor_key_hash=_verified_actor_key_hash(verified_actor),
        role=role,  # type: ignore[arg-type]
    )
    return MitigationAuthenticationMode.JWT, principal


def _rollback_safely(db: Session) -> None:
    """Roll back the route-owned transaction without exposing any error detail."""
    try:
        db.rollback()
    except Exception:
        logger.error("Mitigation transaction rollback failed")


@router.get("/analyze", response_model=MitigationAnalysisResponse)
def analyze_mitigation(
    request: Request,
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(
        None, ge=100, le=599, description="HTTP status code filter (100..599)"
    ),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    max_records: int = Query(
        1000,
        ge=1,
        le=5000,
        description="Maximum traffic records analyzed when page=1",
    ),
    include_behavioral_risk: bool = Query(
        False,
        description=(
            "Include separately labelled behavioural risk context. It is never used "
            "to calculate bot_risk_score and is page-scoped, so it may cover a "
            "narrower window than page 1 multi-page bot analysis."
        ),
    ),
    rate_request_threshold: Optional[int] = Query(
        None,
        ge=2,
        le=10000,
        description="Rate detector request-count threshold override",
    ),
    rate_time_window_seconds: Optional[int] = Query(
        None,
        ge=1,
        le=86400,
        description="Rate detector rolling window override in seconds",
    ),
    brute_force_failure_threshold: Optional[int] = Query(
        None,
        ge=1,
        le=1000,
        description="Brute-force detector failure threshold override",
    ),
    suspicious_score_threshold: Optional[float] = Query(
        None,
        ge=0.0,
        le=100.0,
        description=(
            "Score threshold used only when grouped brute-force evidence is present "
            "and the override is disabled; weak supporting signals never trigger "
            "automation_suspicious on their own."
        ),
    ),
    brute_force_override_enabled: bool = Query(
        True,
        description=(
            "When enabled (default), grouped brute-force evidence classifies a "
            "client automation_suspicious even below suspicious_score_threshold. "
            "The triggering result includes BRUTE_FORCE_OVERRIDE."
        ),
    ),
    db: Session = Depends(get_db),
) -> MitigationAnalysisResponse:
    """
    Analyze stored traffic logs and return advisory mitigation outcomes.

    Query validation and detection behavior are delegated unchanged to the Stage 1
    endpoint. Stage A outcomes are audited inside the same caller-owned transaction
    before the single commit. No decision is enforced.
    """
    try:
        detection = analyze_bot_traffic(
            start_time=start_time,
            end_time=end_time,
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            page=page,
            page_size=page_size,
            max_records=max_records,
            include_behavioral_risk=include_behavioral_risk,
            rate_request_threshold=rate_request_threshold,
            rate_time_window_seconds=rate_time_window_seconds,
            brute_force_failure_threshold=brute_force_failure_threshold,
            suspicious_score_threshold=suspicious_score_threshold,
            brute_force_override_enabled=brute_force_override_enabled,
            db=db,
        )
        authentication_mode, verified_principal = _resolve_authentication(request)
        mitigation = evaluate_and_persist_bot_detection(
            db,
            detection,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )
        persist_decision_audit_events(
            db,
            mitigation,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )
        db.commit()
    except HTTPException as exc:
        if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
            _rollback_safely(db)
        raise
    except Exception:
        _rollback_safely(db)
        logger.error("Mitigation analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bot detection analysis could not be completed.",
        ) from None

    return MitigationAnalysisResponse(
        detection=detection,
        mitigation=mitigation,
        advisory_only=True,
    )


@router.get("/runtime-analyze", response_model=MW4RuntimeAnalysisResponse)
def analyze_runtime_mitigation(
    request: Request,
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(
        None, ge=100, le=599, description="HTTP status code filter (100..599)"
    ),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    max_records: int = Query(
        1000,
        ge=1,
        le=5000,
        description="Maximum traffic records analyzed when page=1",
    ),
    include_behavioral_risk: bool = Query(
        False,
        description=(
            "Include separately labelled behavioural risk context. It is never used "
            "to calculate bot_risk_score and is page-scoped, so it may cover a "
            "narrower window than page 1 multi-page bot analysis."
        ),
    ),
    rate_request_threshold: Optional[int] = Query(
        None, ge=2, le=10000, description="Rate detector request-count threshold override"
    ),
    rate_time_window_seconds: Optional[int] = Query(
        None, ge=1, le=86400, description="Rate detector rolling window override in seconds"
    ),
    brute_force_failure_threshold: Optional[int] = Query(
        None, ge=1, le=1000, description="Brute-force detector failure threshold override"
    ),
    suspicious_score_threshold: Optional[float] = Query(
        None,
        ge=0.0,
        le=100.0,
        description=(
            "Score threshold used only when grouped brute-force evidence is present "
            "and the override is disabled; weak supporting signals never trigger "
            "automation_suspicious on their own."
        ),
    ),
    brute_force_override_enabled: bool = Query(
        True,
        description=(
            "When enabled (default), grouped brute-force evidence classifies a "
            "client automation_suspicious even below suspicious_score_threshold. "
            "The triggering result includes BRUTE_FORCE_OVERRIDE."
        ),
    ),
    db: Session = Depends(get_db),
) -> MW4RuntimeAnalysisResponse:
    """Advisory MW4 runtime composition: detection + MW2 + MW1 + Stage A mitigation.

    Reuses existing bot detection and Stage A mitigation integration. MW2 and MW1
    are invoked through actual runtime service code. No enforcement is executed.
    """
    try:
        detection = analyze_bot_traffic(
            start_time=start_time,
            end_time=end_time,
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            page=page,
            page_size=page_size,
            max_records=max_records,
            include_behavioral_risk=include_behavioral_risk,
            rate_request_threshold=rate_request_threshold,
            rate_time_window_seconds=rate_time_window_seconds,
            brute_force_failure_threshold=brute_force_failure_threshold,
            suspicious_score_threshold=suspicious_score_threshold,
            brute_force_override_enabled=brute_force_override_enabled,
            db=db,
        )

        runtime_results, timings = orchestrate_mw4_runtime(detection)

        authentication_mode, verified_principal = _resolve_authentication(request)
        mitigation = evaluate_and_persist_bot_detection(
            db,
            detection,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )
        persist_decision_audit_events(
            db,
            mitigation,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )
        db.commit()
    except HTTPException as exc:
        if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
            _rollback_safely(db)
        raise
    except Exception:
        _rollback_safely(db)
        logger.error("MW4 runtime analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Runtime mitigation analysis could not be completed.",
        ) from None

    # Aggregate uncertainty/provenance for report consumers; no sensitive data.
    mw1_statuses = [r.mw1_status for r in runtime_results]
    mw2_statuses = [
        s.status.value if hasattr(s.status, "value") else str(s.status)
        for r in runtime_results
        for s in r.mw2_advanced_detection.signals
    ]
    return MW4RuntimeAnalysisResponse(
        detection=detection,
        mw2_advanced_detection=runtime_results,
        mw1_unified_risk_assessment=runtime_results,
        runtime_results=runtime_results,
        mitigation=mitigation,
        timings_ms=timings,
        advisory_only=True,
        enforcement_executed=False,
        provenance={
            "mw2_service": "app.services.advanced_detection.advisory_orchestrator.build_advisory_envelope",
            "mw1_service": "app.services.unified_risk_assessment_service.assess_risk",
            "bot_detection_service": "app.services.bot_detection_service.analyze_traffic_for_bot_detection",
            "mitigation_service": "app.services.mitigation_integration_service.evaluate_and_persist_bot_detection",
            "runtime_orchestrator": "app.services.mw4_runtime_orchestration_service.orchestrate_mw4_runtime",
        },
        uncertainty={
            "mw1_result_statuses": mw1_statuses,
            "mw2_signal_statuses": mw2_statuses,
            "coverage_note": "Missing/unavailable/error signals remain explicit; absent evidence is not treated as clean.",
        },
    )


__all__ = ["MitigationAnalysisResponse", "MW4RuntimeAnalysisResponse", "router"]
