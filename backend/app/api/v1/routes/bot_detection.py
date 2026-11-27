"""
Bot Detection API Route — Stage 1.

Endpoint:
    GET /api/v1/security/bot/analyze

Returns deterministic, evidence-based bot assessments. No mitigation, blocking,
throttling, or enforcement is performed by this endpoint.
"""

from datetime import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.bruteforce_detector import BruteForceDetectorConfig
from app.detection.rate_anomaly_detector import RateAnomalyDetectorConfig
from app.schemas.bot_detection import BotDetectionResponse
from app.services.bot_detection_service import (
    BotScoringConfig,
    analyze_traffic_for_bot_detection,
)

router = APIRouter(prefix="/security/bot", tags=["Bot Detection"])
logger = logging.getLogger("apisentry.api.bot_detection")


@router.get("/analyze", response_model=BotDetectionResponse)
def analyze_bot_traffic(
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
) -> BotDetectionResponse:
    """
    Analyze stored traffic logs for bot-like patterns.

    Limits: `max_records` bounds only page 1, which is read across database pages
    with a fixed page size. Page > 1 analyzes only that page and ignores
    `max_records`; `limits.records_analyzed` is exact and `limits.truncated` means
    matching records beyond `max_records` were not analyzed. Optional behavioural
    context is page-scoped and never influences bot_risk_score. Missing or
    incomplete evidence lowers confidence and never creates a high-risk
    classification.
    """
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_time must be earlier than or equal to end_time",
        )

    scoring_kwargs: dict = {}
    if suspicious_score_threshold is not None:
        scoring_kwargs["suspicious_score_threshold"] = suspicious_score_threshold
    if not brute_force_override_enabled:
        scoring_kwargs["brute_force_override_enabled"] = False
    scoring_config = BotScoringConfig(**scoring_kwargs) if scoring_kwargs else None

    rate_config = None
    if rate_request_threshold is not None or rate_time_window_seconds is not None:
        rate_kwargs = {}
        if rate_request_threshold is not None:
            rate_kwargs["request_threshold"] = rate_request_threshold
        if rate_time_window_seconds is not None:
            rate_kwargs["time_window_seconds"] = rate_time_window_seconds
        rate_config = RateAnomalyDetectorConfig(**rate_kwargs)

    brute_config = None
    if brute_force_failure_threshold is not None:
        brute_config = BruteForceDetectorConfig(
            failure_threshold=brute_force_failure_threshold
        )

    try:
        return analyze_traffic_for_bot_detection(
            start_time=start_time,
            end_time=end_time,
            method=method.upper() if method else None,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            page=page,
            page_size=page_size,
            max_records=max_records,
            include_behavioral_risk=include_behavioral_risk,
            scoring_config=scoring_config,
            rate_detector_config=rate_config,
            brute_force_detector_config=brute_config,
            db=db,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Bot detection analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bot detection analysis could not be completed.",
        ) from exc
