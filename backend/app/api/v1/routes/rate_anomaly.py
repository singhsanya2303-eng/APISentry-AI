"""
Rate Anomaly Detection API Route — Module 6, Step 3.

Exposes the rate anomaly & abuse analysis engine via a clean, validated FastAPI route.

Endpoint:
    GET /api/v1/security/rate-anomaly/analyze
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.rate_anomaly import RateAnomalyDetectionResult
from app.detection.rate_anomaly_detector import RateAnomalyDetectorConfig
from app.services.rate_anomaly_analysis_service import analyze_traffic_for_rate_anomaly

router = APIRouter(prefix="/security/rate-anomaly", tags=["Rate Anomaly Security Analysis"])

VALID_SCOPES = {"endpoint", "client_wide"}


@router.get("/analyze", response_model=RateAnomalyDetectionResult)
def analyze_rate_anomaly_traffic(
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(None, ge=100, le=599, description="HTTP status code filter (100..599)"),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    request_threshold: Optional[int] = Query(None, ge=2, le=10000, description="Minimum request count threshold override"),
    time_window_seconds: Optional[int] = Query(None, ge=1, le=86400, description="Rolling time window in seconds override"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score threshold override"),
    scope: Optional[str] = Query(None, description="Analysis scope ('endpoint' or 'client_wide')"),
    db: Session = Depends(get_db)
) -> RateAnomalyDetectionResult:
    """
    Analyze captured API traffic logs for abnormal request rates or volume spikes.
    Always returns HTTP 200 with structured analysis verdict and evidence details.
    """
    norm_method = method.upper() if method else None

    if scope is not None:
        norm_scope = scope.strip().lower()
        if norm_scope not in VALID_SCOPES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid scope '{scope}'. Must be one of: {sorted(VALID_SCOPES)}"
            )
    else:
        norm_scope = None

    detector_config = None
    if (
        request_threshold is not None
        or time_window_seconds is not None
        or min_confidence is not None
        or norm_scope is not None
    ):
        kwargs = {}
        if request_threshold is not None:
            kwargs["request_threshold"] = request_threshold
        if time_window_seconds is not None:
            kwargs["time_window_seconds"] = time_window_seconds
        if min_confidence is not None:
            kwargs["min_confidence"] = min_confidence
        if norm_scope is not None:
            kwargs["scope"] = norm_scope
        detector_config = RateAnomalyDetectorConfig(**kwargs)

    return analyze_traffic_for_rate_anomaly(
        start_time=start_time,
        end_time=end_time,
        method=norm_method,
        path=path,
        status_code=status_code,
        client_ip=client_ip,
        page=page,
        page_size=page_size,
        detector_config=detector_config,
        db=db
    )
