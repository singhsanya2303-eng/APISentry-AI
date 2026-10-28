"""
Brute-Force Detection API Route — Module 5, Step 3.

Exposes the brute-force security analysis engine via a clean, validated FastAPI route.

Endpoint:
    GET /api/v1/security/bruteforce/analyze
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.bruteforce import BruteForceDetectionResult
from app.detection.bruteforce_detector import BruteForceDetectorConfig
from app.services.bruteforce_analysis_service import analyze_traffic_for_bruteforce

router = APIRouter(prefix="/security/bruteforce", tags=["Brute-Force Security Analysis"])


@router.get("/analyze", response_model=BruteForceDetectionResult)
def analyze_bruteforce_traffic(
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(None, ge=100, le=599, description="HTTP status code filter (100..599)"),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    failure_threshold: Optional[int] = Query(None, ge=1, le=1000, description="Minimum failed attempts threshold override"),
    time_window_minutes: Optional[int] = Query(None, ge=1, le=1440, description="Rolling time window in minutes override"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score threshold override"),
    db: Session = Depends(get_db)
) -> BruteForceDetectionResult:
    """
    Analyze captured API traffic logs for brute-force / credential-stuffing patterns.
    Always returns HTTP 200 with structured analysis verdict and evidence details.
    """
    norm_method = method.upper() if method else None

    detector_config = None
    if failure_threshold is not None or time_window_minutes is not None or min_confidence is not None:
        kwargs = {}
        if failure_threshold is not None:
            kwargs["failure_threshold"] = failure_threshold
        if time_window_minutes is not None:
            kwargs["time_window_minutes"] = time_window_minutes
        if min_confidence is not None:
            kwargs["min_confidence"] = min_confidence
        detector_config = BruteForceDetectorConfig(**kwargs)

    return analyze_traffic_for_bruteforce(
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
