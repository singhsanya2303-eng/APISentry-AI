"""
Behavioral Analysis & Risk Scoring API Route — Module 7, Step 3.

Exposes behavioral feature extraction and deterministic risk scoring via a clean, validated FastAPI route.

Endpoint:
    GET /api/v1/security/behavior/analyze
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.behavior import BehaviorRiskAnalysisResponse
from app.detection.risk_scorer import RiskScoringConfig
from app.services.behavior_analysis_service import analyze_traffic_for_behavior_risk

router = APIRouter(prefix="/security/behavior", tags=["Behavioral Risk Analysis"])


@router.get("/analyze", response_model=BehaviorRiskAnalysisResponse)
def analyze_behavior_traffic(
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(None, ge=100, le=599, description="HTTP status code filter (100..599)"),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    bola_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for BOLA activity"),
    brute_force_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for brute-force activity"),
    rate_anomaly_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for rate anomaly signals"),
    authentication_failure_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for HTTP 401 auth failures"),
    failed_request_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for non-auth HTTP errors"),
    endpoint_diversity_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for endpoint exploration"),
    resource_diversity_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for resource enumeration"),
    high_request_volume_weight: Optional[float] = Query(None, ge=0.0, le=100.0, description="Score contribution weight override for high request volume"),
    db: Session = Depends(get_db)
) -> BehaviorRiskAnalysisResponse:
    """
    Analyze API traffic behavior and calculate deterministic per-client risk scores.
    Always returns HTTP 200 with structured per-client risk evaluation, factor breakdown, and neutral explanations.
    """
    norm_method = method.upper() if method else None

    # UTC time range validation: start_time <= end_time
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_time must be earlier than or equal to end_time"
        )

    # Construct RiskScoringConfig if weight overrides are specified
    scoring_config = None
    if any(w is not None for w in [
        bola_weight, brute_force_weight, rate_anomaly_weight,
        authentication_failure_weight, failed_request_weight,
        endpoint_diversity_weight, resource_diversity_weight,
        high_request_volume_weight
    ]):
        kwargs = {}
        if bola_weight is not None:
            kwargs["bola_weight"] = bola_weight
        if brute_force_weight is not None:
            kwargs["brute_force_weight"] = brute_force_weight
        if rate_anomaly_weight is not None:
            kwargs["rate_anomaly_weight"] = rate_anomaly_weight
        if authentication_failure_weight is not None:
            kwargs["authentication_failure_weight"] = authentication_failure_weight
        if failed_request_weight is not None:
            kwargs["failed_request_weight"] = failed_request_weight
        if endpoint_diversity_weight is not None:
            kwargs["endpoint_diversity_weight"] = endpoint_diversity_weight
        if resource_diversity_weight is not None:
            kwargs["resource_diversity_weight"] = resource_diversity_weight
        if high_request_volume_weight is not None:
            kwargs["high_request_volume_weight"] = high_request_volume_weight
        scoring_config = RiskScoringConfig(**kwargs)

    return analyze_traffic_for_behavior_risk(
        start_time=start_time,
        end_time=end_time,
        method=norm_method,
        path=path,
        status_code=status_code,
        client_ip=client_ip,
        page=page,
        page_size=page_size,
        scoring_config=scoring_config,
        db=db
    )
