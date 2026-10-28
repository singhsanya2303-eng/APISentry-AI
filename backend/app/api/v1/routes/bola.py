from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.bola import BolaDetectionResult
from app.detection.bola_detector import BolaDetectorConfig
from app.services.bola_analysis_service import analyze_traffic_for_bola

router = APIRouter(prefix="/security/bola", tags=["BOLA Security Analysis"])


@router.get("/analyze", response_model=BolaDetectionResult)
def analyze_bola_traffic(
    start_time: Optional[datetime] = Query(None, description="Start time filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time filter (UTC)"),
    method: Optional[str] = Query(None, description="HTTP method filter (e.g. GET, POST)"),
    path: Optional[str] = Query(None, description="URI path filter"),
    status_code: Optional[int] = Query(None, ge=100, le=599, description="HTTP status code filter (100..599)"),
    client_ip: Optional[str] = Query(None, description="Client IP filter"),
    page: int = Query(1, ge=1, description="Page number for traffic query"),
    page_size: int = Query(200, ge=1, le=500, description="Page size for traffic query"),
    min_distinct_objects: Optional[int] = Query(None, ge=2, le=100, description="Minimum distinct objects threshold override"),
    min_extraction_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Extraction confidence threshold override"),
    db: Session = Depends(get_db)
) -> BolaDetectionResult:
    """
    Analyze API traffic for potential BOLA / IDOR candidate access patterns.
    Always returns HTTP 200 with structured analysis verdict and evidence details.
    """
    norm_method = method.upper() if method else None

    detector_config = None
    if min_distinct_objects is not None or min_extraction_confidence is not None:
        kwargs = {}
        if min_distinct_objects is not None:
            kwargs["min_distinct_objects"] = min_distinct_objects
        if min_extraction_confidence is not None:
            kwargs["min_extraction_confidence"] = min_extraction_confidence
        detector_config = BolaDetectorConfig(**kwargs)

    return analyze_traffic_for_bola(
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
