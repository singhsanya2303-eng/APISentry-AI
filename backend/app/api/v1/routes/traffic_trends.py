
"""API endpoint for baseline-based traffic trend anomaly analysis."""

from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.traffic_service import get_traffic_logs
from app.services.traffic_trend_analysis_service import analyze_traffic_trends

router = APIRouter(
    prefix="/security/traffic-trends",
    tags=["Traffic Trend Anomaly Analysis"],
)

PAGE_SIZE = 500
MAX_LOGS_PER_WINDOW = 10000


def _fetch_window_logs(
    start_time: datetime,
    end_time: datetime,
    db: Session,
) -> List[Any]:
    """Fetch a complete time window with a bounded record limit."""
    logs: List[Any] = []
    page = 1

    while True:
        batch = get_traffic_logs(
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=PAGE_SIZE,
            db=db,
        )

        if not batch:
            break

        if len(logs) + len(batch) > MAX_LOGS_PER_WINDOW:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Time window exceeds the 10000-record analysis limit. "
                    "Use a shorter time range."
                ),
            )

        logs.extend(batch)

        if len(batch) < PAGE_SIZE:
            break

        page += 1

    # The query service returns newest-first; aggregation sorts windows itself.
    return logs


@router.get("/analyze")
def analyze_traffic_trend_endpoint(
    baseline_start: datetime = Query(...),
    baseline_end: datetime = Query(...),
    target_start: datetime = Query(...),
    target_end: datetime = Query(...),
    threshold_percentile: float = Query(95.0, ge=50.0, le=99.9),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Train on an earlier baseline and score a later target window."""
    if not (
        baseline_start < baseline_end < target_start < target_end
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Required order: baseline_start < baseline_end "
                "< target_start < target_end."
            ),
        )

    baseline_logs = _fetch_window_logs(baseline_start, baseline_end, db)
    target_logs = _fetch_window_logs(target_start, target_end, db)

    try:
        return analyze_traffic_trends(
            baseline_logs=baseline_logs,
            target_logs=target_logs,
            threshold_percentile=threshold_percentile,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
