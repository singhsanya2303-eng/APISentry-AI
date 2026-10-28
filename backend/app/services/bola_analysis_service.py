import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.schemas.bola import BolaDetectionResult, ResourceAccessEvent, DetectionVerdict
from app.detection.bola_detector import BolaDetector, BolaDetectorConfig
from app.services.resource_extractor import extract_from_traffic_log
from app.services.traffic_service import get_traffic_logs
from app.models.traffic import APITrafficLog

logger = logging.getLogger("apisentry.analysis.bola")


def analyze_traffic_for_bola(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    page: int = 1,
    page_size: int = 200,
    detector_config: Optional[BolaDetectorConfig] = None,
    headers_map: Optional[Dict[str, Dict[str, str]]] = None,
    db: Optional[Session] = None
) -> BolaDetectionResult:
    """
    End-to-end service integration workflow for BOLA/IDOR analysis.

    Flow:
    1. Query database traffic logs using filter criteria via traffic_service.get_traffic_logs.
    2. Convert traffic logs into ResourceAccessEvent objects using resource_extractor.
       Defensively handles malformed or missing log fields.
    3. Execute BolaDetector over the extracted ResourceAccessEvent sequence.
    4. Return BolaDetectionResult.
    """
    headers_map = headers_map or {}

    try:
        logs = get_traffic_logs(
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
            db=db
        )
    except Exception as exc:
        logger.error("Failed to query traffic logs for BOLA analysis: %s", exc)
        logs = []

    if not logs:
        return BolaDetectionResult(
            verdict=DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR,
            evidences=[],
            analyzed_event_count=0,
            explanation="No traffic events matching query criteria found for BOLA analysis."
        )

    events: List[ResourceAccessEvent] = []
    for log in logs:
        try:
            if not log or not getattr(log, "request_id", None) or not getattr(log, "path", None):
                logger.warning("Skipping invalid or incomplete traffic log record")
                continue

            headers = headers_map.get(log.request_id)
            event = extract_from_traffic_log(log, headers=headers)
            events.append(event)
        except Exception as exc:
            logger.warning("Skipping malformed traffic log entry (request_id=%s): %s", getattr(log, "request_id", "unknown"), exc)
            continue

    detector = BolaDetector(config=detector_config)
    return detector.analyze_events(events)


def analyze_events_directly(
    events: List[ResourceAccessEvent],
    detector_config: Optional[BolaDetectorConfig] = None
) -> BolaDetectionResult:
    """Convenience entry point for directly analyzing pre-constructed ResourceAccessEvent lists."""
    detector = BolaDetector(config=detector_config)
    return detector.analyze_events(events)
