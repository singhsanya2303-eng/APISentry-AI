"""
Brute-Force Analysis Service — Module 5, Step 2.

Connects the existing APITrafficLog persistence/query layer to the
BruteForceDetector engine via a deterministic extraction pipeline.

PIPELINE:
    APITrafficLog (DB Model)
          ↓
    BruteForceAnalysisService
          ↓
    BruteForceEvent (Schema)
          ↓
    BruteForceDetector (Engine)
          ↓
    BruteForceDetectionResult (Output)

SECURITY CONTRACT:
  - Authorization headers, Bearer tokens, cookies, API keys, passwords,
    and any credential-bearing data are NEVER inspected, stored, logged, or exposed.
  - actor_id is OPTIONAL context, extracted strictly through safe channels
    (e.g., non-sensitive X-User-ID header or safe query params).
  - client_ip is the primary attribution signal. Missing client IPs are
    never fabricated.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.traffic import APITrafficLog
from app.schemas.bruteforce import (
    BruteForceDetectionResult,
    BruteForceEvent,
    BruteForceVerdict,
)
from app.detection.bruteforce_detector import (
    BruteForceDetector,
    BruteForceDetectorConfig,
)
from app.services.resource_extractor import extract_safe_actor_id
from app.services.traffic_service import get_traffic_logs

logger = logging.getLogger("apisentry.analysis.bruteforce")


def convert_traffic_log_to_bruteforce_event(
    log: APITrafficLog,
    headers: Optional[Dict[str, str]] = None
) -> Optional[BruteForceEvent]:
    """
    Safely convert an APITrafficLog ORM object into a BruteForceEvent schema.

    Guarantees:
    - Uses only information already available from sanitized traffic records.
    - Never inspects or derives actor identity from Authorization headers,
      Bearer tokens, cookies, API keys, passwords, or secrets.
    - Preserves client_ip as the primary attribution signal; sets to None if missing.
    - If required fields are missing or invalid, raises ValueError to allow
      the caller to skip the malformed entry.
    """
    if log is None:
        return None

    request_id = getattr(log, "request_id", None)
    if not request_id or not isinstance(request_id, str):
        raise ValueError("Missing or invalid request_id in traffic log")

    path = getattr(log, "path", None)
    if not path or not isinstance(path, str):
        raise ValueError("Missing or invalid path in traffic log")

    method = getattr(log, "method", "POST")
    if not method or not isinstance(method, str):
        method = "POST"
    method = method.upper()

    timestamp = getattr(log, "timestamp", None)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    elif timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    raw_ip = getattr(log, "client_ip", None)
    client_ip: Optional[str] = None
    if raw_ip and isinstance(raw_ip, str) and raw_ip.strip():
        client_ip = raw_ip.strip()

    status_code = getattr(log, "status_code", None)
    if status_code is None or not isinstance(status_code, int):
        raise ValueError("Missing or invalid status_code in traffic log")

    query_params = getattr(log, "query_params", None)
    actor_id = extract_safe_actor_id(headers=headers, query_params=query_params)

    return BruteForceEvent(
        request_id=request_id,
        timestamp=timestamp,
        method=method,
        path=path,
        client_ip=client_ip,
        actor_id=actor_id,
        status_code=status_code,
        authentication_failure=(status_code == 401)
    )


def analyze_traffic_for_bruteforce(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    page: int = 1,
    page_size: int = 200,
    detector_config: Optional[BruteForceDetectorConfig] = None,
    headers_map: Optional[Dict[str, Dict[str, str]]] = None,
    db: Optional[Session] = None
) -> BruteForceDetectionResult:
    """
    End-to-end service integration workflow for brute-force detection analysis.

    Flow:
    1. Query database traffic logs using filter criteria via traffic_service.get_traffic_logs.
    2. Convert traffic logs into BruteForceEvent objects safely.
       Defensively handles malformed or incomplete log records.
    3. Execute BruteForceDetector over the extracted BruteForceEvent sequence.
    4. Return BruteForceDetectionResult.
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
        logger.error("Failed to query traffic logs for brute-force analysis: %s", exc)
        logs = []

    if not logs:
        return BruteForceDetectionResult(
            verdict=BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
            analyzed_event_count=0,
            failed_attempt_count=0,
            distinct_client_count=0,
            distinct_actor_count=0,
            evidences=[],
            summary="No traffic events matching query criteria found for brute-force analysis."
        )

    events: List[BruteForceEvent] = []
    for log in logs:
        try:
            req_id = getattr(log, "request_id", None)
            headers = headers_map.get(req_id) if req_id else None
            event = convert_traffic_log_to_bruteforce_event(log, headers=headers)
            if event is not None:
                events.append(event)
            else:
                logger.warning("Skipping invalid or incomplete traffic log record")
        except Exception as exc:
            logger.warning(
                "Skipping malformed traffic log entry (request_id=%s): %s",
                getattr(log, "request_id", "unknown"),
                exc
            )
            continue

    if not events:
        return BruteForceDetectionResult(
            verdict=BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
            analyzed_event_count=0,
            failed_attempt_count=0,
            distinct_client_count=0,
            distinct_actor_count=0,
            evidences=[],
            summary="No valid traffic events available for brute-force analysis after filtering."
        )

    detector = BruteForceDetector(config=detector_config)
    return detector.analyze_events(events)


def analyze_events_directly(
    events: List[BruteForceEvent],
    detector_config: Optional[BruteForceDetectorConfig] = None
) -> BruteForceDetectionResult:
    """Convenience entry point for directly analyzing pre-constructed BruteForceEvent lists."""
    detector = BruteForceDetector(config=detector_config)
    return detector.analyze_events(events)
