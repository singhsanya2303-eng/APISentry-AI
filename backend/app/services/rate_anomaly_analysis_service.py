"""
Rate Anomaly Analysis Service — Module 6, Step 2.

Connects the existing APITrafficLog persistence/query layer to the
RateAnomalyDetector engine via a deterministic extraction pipeline.

PIPELINE:
    APITrafficLog (DB Model)
          ↓
    RateAnomalyAnalysisService
          ↓
    RateAnomalyEvent (Schema)
          ↓
    RateAnomalyDetector (Engine)
          ↓
    RateAnomalyDetectionResult (Output)

TIME-WINDOW ARCHITECTURE NOTE:
  The Step 1 RateAnomalyDetector uses a batch-anchored time window:
      window_start = latest_event_timestamp - time_window_seconds
  This service retrieves an appropriately bounded time range / batch from PostgreSQL,
  controlled by query filters (start_time, end_time, max_records), and feeds the
  retrieved events into the batch-anchored detector without arbitrarily truncating
  traffic across small pagination bounds.

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
from app.schemas.rate_anomaly import (
    RateAnomalyDetectionResult,
    RateAnomalyEvent,
    RateAnomalyVerdict,
)
from app.detection.rate_anomaly_detector import (
    RateAnomalyDetector,
    RateAnomalyDetectorConfig,
)
from app.services.resource_extractor import extract_safe_actor_id
from app.services.traffic_service import get_traffic_logs

logger = logging.getLogger("apisentry.analysis.rate_anomaly")


def convert_traffic_log_to_rate_anomaly_event(
    log: APITrafficLog,
    headers: Optional[Dict[str, str]] = None
) -> Optional[RateAnomalyEvent]:
    """
    Safely convert an APITrafficLog ORM object into a RateAnomalyEvent schema.

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

    method = getattr(log, "method", "GET")
    if not method or not isinstance(method, str):
        method = "GET"
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

    return RateAnomalyEvent(
        request_id=request_id,
        timestamp=timestamp,
        method=method,
        path=path,
        client_ip=client_ip,
        actor_id=actor_id,
        status_code=status_code,
    )


def _fetch_traffic_records(
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 200,
    max_records: int = 1000,
    fetch_full_window: bool = True,
    db: Optional[Session] = None
) -> List[APITrafficLog]:
    """
    Retrieve traffic logs from the database layer with controlled pagination.

    Safeguards:
    - If fetch_full_window is True and page == 1, retrieves across pages up to max_records
      to prevent small page_size values from truncating burst volume into false-negatives.
    - If page > 1 or fetch_full_window is False, queries the single requested page.
    - Strictly bounds maximum database retrieval to max_records to prevent memory exhaustion.
    """
    if not fetch_full_window or page > 1:
        return get_traffic_logs(
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

    all_logs: List[APITrafficLog] = []
    current_page = 1
    fetch_batch_size = min(500, max(50, page_size))

    while len(all_logs) < max_records:
        remaining_budget = max_records - len(all_logs)
        current_limit = min(fetch_batch_size, remaining_budget)

        batch = get_traffic_logs(
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time,
            page=current_page,
            page_size=current_limit,
            db=db
        )

        if not batch:
            break

        all_logs.extend(batch)

        # If fewer records returned than requested, we've reached the end of available data
        if len(batch) < current_limit:
            break

        current_page += 1

    return all_logs


def analyze_traffic_for_rate_anomaly(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    page: int = 1,
    page_size: int = 200,
    max_records: int = 1000,
    fetch_full_window: bool = True,
    detector_config: Optional[RateAnomalyDetectorConfig] = None,
    headers_map: Optional[Dict[str, Dict[str, str]]] = None,
    db: Optional[Session] = None
) -> RateAnomalyDetectionResult:
    """
    End-to-end service integration workflow for rate anomaly & abuse analysis.

    Flow:
    1. Query database traffic logs using filter criteria via traffic_service.get_traffic_logs.
    2. Convert traffic logs into RateAnomalyEvent objects safely.
       Defensively handles malformed or incomplete log records.
    3. Execute RateAnomalyDetector over the extracted RateAnomalyEvent sequence.
    4. Return RateAnomalyDetectionResult.
    """
    headers_map = headers_map or {}

    try:
        logs = _fetch_traffic_records(
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
            max_records=max_records,
            fetch_full_window=fetch_full_window,
            db=db
        )
    except Exception as exc:
        logger.error("Failed to query traffic logs for rate anomaly analysis: %s", exc)
        logs = []

    if not logs:
        return RateAnomalyDetectionResult(
            verdict=RateAnomalyVerdict.NO_ANOMALY,
            analyzed_event_count=0,
            anomalous_request_count=0,
            distinct_client_count=0,
            distinct_actor_count=0,
            evidences=[],
            summary="No traffic events matching query criteria found for rate anomaly analysis."
        )

    events: List[RateAnomalyEvent] = []
    for log in logs:
        try:
            req_id = getattr(log, "request_id", None)
            headers = headers_map.get(req_id) if req_id else None
            event = convert_traffic_log_to_rate_anomaly_event(log, headers=headers)
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
        return RateAnomalyDetectionResult(
            verdict=RateAnomalyVerdict.NO_ANOMALY,
            analyzed_event_count=0,
            anomalous_request_count=0,
            distinct_client_count=0,
            distinct_actor_count=0,
            evidences=[],
            summary="No valid traffic events available for rate anomaly analysis after filtering."
        )

    detector = RateAnomalyDetector(config=detector_config)
    return detector.analyze_events(events)


def analyze_events_directly(
    events: List[RateAnomalyEvent],
    detector_config: Optional[RateAnomalyDetectorConfig] = None
) -> RateAnomalyDetectionResult:
    """Convenience entry point for directly analyzing pre-constructed RateAnomalyEvent lists."""
    detector = RateAnomalyDetector(config=detector_config)
    return detector.analyze_events(events)
