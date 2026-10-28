"""
Tests for RateAnomalyAnalysisService — Module 6, Step 2.

Comprehensive integration test suite verifying the database integration pipeline:
  APITrafficLog (DB) -> RateAnomalyAnalysisService -> RateAnomalyEvent -> RateAnomalyDetector -> RateAnomalyDetectionResult

Scenarios covered:
  1. Empty PostgreSQL traffic dataset
  2. Normal low-rate traffic
  3. Threshold-level traffic
  4. High-rate traffic
  5. Requests outside analysis window
  6. Multiple client IPs
  7. Missing client IP
  8. Missing actor ID but valid client IP
  9. Different endpoints
  10. Client-wide scope
  11. Endpoint scope
  12. Mixed HTTP status codes
  13. Existing traffic filters
  14. UTC start/end filtering
  15. Custom detector configuration
  16. Pagination / complete-window behavior
  17. Malformed traffic record
  18. Deterministic result
  19. No sensitive credential values in result
  20. Detector result returned correctly
  21. Bounded analysis window
  22. No accidental unbounded database retrieval
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
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
from app.services.rate_anomaly_analysis_service import (
    analyze_traffic_for_rate_anomaly,
    analyze_events_directly,
    convert_traffic_log_to_rate_anomaly_event,
    _fetch_traffic_records,
)


# ---------------------------------------------------------------------------
# Database Fixture (In-Memory SQLite)
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """Fixture creating an in-memory SQLite database session for service testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()


def create_traffic_log(
    request_id: str,
    path: str = "/api/v1/search",
    status_code: int = 200,
    client_ip: Optional[str] = "192.168.1.100",
    method: str = "GET",
    query_params: Optional[Dict[str, Any]] = None,
    user_agent: str = "TestBrowser/1.0",
    response_time_ms: float = 12.0,
    timestamp: Optional[datetime] = None,
) -> APITrafficLog:
    """Helper to construct APITrafficLog ORM instances."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return APITrafficLog(
        request_id=request_id,
        timestamp=timestamp,
        method=method,
        path=path,
        query_params=query_params or {},
        client_ip=client_ip if client_ip is not None else "",
        user_agent=user_agent,
        status_code=status_code,
        response_time_ms=response_time_ms,
    )


# ---------------------------------------------------------------------------
# 1. Empty PostgreSQL Traffic Dataset
# ---------------------------------------------------------------------------

def test_scenario_1_empty_traffic_dataset(db_session):
    result = analyze_traffic_for_rate_anomaly(db=db_session)
    assert isinstance(result, RateAnomalyDetectionResult)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert result.analyzed_event_count == 0
    assert result.anomalous_request_count == 0
    assert len(result.evidences) == 0
    assert "No traffic events" in result.summary


# ---------------------------------------------------------------------------
# 2. Normal Low-Rate Traffic
# ---------------------------------------------------------------------------

def test_scenario_2_normal_low_rate_traffic(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"r-{i}", timestamp=now - timedelta(seconds=i * 10))
        for i in range(1, 5)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(db=db_session)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert result.analyzed_event_count == 4
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 3. Threshold-Level Traffic
# ---------------------------------------------------------------------------

def test_scenario_3_threshold_level_traffic(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"t-{i}", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.analyzed_event_count == 5
    assert result.anomalous_request_count == 5
    assert len(result.evidences) == 1
    assert result.evidences[0].request_count == 5


# ---------------------------------------------------------------------------
# 4. High-Rate Traffic
# ---------------------------------------------------------------------------

def test_scenario_4_high_rate_traffic(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=20, time_window_seconds=10)
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"flood-{i}", timestamp=now - timedelta(seconds=i * 0.1))
        for i in range(1, 31)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.anomalous_request_count == 30
    assert result.evidences[0].requests_per_second == 3.0


# ---------------------------------------------------------------------------
# 5. Requests Outside Analysis Window
# ---------------------------------------------------------------------------

def test_scenario_5_requests_outside_analysis_window(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=10)
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"old-{i}", timestamp=now - timedelta(seconds=60 + i))
        for i in range(1, 5)
    ] + [
        create_traffic_log("recent-1", timestamp=now)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 6. Multiple Client IPs
# ---------------------------------------------------------------------------

def test_scenario_6_multiple_client_ips(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    now = datetime.now(timezone.utc)
    logs_a = [
        create_traffic_log(f"a-{i}", client_ip="10.0.0.1", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    logs_b = [
        create_traffic_log(f"b-{i}", client_ip="10.0.0.2", timestamp=now - timedelta(seconds=i))
        for i in range(1, 3)
    ]
    db_session.add_all(logs_a + logs_b)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert len(result.evidences) == 1
    assert result.evidences[0].client_ip == "10.0.0.1"
    assert result.distinct_client_count == 1


# ---------------------------------------------------------------------------
# 7. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_7_missing_client_ip(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"noip-{i}", client_ip="", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(db=db_session)
    assert result.verdict == RateAnomalyVerdict.INSUFFICIENT_EVIDENCE
    assert "lacked a client IP" in result.summary


# ---------------------------------------------------------------------------
# 8. Missing Actor ID but Valid Client IP
# ---------------------------------------------------------------------------

def test_scenario_8_missing_actor_id_valid_client_ip(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"noact-{i}", client_ip="172.16.0.1", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].actor_id is None
    assert result.evidences[0].client_ip == "172.16.0.1"


# ---------------------------------------------------------------------------
# 9. Different Endpoints
# ---------------------------------------------------------------------------

def test_scenario_9_different_endpoints(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30, scope="endpoint")
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"e1-{i}", path="/api/v1/orders", timestamp=now - timedelta(seconds=i))
        for i in range(1, 4)
    ] + [
        create_traffic_log(f"e2-{i}", path="/api/v1/users", timestamp=now - timedelta(seconds=i))
        for i in range(1, 4)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 10. Client-Wide Scope
# ---------------------------------------------------------------------------

def test_scenario_10_client_wide_scope(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=6, time_window_seconds=30, scope="client_wide")
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"e1-{i}", path="/api/v1/orders", timestamp=now - timedelta(seconds=i))
        for i in range(1, 4)
    ] + [
        create_traffic_log(f"e2-{i}", path="/api/v1/users", timestamp=now - timedelta(seconds=i))
        for i in range(1, 4)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert len(result.evidences) == 1
    assert result.evidences[0].analyzed_endpoint == "CLIENT_WIDE"
    assert result.evidences[0].request_count == 6


# ---------------------------------------------------------------------------
# 11. Endpoint Scope
# ---------------------------------------------------------------------------

def test_scenario_11_endpoint_scope(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30, scope="endpoint")
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"ep-{i}", path="/api/v1/items", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].analyzed_endpoint == "/api/v1/items"


# ---------------------------------------------------------------------------
# 12. Mixed HTTP Status Codes
# ---------------------------------------------------------------------------

def test_scenario_12_mixed_http_status_codes(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    now = datetime.now(timezone.utc)
    statuses = [200, 201, 304, 400, 500]
    logs = [
        create_traffic_log(f"st-{i}", status_code=statuses[i], timestamp=now - timedelta(seconds=i))
        for i in range(5)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].request_count == 5
    assert set(result.evidences[0].status_codes) == set(statuses)


# ---------------------------------------------------------------------------
# 13. Existing Traffic Filters
# ---------------------------------------------------------------------------

def test_scenario_13_existing_traffic_filters(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("f1", method="POST", client_ip="192.168.1.1", status_code=200, timestamp=now),
        create_traffic_log("f2", method="POST", client_ip="192.168.1.1", status_code=200, timestamp=now),
        create_traffic_log("f3", method="GET", client_ip="192.168.1.1", status_code=200, timestamp=now),
        create_traffic_log("f4", method="POST", client_ip="10.0.0.1", status_code=200, timestamp=now),
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(
        method="POST",
        client_ip="192.168.1.1",
        db=db_session
    )
    assert result.analyzed_event_count == 2


# ---------------------------------------------------------------------------
# 14. UTC Start/End Filtering
# ---------------------------------------------------------------------------

def test_scenario_14_utc_start_end_filtering(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"t-{i}", timestamp=now - timedelta(minutes=i))
        for i in range(1, 10)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(
        start_time=now - timedelta(minutes=5),
        end_time=now - timedelta(minutes=2),
        db=db_session
    )
    assert result.analyzed_event_count == 4


# ---------------------------------------------------------------------------
# 15. Custom Detector Configuration
# ---------------------------------------------------------------------------

def test_scenario_15_custom_detector_configuration(db_session):
    config = RateAnomalyDetectorConfig(request_threshold=2, time_window_seconds=10, min_confidence=0.8)
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"cust-{i}", timestamp=now - timedelta(seconds=i))
        for i in range(1, 3)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].request_count == 2
    assert result.evidences[0].confidence_score >= 0.80


# ---------------------------------------------------------------------------
# 16. Pagination / Complete-Window Behavior
# ---------------------------------------------------------------------------

def test_scenario_16_pagination_complete_window_behavior(db_session):
    """Verifies that a burst exceeding standard single-page limits is retrieved across pages without truncation."""
    config = RateAnomalyDetectorConfig(request_threshold=60, time_window_seconds=30)
    now = datetime.now(timezone.utc)

    # Insert 80 rapid requests
    logs = [
        create_traffic_log(f"burst-{i}", timestamp=now - timedelta(seconds=i * 0.2))
        for i in range(1, 81)
    ]
    db_session.add_all(logs)
    db_session.commit()

    # If page_size=50 and fetch_full_window=True, it should retrieve all 80 records across pages
    result = analyze_traffic_for_rate_anomaly(
        page=1,
        page_size=50,
        fetch_full_window=True,
        detector_config=config,
        db=db_session
    )
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.analyzed_event_count == 80
    assert result.anomalous_request_count == 80


# ---------------------------------------------------------------------------
# 17. Malformed Traffic Record Handling
# ---------------------------------------------------------------------------

def test_scenario_17_malformed_traffic_record(db_session):
    now = datetime.now(timezone.utc)
    valid_logs = [
        create_traffic_log(f"ok-{i}", timestamp=now - timedelta(seconds=i))
        for i in range(1, 6)
    ]
    malformed_log = APITrafficLog(
        request_id="",
        timestamp=now,
        method="GET",
        path="",
        query_params={},
        client_ip="192.168.1.100",
        user_agent="Bad",
        status_code=200,
        response_time_ms=5.0
    )
    db_session.add_all(valid_logs + [malformed_log])
    db_session.commit()

    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    result = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].request_count == 5


def test_convert_traffic_log_malformed():
    assert convert_traffic_log_to_rate_anomaly_event(None) is None

    bad_log1 = APITrafficLog(request_id="", path="/search", method="GET", client_ip="1.1.1.1", status_code=200, response_time_ms=5.0)
    with pytest.raises(ValueError, match="request_id"):
        convert_traffic_log_to_rate_anomaly_event(bad_log1)

    bad_log2 = APITrafficLog(request_id="r1", path="", method="GET", client_ip="1.1.1.1", status_code=200, response_time_ms=5.0)
    with pytest.raises(ValueError, match="path"):
        convert_traffic_log_to_rate_anomaly_event(bad_log2)


# ---------------------------------------------------------------------------
# 18. Deterministic Result
# ---------------------------------------------------------------------------

def test_scenario_18_deterministic_result(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"det-{i}", timestamp=now - timedelta(seconds=i))
        for i in range(1, 7)
    ]
    db_session.add_all(logs)
    db_session.commit()

    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    res1 = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)
    res2 = analyze_traffic_for_rate_anomaly(detector_config=config, db=db_session)

    assert res1.verdict == res2.verdict
    assert res1.analyzed_event_count == res2.analyzed_event_count
    assert res1.anomalous_request_count == res2.anomalous_request_count
    assert len(res1.evidences) == len(res2.evidences)
    assert res1.evidences[0].confidence_score == res2.evidences[0].confidence_score
    assert res1.evidences[0].explanation == res2.evidences[0].explanation


# ---------------------------------------------------------------------------
# 19. No Sensitive Credentials in Result
# ---------------------------------------------------------------------------

def test_scenario_19_no_sensitive_credentials_in_result(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(
            f"sec-{i}",
            query_params={"token": "***MASKED***", "password": "***MASKED***"},
            timestamp=now - timedelta(seconds=i)
        )
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers_map = {
        f"sec-{i}": {
            "Authorization": "Bearer super-secret-rate-token",
            "Cookie": "session_id=secret-session-rate",
            "X-User-ID": "actor_rate_safe",
        }
        for i in range(1, 6)
    }

    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    result = analyze_traffic_for_rate_anomaly(
        headers_map=headers_map,
        detector_config=config,
        db=db_session
    )
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    ev = result.evidences[0]

    assert ev.actor_id == "actor_rate_safe"
    assert "Bearer" not in ev.explanation
    assert "super-secret-rate-token" not in ev.explanation
    assert "super-secret-rate-token" not in result.summary


# ---------------------------------------------------------------------------
# 20. Direct Event Analysis (analyze_events_directly)
# ---------------------------------------------------------------------------

def test_scenario_20_direct_event_analysis():
    now = datetime.now(timezone.utc)
    events = [
        RateAnomalyEvent(
            request_id=f"dir-{i}",
            timestamp=now - timedelta(seconds=i),
            method="GET",
            path="/api/v1/feed",
            client_ip="192.0.2.77",
            actor_id="actor_dir",
            status_code=200,
        )
        for i in range(1, 6)
    ]

    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    result = analyze_events_directly(events, detector_config=config)
    assert isinstance(result, RateAnomalyDetectionResult)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.analyzed_event_count == 5
    assert len(result.evidences) == 1
    assert result.evidences[0].client_ip == "192.0.2.77"
    assert result.evidences[0].actor_id == "actor_dir"


# ---------------------------------------------------------------------------
# 21. Bounded Analysis Window
# ---------------------------------------------------------------------------

def test_scenario_21_bounded_analysis_window(db_session):
    now = datetime.now(timezone.utc)
    # 20 records distributed across 20 minutes
    logs = [
        create_traffic_log(f"bw-{i}", timestamp=now - timedelta(minutes=i))
        for i in range(1, 21)
    ]
    db_session.add_all(logs)
    db_session.commit()

    # Query strictly a 5-minute window
    start_time = now - timedelta(minutes=7)
    end_time = now - timedelta(minutes=2)

    result = analyze_traffic_for_rate_anomaly(
        start_time=start_time,
        end_time=end_time,
        db=db_session
    )
    assert result.analyzed_event_count == 6


# ---------------------------------------------------------------------------
# 22. No Accidental Unbounded Database Retrieval
# ---------------------------------------------------------------------------

def test_scenario_22_no_unbounded_database_retrieval(db_session):
    now = datetime.now(timezone.utc)
    # Insert 150 records
    logs = [
        create_traffic_log(f"bulk-{i}", timestamp=now - timedelta(seconds=i * 0.1))
        for i in range(1, 151)
    ]
    db_session.add_all(logs)
    db_session.commit()

    # Set max_records=50 safety ceiling
    fetched = _fetch_traffic_records(
        page=1,
        page_size=20,
        max_records=50,
        fetch_full_window=True,
        db=db_session
    )
    assert len(fetched) == 50
