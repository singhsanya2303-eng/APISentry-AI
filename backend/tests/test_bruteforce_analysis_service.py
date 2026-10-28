"""
Tests for BruteForceAnalysisService — Module 5, Step 2.

Comprehensive integration test suite verifying the complete pipeline:
  APITrafficLog (DB) -> BruteForceAnalysisService -> BruteForceEvent -> BruteForceDetector -> BruteForceDetectionResult

Scenarios covered:
  1. Empty traffic dataset
  2. Single failed login
  3. Multiple failed logins from same IP (below threshold)
  4. Threshold reached (suspicious candidate)
  5. Attempts outside detector time window
  6. 401 login failures
  7. 403 login responses
  8. Successful login responses (2xx)
  9. Non-authentication endpoint returning 401
  10. Multiple client IPs
  11. Missing actor_id but valid client_ip
  12. Missing client_ip
  13. Nested/variant auth paths
  14. Existing traffic filters are respected
  15. Custom BruteForceDetectorConfig
  16. Mixed success/failure responses
  17. Malformed traffic record handling
  18. No sensitive credential values in analysis output
  19. Deterministic result
  20. Detector result is returned correctly by the service
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
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
from app.services.bruteforce_analysis_service import (
    analyze_traffic_for_bruteforce,
    analyze_events_directly,
    convert_traffic_log_to_bruteforce_event,
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
    path: str = "/api/v1/auth/login",
    status_code: int = 401,
    client_ip: Optional[str] = "192.168.1.100",
    method: str = "POST",
    query_params: Optional[Dict[str, Any]] = None,
    user_agent: str = "TestBrowser/1.0",
    response_time_ms: float = 15.0,
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
        client_ip=client_ip,
        user_agent=user_agent,
        status_code=status_code,
        response_time_ms=response_time_ms,
    )


# ---------------------------------------------------------------------------
# Scenario 1: Empty Traffic Dataset
# ---------------------------------------------------------------------------

def test_scenario_1_empty_traffic_dataset(db_session):
    """When no traffic logs exist, service returns NO_BRUTEFORCE_DETECTED cleanly."""
    result = analyze_traffic_for_bruteforce(db=db_session)
    assert isinstance(result, BruteForceDetectionResult)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.analyzed_event_count == 0
    assert result.failed_attempt_count == 0
    assert len(result.evidences) == 0
    assert "No traffic events" in result.summary


# ---------------------------------------------------------------------------
# Scenario 2: Single Failed Login
# ---------------------------------------------------------------------------

def test_scenario_2_single_failed_login(db_session):
    """A single 401 failure is below threshold -> NO_BRUTEFORCE_DETECTED."""
    log = create_traffic_log("req-1", status_code=401)
    db_session.add(log)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.analyzed_event_count == 1
    assert result.failed_attempt_count == 1
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 3: Multiple Failed Logins from Same IP (Below Threshold)
# ---------------------------------------------------------------------------

def test_scenario_3_multiple_failed_logins_below_threshold(db_session):
    """4 failures < default threshold of 5 -> NO_BRUTEFORCE_DETECTED."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"req-{i}", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 5)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.analyzed_event_count == 4
    assert result.failed_attempt_count == 4
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 4: Threshold Reached
# ---------------------------------------------------------------------------

def test_scenario_4_threshold_reached(db_session):
    """5 failures == threshold -> SUSPICIOUS_BRUTEFORCE_CANDIDATE."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"req-{i}", status_code=401, client_ip="192.168.1.100", timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert result.analyzed_event_count == 5
    assert result.failed_attempt_count == 5
    assert len(result.evidences) == 1

    ev = result.evidences[0]
    assert ev.client_ip == "192.168.1.100"
    assert ev.auth_endpoint == "/api/v1/auth/login"
    assert ev.failed_attempt_count == 5
    assert ev.confidence_score >= 0.70


# ---------------------------------------------------------------------------
# Scenario 5: Attempts Outside Detector Time Window
# ---------------------------------------------------------------------------

def test_scenario_5_attempts_outside_detector_time_window(db_session):
    """Failures occurring outside the 15-minute window are excluded from candidate grouping."""
    now = datetime.now(timezone.utc)
    # 4 old failures (30m ago) + 1 recent failure (now)
    logs = [
        create_traffic_log(f"old-{i}", status_code=401, timestamp=now - timedelta(minutes=30 + i))
        for i in range(1, 5)
    ] + [
        create_traffic_log("recent-1", status_code=401, timestamp=now)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 6: 401 Login Failures
# ---------------------------------------------------------------------------

def test_scenario_6_401_login_failures(db_session):
    """401 status codes on authentication endpoints are specifically classified as auth failures."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"fail-{i}", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 7)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert result.failed_attempt_count == 6
    assert result.evidences[0].failed_attempt_count == 6


# ---------------------------------------------------------------------------
# Scenario 7: 403 Login Responses
# ---------------------------------------------------------------------------

def test_scenario_7_403_login_responses(db_session):
    """HTTP 403 (Forbidden) is NOT counted as an authentication failure."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"forb-{i}", status_code=403, timestamp=now - timedelta(minutes=i))
        for i in range(1, 8)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.failed_attempt_count == 0
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 8: Successful Login Responses (2xx)
# ---------------------------------------------------------------------------

def test_scenario_8_successful_login_responses(db_session):
    """HTTP 200 responses are successful authentications and do not trigger brute-force candidate."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"succ-{i}", status_code=200, timestamp=now - timedelta(minutes=i))
        for i in range(1, 8)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.failed_attempt_count == 0
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 9: Non-Authentication Endpoint Returning 401
# ---------------------------------------------------------------------------

def test_scenario_9_non_authentication_endpoint_returning_401(db_session):
    """401 responses on non-auth endpoints (e.g. /api/v1/orders) must NOT participate in brute-force detection."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"order-{i}", path="/api/v1/orders/99", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 8)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.failed_attempt_count == 0
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 10: Multiple Client IPs
# ---------------------------------------------------------------------------

def test_scenario_10_multiple_client_ips(db_session):
    """IP attribution keeps distinct client IPs separate."""
    now = datetime.now(timezone.utc)
    # IP A: 5 failures (candidate)
    logs_a = [
        create_traffic_log(f"ipA-{i}", client_ip="10.0.0.1", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    # IP B: 2 failures (below threshold)
    logs_b = [
        create_traffic_log(f"ipB-{i}", client_ip="10.0.0.2", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 3)
    ]
    db_session.add_all(logs_a + logs_b)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].client_ip == "10.0.0.1"
    assert result.distinct_client_count == 2


# ---------------------------------------------------------------------------
# Scenario 11: Missing actor_id but Valid client_ip
# ---------------------------------------------------------------------------

def test_scenario_11_missing_actor_id_but_valid_client_ip(db_session):
    """Missing actor_id does not hinder detection when valid client_ip is present."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"noactor-{i}", client_ip="172.16.0.5", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    # No headers_map passed -> actor_id is None
    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].client_ip == "172.16.0.5"
    assert result.evidences[0].actor_id is None
    assert result.distinct_actor_count == 0


# ---------------------------------------------------------------------------
# Scenario 12: Missing client_ip
# ---------------------------------------------------------------------------

def test_scenario_12_missing_client_ip(db_session):
    """Missing or empty client_ip results in safe exclusion from IP attribution."""
    now = datetime.now(timezone.utc)
    # APITrafficLog schema enforces non-null string, so empty string represents missing IP in storage
    logs = [
        create_traffic_log(f"noip-{i}", client_ip="", status_code=401, timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.INSUFFICIENT_EVIDENCE
    assert result.analyzed_event_count == 5
    assert len(result.evidences) == 0
    assert "lacked a client IP" in result.summary


def test_convert_traffic_log_with_none_client_ip():
    """convert_traffic_log_to_bruteforce_event preserves client_ip=None when client_ip attribute is None."""
    class DummyLog:
        request_id = "dummy-1"
        timestamp = datetime.now(timezone.utc)
        method = "POST"
        path = "/api/v1/auth/login"
        client_ip = None
        status_code = 401
        query_params = {}

    event = convert_traffic_log_to_bruteforce_event(DummyLog())
    assert event is not None
    assert event.client_ip is None
    assert event.request_id == "dummy-1"


# ---------------------------------------------------------------------------
# Scenario 13: Nested / Variant Auth Paths
# ---------------------------------------------------------------------------

def test_scenario_13_nested_variant_auth_paths(db_session):
    """Recognized auth endpoints like /login, /auth/login, /api/v2/auth/login are matched."""
    now = datetime.now(timezone.utc)
    logs_v2 = [
        create_traffic_log(f"v2-{i}", path="/api/v2/auth/login", status_code=401, client_ip="10.10.10.10", timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    logs_nonauth = [
        create_traffic_log(f"nonauth-{i}", path="/api/v2/users/auth-status", status_code=401, client_ip="10.10.10.10", timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    db_session.add_all(logs_v2 + logs_nonauth)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].auth_endpoint == "/api/v2/auth/login"


# ---------------------------------------------------------------------------
# Scenario 14: Existing Traffic Filters Are Respected
# ---------------------------------------------------------------------------

def test_scenario_14_existing_traffic_filters_respected(db_session):
    """Traffic query filters (method, path, client_ip, status_code, start_time/end_time) are honored."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("f1", path="/api/v1/auth/login", method="POST", client_ip="192.168.1.1", status_code=401, timestamp=now - timedelta(minutes=2)),
        create_traffic_log("f2", path="/api/v1/auth/login", method="POST", client_ip="192.168.1.1", status_code=401, timestamp=now - timedelta(minutes=1)),
        create_traffic_log("f3", path="/api/v1/auth/login", method="GET", client_ip="192.168.1.1", status_code=401, timestamp=now),
        create_traffic_log("f4", path="/api/v1/other", method="POST", client_ip="192.168.1.2", status_code=401, timestamp=now),
    ]
    db_session.add_all(logs)
    db_session.commit()

    # Filter by method="POST" and client_ip="192.168.1.1"
    result = analyze_traffic_for_bruteforce(
        method="POST",
        client_ip="192.168.1.1",
        db=db_session
    )
    assert result.analyzed_event_count == 2
    assert result.failed_attempt_count == 2


# ---------------------------------------------------------------------------
# Scenario 15: Custom BruteForceDetectorConfig
# ---------------------------------------------------------------------------

def test_scenario_15_custom_detector_config(db_session):
    """Custom threshold and time window configuration are respected."""
    custom_config = BruteForceDetectorConfig(
        failure_threshold=2,
        time_window_minutes=5
    )
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("c1", status_code=401, client_ip="192.168.5.5", timestamp=now - timedelta(minutes=1)),
        create_traffic_log("c2", status_code=401, client_ip="192.168.5.5", timestamp=now),
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(
        detector_config=custom_config,
        db=db_session
    )
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].failed_attempt_count == 2


# ---------------------------------------------------------------------------
# Scenario 16: Mixed Success / Failure Responses
# ---------------------------------------------------------------------------

def test_scenario_16_mixed_success_failure_responses(db_session):
    """Evidence accurately tracks successful 2xx responses alongside 401 failures."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"f-{i}", status_code=401, client_ip="10.0.0.50", timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ] + [
        create_traffic_log("s-1", status_code=200, client_ip="10.0.0.50", timestamp=now)
    ]
    db_session.add_all(logs)
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    ev = result.evidences[0]
    assert ev.failed_attempt_count == 5
    assert ev.successful_attempt_count == 1
    assert 200 in ev.status_codes


# ---------------------------------------------------------------------------
# Scenario 17: Malformed Traffic Record Handling
# ---------------------------------------------------------------------------

def test_scenario_17_malformed_traffic_record_handling(db_session):
    """Malformed individual traffic records are safely skipped without breaking the analysis."""
    now = datetime.now(timezone.utc)
    valid_logs = [
        create_traffic_log(f"valid-{i}", status_code=401, client_ip="10.0.0.99", timestamp=now - timedelta(minutes=i))
        for i in range(1, 6)
    ]
    # Incomplete / corrupted log
    malformed_log = APITrafficLog(
        request_id="",  # Empty request_id
        timestamp=now,
        method="POST",
        path="",        # Empty path
        query_params={},
        client_ip="10.0.0.99",
        user_agent="BadClient",
        status_code=401,
        response_time_ms=10.0
    )
    db_session.add_all(valid_logs + [malformed_log])
    db_session.commit()

    result = analyze_traffic_for_bruteforce(db=db_session)
    # The 5 valid records should still trigger candidate
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].failed_attempt_count == 5


def test_convert_traffic_log_malformed_inputs():
    """Unit test for convert_traffic_log_to_bruteforce_event with malformed inputs."""
    assert convert_traffic_log_to_bruteforce_event(None) is None

    # Missing request_id
    bad_log1 = APITrafficLog(request_id="", path="/login", method="POST", client_ip="1.1.1.1", status_code=401, response_time_ms=5.0)
    with pytest.raises(ValueError, match="request_id"):
        convert_traffic_log_to_bruteforce_event(bad_log1)

    # Missing path
    bad_log2 = APITrafficLog(request_id="r1", path="", method="POST", client_ip="1.1.1.1", status_code=401, response_time_ms=5.0)
    with pytest.raises(ValueError, match="path"):
        convert_traffic_log_to_bruteforce_event(bad_log2)


# ---------------------------------------------------------------------------
# Scenario 18: No Sensitive Credential Values in Analysis Output
# ---------------------------------------------------------------------------

def test_scenario_18_no_sensitive_credentials_in_analysis_output(db_session):
    """Never derives actor_id or exposes secrets from Authorization/Cookie/Token headers."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(
            f"sec-{i}",
            query_params={"token": "***MASKED***", "password": "***MASKED***", "safe_tag": "public"},
            status_code=401,
            timestamp=now - timedelta(minutes=i)
        )
        for i in range(1, 6)
    ]
    db_session.add_all(logs)
    db_session.commit()

    # Pass headers with sensitive auth tokens
    headers_map = {
        f"sec-{i}": {
            "Authorization": "Bearer super-secret-token-12345",
            "Cookie": "sessionid=secret-cookie-val",
            "X-API-Key": "my-secret-api-key",
            "X-User-ID": "safe_actor_42",
        }
        for i in range(1, 6)
    }

    result = analyze_traffic_for_bruteforce(headers_map=headers_map, db=db_session)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    ev = result.evidences[0]

    # Safe actor_id is extracted
    assert ev.actor_id == "safe_actor_42"

    # None of the secret tokens leak into any result text
    secret_strings = ["super-secret-token-12345", "secret-cookie-val", "my-secret-api-key", "Bearer"]
    for secret in secret_strings:
        assert secret not in ev.explanation
        assert secret not in result.summary


# ---------------------------------------------------------------------------
# Scenario 19: Deterministic Result
# ---------------------------------------------------------------------------

def test_scenario_19_deterministic_result(db_session):
    """Running analysis twice on the exact same database records produces identical results."""
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"det-{i}", status_code=401, client_ip="10.20.30.40", timestamp=now - timedelta(minutes=i))
        for i in range(1, 7)
    ]
    db_session.add_all(logs)
    db_session.commit()

    res1 = analyze_traffic_for_bruteforce(db=db_session)
    res2 = analyze_traffic_for_bruteforce(db=db_session)

    assert res1.verdict == res2.verdict
    assert res1.analyzed_event_count == res2.analyzed_event_count
    assert res1.failed_attempt_count == res2.failed_attempt_count
    assert len(res1.evidences) == len(res2.evidences)
    assert res1.evidences[0].confidence_score == res2.evidences[0].confidence_score
    assert res1.evidences[0].explanation == res2.evidences[0].explanation


# ---------------------------------------------------------------------------
# Scenario 20: Direct Event Analysis and Detector Result Return
# ---------------------------------------------------------------------------

def test_scenario_20_direct_event_analysis():
    """analyze_events_directly passes events straight to the detector engine."""
    now = datetime.now(timezone.utc)
    events = [
        BruteForceEvent(
            request_id=f"direct-{i}",
            timestamp=now - timedelta(minutes=i),
            method="POST",
            path="/api/v1/auth/login",
            client_ip="192.0.2.99",
            actor_id="actor_direct",
            status_code=401,
            authentication_failure=True
        )
        for i in range(1, 6)
    ]

    result = analyze_events_directly(events)
    assert isinstance(result, BruteForceDetectionResult)
    assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
    assert result.analyzed_event_count == 5
    assert len(result.evidences) == 1
    assert result.evidences[0].actor_id == "actor_direct"
    assert result.evidences[0].client_ip == "192.0.2.99"
