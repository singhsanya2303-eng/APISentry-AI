"""
Tests for Behavioral Analysis & Feature Extraction Service — Module 7, Step 1.

Comprehensive test suite verifying normalized event generation and behavioral feature extraction:
  1. Empty input
  2. Single normal request
  3. Multiple endpoints
  4. Multiple resource types
  5. Multiple resource IDs
  6. Successful requests
  7. Failed requests
  8. Authentication failures
  9. Missing client IP
  10. Missing actor ID
  11. UTC timestamp handling
  12. Observation window calculation
  13. Endpoint normalization
  14. BOLA signal metadata
  15. Brute-force signal metadata
  16. Rate anomaly signal metadata
  17. Mixed detection signals
  18. Malformed event handling
  19. Deterministic output
  20. No sensitive credential data
  21. Correct aggregation by client IP
  22. Correct counting of unique resources
  23. Correct counting of unique endpoints
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import pytest

from app.db.base import Base
from app.models.traffic import APITrafficLog
from app.schemas.behavior import (
    BehaviorEvent,
    BehaviorFeatures,
    BehaviorAnalysisResult,
)
from app.services.behavior_analysis_service import (
    convert_traffic_log_to_behavior_event,
    extract_features_for_events,
    extract_features_from_traffic_logs,
)


def create_traffic_log(
    request_id: str,
    path: str = "/api/v1/users/101",
    method: str = "GET",
    status_code: int = 200,
    client_ip: Optional[str] = "192.168.1.100",
    query_params: Optional[Dict[str, Any]] = None,
    user_agent: str = "TestClient/1.0",
    response_time_ms: float = 10.0,
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
# 1. Empty Input
# ---------------------------------------------------------------------------

def test_scenario_1_empty_input():
    result = extract_features_for_events([])
    assert isinstance(result, BehaviorAnalysisResult)
    assert result.analyzed_event_count == 0
    assert result.distinct_client_count == 0
    assert result.distinct_actor_count == 0
    assert len(result.client_features) == 0
    assert "No behavioral events" in result.summary


# ---------------------------------------------------------------------------
# 2. Single Normal Request
# ---------------------------------------------------------------------------

def test_scenario_2_single_normal_request():
    now = datetime.now(timezone.utc)
    log = create_traffic_log("r1", path="/api/v1/orders/42", timestamp=now, client_ip="10.0.0.5")
    result = extract_features_from_traffic_logs([log])

    assert result.analyzed_event_count == 1
    assert result.distinct_client_count == 1
    feat = result.client_features[0]

    assert feat.client_ip == "10.0.0.5"
    assert feat.total_requests == 1
    assert feat.unique_endpoints == 1
    assert feat.unique_resource_types == 1
    assert feat.unique_resource_ids == 1
    assert feat.successful_request_count == 1
    assert feat.failed_request_count == 0
    assert feat.authentication_failure_count == 0
    assert feat.observation_window_seconds == 0.0


# ---------------------------------------------------------------------------
# 3. Multiple Endpoints
# ---------------------------------------------------------------------------

def test_scenario_3_multiple_endpoints():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", path="/api/v1/orders/1", timestamp=now - timedelta(seconds=20)),
        create_traffic_log("r2", path="/api/v1/users/99", timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r3", path="/api/v1/products/500", timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.unique_endpoints == 3
    assert feat.total_requests == 3


# ---------------------------------------------------------------------------
# 4. Multiple Resource Types
# ---------------------------------------------------------------------------

def test_scenario_4_multiple_resource_types():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", path="/api/v1/invoices/101", timestamp=now - timedelta(seconds=15)),
        create_traffic_log("r2", path="/api/v1/customers/202", timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r3", path="/api/v1/shipments/303", timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.unique_resource_types == 3


# ---------------------------------------------------------------------------
# 5. Multiple Resource IDs
# ---------------------------------------------------------------------------

def test_scenario_5_multiple_resource_ids():
    now = datetime.now(timezone.utc)
    # Same resource type 'accounts', accessing 4 distinct IDs
    logs = [
        create_traffic_log(f"r{i}", path=f"/api/v1/accounts/{i}", timestamp=now - timedelta(seconds=i))
        for i in range(1, 5)
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.unique_resource_types == 1
    assert feat.unique_resource_ids == 4


# ---------------------------------------------------------------------------
# 6. Successful Requests
# ---------------------------------------------------------------------------

def test_scenario_6_successful_requests():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", status_code=200, timestamp=now - timedelta(seconds=5)),
        create_traffic_log("r2", status_code=201, timestamp=now - timedelta(seconds=3)),
        create_traffic_log("r3", status_code=204, timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.successful_request_count == 3
    assert feat.failed_request_count == 0


# ---------------------------------------------------------------------------
# 7. Failed Requests
# ---------------------------------------------------------------------------

def test_scenario_7_failed_requests():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", status_code=400, timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r2", status_code=404, timestamp=now - timedelta(seconds=5)),
        create_traffic_log("r3", status_code=500, timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.failed_request_count == 3
    assert feat.successful_request_count == 0


# ---------------------------------------------------------------------------
# 8. Authentication Failures
# ---------------------------------------------------------------------------

def test_scenario_8_authentication_failures():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", status_code=401, timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r2", status_code=401, timestamp=now - timedelta(seconds=5)),
        create_traffic_log("r3", status_code=403, timestamp=now),  # 403 is failed but not 401
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.authentication_failure_count == 2
    assert feat.failed_request_count == 3


# ---------------------------------------------------------------------------
# 9. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_9_missing_client_ip():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("noip-1", client_ip="", timestamp=now),
        create_traffic_log("noip-2", client_ip=None, timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    assert result.analyzed_event_count == 2
    assert result.distinct_client_count == 0
    assert len(result.client_features) == 0


# ---------------------------------------------------------------------------
# 10. Missing Actor ID
# ---------------------------------------------------------------------------

def test_scenario_10_missing_actor_id():
    now = datetime.now(timezone.utc)
    log = create_traffic_log("r1", client_ip="172.16.0.99", timestamp=now)
    result = extract_features_from_traffic_logs([log])
    feat = result.client_features[0]
    assert feat.actor_id is None
    assert feat.client_ip == "172.16.0.99"


# ---------------------------------------------------------------------------
# 11. UTC Timestamp Handling
# ---------------------------------------------------------------------------

def test_scenario_11_utc_timestamp_handling():
    now_aware = datetime.now(timezone.utc)
    now_naive = now_aware.replace(tzinfo=None)

    events = [
        BehaviorEvent(request_id="e1", timestamp=now_aware, client_ip="1.1.1.1", method="GET", path="/a", normalized_endpoint="/a", status_code=200),
        BehaviorEvent(request_id="e2", timestamp=now_naive, client_ip="1.1.1.1", method="GET", path="/b", normalized_endpoint="/b", status_code=200),
    ]
    result = extract_features_for_events(events)
    feat = result.client_features[0]
    assert feat.first_seen.tzinfo is not None
    assert feat.last_seen.tzinfo is not None


# ---------------------------------------------------------------------------
# 12. Observation Window Calculation
# ---------------------------------------------------------------------------

def test_scenario_12_observation_window_calculation():
    base_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    logs = [
        create_traffic_log("t1", timestamp=base_time),
        create_traffic_log("t2", timestamp=base_time + timedelta(seconds=120.5)),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.observation_window_seconds == 120.5


# ---------------------------------------------------------------------------
# 13. Endpoint Normalization
# ---------------------------------------------------------------------------

def test_scenario_13_endpoint_normalization():
    log = create_traffic_log("r1", path="/api/v1/tenants/55/reports/999")
    event = convert_traffic_log_to_behavior_event(log)
    assert event is not None
    assert event.normalized_endpoint == "/api/v1/tenants/{tenant_id}/reports/{report_id}"
    assert event.resource_type == "reports"
    assert event.resource_id == "999"


# ---------------------------------------------------------------------------
# 14. BOLA Signal Metadata
# ---------------------------------------------------------------------------

def test_scenario_14_bola_signal_metadata():
    log = create_traffic_log("r1")
    signals = {"r1": {"detection_source": "bola", "detection_verdict": "suspicious_bola_candidate"}}
    result = extract_features_from_traffic_logs([log], signals_map=signals)
    feat = result.client_features[0]
    assert feat.bola_candidate_count == 1
    assert feat.brute_force_candidate_count == 0
    assert feat.rate_anomaly_count == 0


# ---------------------------------------------------------------------------
# 15. Brute-Force Signal Metadata
# ---------------------------------------------------------------------------

def test_scenario_15_bruteforce_signal_metadata():
    log = create_traffic_log("r1", status_code=401)
    signals = {"r1": {"detection_source": "bruteforce", "detection_verdict": "suspicious_bruteforce_candidate"}}
    result = extract_features_from_traffic_logs([log], signals_map=signals)
    feat = result.client_features[0]
    assert feat.brute_force_candidate_count == 1
    assert feat.bola_candidate_count == 0
    assert feat.rate_anomaly_count == 0


# ---------------------------------------------------------------------------
# 16. Rate Anomaly Signal Metadata
# ---------------------------------------------------------------------------

def test_scenario_16_rate_anomaly_signal_metadata():
    log = create_traffic_log("r1")
    signals = {"r1": {"detection_source": "rate_anomaly", "detection_verdict": "suspicious_rate_anomaly"}}
    result = extract_features_from_traffic_logs([log], signals_map=signals)
    feat = result.client_features[0]
    assert feat.rate_anomaly_count == 1
    assert feat.bola_candidate_count == 0
    assert feat.brute_force_candidate_count == 0


# ---------------------------------------------------------------------------
# 17. Mixed Detection Signals
# ---------------------------------------------------------------------------

def test_scenario_17_mixed_detection_signals():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", timestamp=now - timedelta(seconds=30)),
        create_traffic_log("r2", timestamp=now - timedelta(seconds=20), status_code=401),
        create_traffic_log("r3", timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r4", timestamp=now),
    ]
    signals = {
        "r1": {"detection_source": "bola", "detection_verdict": "suspicious_bola_candidate"},
        "r2": {"detection_source": "bruteforce", "detection_verdict": "suspicious_bruteforce_candidate"},
        "r3": {"detection_source": "rate_anomaly", "detection_verdict": "suspicious_rate_anomaly"},
    }
    result = extract_features_from_traffic_logs(logs, signals_map=signals)
    feat = result.client_features[0]
    assert feat.total_requests == 4
    assert feat.bola_candidate_count == 1
    assert feat.brute_force_candidate_count == 1
    assert feat.rate_anomaly_count == 1


# ---------------------------------------------------------------------------
# 18. Malformed Event Handling
# ---------------------------------------------------------------------------

def test_scenario_18_malformed_event_handling():
    now = datetime.now(timezone.utc)
    valid_log = create_traffic_log("ok-1", timestamp=now)
    malformed_log = APITrafficLog(
        request_id="",
        timestamp=now,
        method="GET",
        path="",
        query_params={},
        client_ip="1.1.1.1",
        user_agent="C",
        status_code=200,
        response_time_ms=5.0
    )
    result = extract_features_from_traffic_logs([valid_log, malformed_log])
    assert result.analyzed_event_count == 1
    assert len(result.client_features) == 1


def test_convert_traffic_log_malformed_exceptions():
    assert convert_traffic_log_to_behavior_event(None) is None

    bad1 = APITrafficLog(request_id="", path="/a", method="GET", client_ip="1.1.1.1", status_code=200, response_time_ms=5.0)
    with pytest.raises(ValueError, match="request_id"):
        convert_traffic_log_to_behavior_event(bad1)

    bad2 = APITrafficLog(request_id="r1", path="", method="GET", client_ip="1.1.1.1", status_code=200, response_time_ms=5.0)
    with pytest.raises(ValueError, match="path"):
        convert_traffic_log_to_behavior_event(bad2)


# ---------------------------------------------------------------------------
# 19. Deterministic Output
# ---------------------------------------------------------------------------

def test_scenario_19_deterministic_output():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log(f"r{i}", timestamp=now - timedelta(seconds=i), path=f"/api/v1/items/{i}")
        for i in range(5)
    ]
    res1 = extract_features_from_traffic_logs(logs)
    res2 = extract_features_from_traffic_logs(logs)

    assert res1.analyzed_event_count == res2.analyzed_event_count
    assert res1.client_features[0].unique_resource_ids == res2.client_features[0].unique_resource_ids
    assert res1.client_features[0].observation_window_seconds == res2.client_features[0].observation_window_seconds


# ---------------------------------------------------------------------------
# 20. No Sensitive Credential Data
# ---------------------------------------------------------------------------

def test_scenario_20_no_sensitive_credentials():
    now = datetime.now(timezone.utc)
    log = create_traffic_log(
        "sec-1",
        query_params={"password": "***MASKED***", "token": "***MASKED***"},
        timestamp=now
    )
    headers = {
        "sec-1": {
            "Authorization": "Bearer confidential-token-12345",
            "Cookie": "session=secret-cookie",
            "X-User-ID": "safe_actor_999",
        }
    }
    result = extract_features_from_traffic_logs([log], headers_map=headers)
    feat = result.client_features[0]

    assert feat.actor_id == "safe_actor_999"
    result_text = result.model_dump_json()
    assert "confidential-token-12345" not in result_text
    assert "secret-cookie" not in result_text
    assert "Bearer" not in result_text


# ---------------------------------------------------------------------------
# 21. Correct Aggregation by Client IP
# ---------------------------------------------------------------------------

def test_scenario_21_correct_aggregation_by_client_ip():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("a1", client_ip="10.0.0.1", timestamp=now - timedelta(seconds=5)),
        create_traffic_log("a2", client_ip="10.0.0.1", timestamp=now),
        create_traffic_log("b1", client_ip="10.0.0.2", timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    assert result.distinct_client_count == 2

    feat_a = next(f for f in result.client_features if f.client_ip == "10.0.0.1")
    feat_b = next(f for f in result.client_features if f.client_ip == "10.0.0.2")

    assert feat_a.total_requests == 2
    assert feat_b.total_requests == 1


# ---------------------------------------------------------------------------
# 22. Correct Counting of Unique Resources
# ---------------------------------------------------------------------------

def test_scenario_22_correct_counting_of_unique_resources():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", path="/api/v1/orders/100", timestamp=now - timedelta(seconds=20)),
        create_traffic_log("r2", path="/api/v1/orders/100", timestamp=now - timedelta(seconds=10)),  # duplicate ID
        create_traffic_log("r3", path="/api/v1/orders/200", timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    assert feat.total_requests == 3
    assert feat.unique_resource_ids == 2
    assert feat.unique_resource_types == 1


# ---------------------------------------------------------------------------
# 23. Correct Counting of Unique Endpoints
# ---------------------------------------------------------------------------

def test_scenario_23_correct_counting_of_unique_endpoints():
    now = datetime.now(timezone.utc)
    logs = [
        create_traffic_log("r1", path="/api/v1/orders/100", timestamp=now - timedelta(seconds=20)),
        create_traffic_log("r2", path="/api/v1/orders/200", timestamp=now - timedelta(seconds=10)),
        create_traffic_log("r3", path="/api/v1/orders/300", timestamp=now),
    ]
    result = extract_features_from_traffic_logs(logs)
    feat = result.client_features[0]
    # All 3 paths normalize to /api/v1/orders/{order_id} -> 1 unique endpoint
    assert feat.unique_endpoints == 1
    assert feat.unique_resource_ids == 3
