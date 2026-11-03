"""
Tests for RateAnomalyDetector — Module 6, Step 1.

Comprehensive test suite verifying the rate anomaly detection engine across all core scenarios:
  1. Empty input
  2. Single request
  3. Low normal request rate
  4. Threshold not reached
  5. Threshold reached
  6. Very high request rate
  7. Requests outside the time window
  8. Multiple clients analyzed independently
  9. Missing client IP
  10. Missing actor ID but valid client IP
  11. Different endpoints
  12. Same endpoint rapid requests
  13. Mixed HTTP status codes
  14. UTC timestamp handling
  15. Configurable threshold
  16. Configurable time window
  17. Deterministic result
  18. No sensitive credentials in result
  19. Malformed/missing timestamp handling
  20. Explanation and evidence correctness
  21. Client-wide vs endpoint scope
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest

from app.detection.rate_anomaly_detector import (
    RateAnomalyDetector,
    RateAnomalyDetectorConfig,
    _normalise_path,
    _ensure_utc,
)
from app.schemas.rate_anomaly import (
    RateAnomalyEvent,
    RateAnomalyVerdict,
    RateAnomalyDetectionResult,
)


def make_event(
    request_id: str,
    path: str = "/api/v1/orders",
    method: str = "GET",
    client_ip: Optional[str] = "192.168.1.100",
    actor_id: Optional[str] = None,
    status_code: int = 200,
    timestamp: Optional[datetime] = None,
    ts_offset_seconds: float = 0.0,
    base_time: Optional[datetime] = None,
) -> RateAnomalyEvent:
    """Helper to create RateAnomalyEvent instances for testing."""
    if timestamp is None:
        base = base_time or datetime.now(timezone.utc)
        timestamp = base + timedelta(seconds=ts_offset_seconds)
    return RateAnomalyEvent(
        request_id=request_id,
        timestamp=timestamp,
        method=method,
        path=path,
        client_ip=client_ip,
        actor_id=actor_id,
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# 1. Empty Input
# ---------------------------------------------------------------------------

def test_scenario_1_empty_input():
    detector = RateAnomalyDetector()
    result = detector.analyze_events([])
    assert isinstance(result, RateAnomalyDetectionResult)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert result.analyzed_event_count == 0
    assert result.anomalous_request_count == 0
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 2. Single Request
# ---------------------------------------------------------------------------

def test_scenario_2_single_request():
    detector = RateAnomalyDetector()
    events = [make_event("req-1")]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert result.analyzed_event_count == 1
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 3. Low Normal Request Rate
# ---------------------------------------------------------------------------

def test_scenario_3_low_normal_request_rate():
    detector = RateAnomalyDetector()  # default threshold = 50
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"req-{i}", ts_offset_seconds=-i * 5, base_time=now)
        for i in range(1, 10)  # 9 requests over 45s
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert result.analyzed_event_count == 9
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 4. Threshold Not Reached
# ---------------------------------------------------------------------------

def test_scenario_4_threshold_not_reached():
    config = RateAnomalyDetectorConfig(request_threshold=10, time_window_seconds=30)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"req-{i}", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 10)  # 9 requests < 10
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 5. Threshold Reached
# ---------------------------------------------------------------------------

def test_scenario_5_threshold_reached():
    config = RateAnomalyDetectorConfig(request_threshold=10, time_window_seconds=30)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"req-{i}", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 11)  # exactly 10 requests == threshold
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.analyzed_event_count == 10
    assert result.anomalous_request_count == 10
    assert len(result.evidences) == 1

    ev = result.evidences[0]
    assert ev.client_ip == "192.168.1.100"
    assert ev.request_count == 10
    assert ev.time_window_seconds == 30.0
    assert ev.requests_per_second == round(10 / 30.0, 3)
    assert ev.confidence_score >= 0.70


# ---------------------------------------------------------------------------
# 6. Very High Request Rate
# ---------------------------------------------------------------------------

def test_scenario_6_very_high_request_rate():
    config = RateAnomalyDetectorConfig(request_threshold=50, time_window_seconds=10)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"flood-{i}", ts_offset_seconds=-(i * 0.05), base_time=now)
        for i in range(1, 101)  # 100 requests in 5 seconds
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.anomalous_request_count == 100
    ev = result.evidences[0]
    assert ev.requests_per_second == round(100 / 10.0, 3)  # 10.0 req/sec
    assert ev.requests_per_minute == round(10.0 * 60.0, 2)  # 600.0 req/min
    assert ev.confidence_score >= 0.85


# ---------------------------------------------------------------------------
# 7. Requests Outside Time Window
# ---------------------------------------------------------------------------

def test_scenario_7_requests_outside_time_window():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=10)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    # 4 old requests (60s ago) + 2 recent requests (now)
    events = [
        make_event(f"old-{i}", ts_offset_seconds=-(60 + i), base_time=now)
        for i in range(1, 5)
    ] + [
        make_event(f"recent-{i}", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 3)
    ]
    result = detector.analyze_events(events)
    # Only 2 requests within the 10s window relative to latest ts -> below threshold 5
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 8. Multiple Clients Analyzed Independently
# ---------------------------------------------------------------------------

def test_scenario_8_multiple_clients_analyzed_independently():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=20)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)

    # Client A: 6 requests (triggers anomaly)
    events_a = [
        make_event(f"a-{i}", client_ip="10.0.0.1", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 7)
    ]
    # Client B: 3 requests (normal)
    events_b = [
        make_event(f"b-{i}", client_ip="10.0.0.2", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 4)
    ]
    result = detector.analyze_events(events_a + events_b)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert len(result.evidences) == 1
    assert result.evidences[0].client_ip == "10.0.0.1"
    assert result.distinct_client_count == 1


# ---------------------------------------------------------------------------
# 9. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_9_missing_client_ip():
    detector = RateAnomalyDetector()
    events = [
        make_event(f"noip-{i}", client_ip=None)
        for i in range(1, 10)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.INSUFFICIENT_EVIDENCE
    assert result.analyzed_event_count == 9
    assert "lacked a client IP" in result.summary


# ---------------------------------------------------------------------------
# 10. Missing Actor ID but Valid Client IP
# ---------------------------------------------------------------------------

def test_scenario_10_missing_actor_id_valid_client_ip():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"req-{i}", client_ip="172.16.0.1", actor_id=None, ts_offset_seconds=-i, base_time=now)
        for i in range(1, 6)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].actor_id is None
    assert result.evidences[0].client_ip == "172.16.0.1"


# ---------------------------------------------------------------------------
# 11. Different Endpoints
# ---------------------------------------------------------------------------

def test_scenario_11_different_endpoints():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30, scope="endpoint")
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)

    # 3 requests to /api/v1/orders + 3 requests to /api/v1/users (neither reaches 5 under endpoint scope)
    events = [
        make_event(f"o-{i}", path="/api/v1/orders", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 4)
    ] + [
        make_event(f"u-{i}", path="/api/v1/users", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 4)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
    assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# 12. Same Endpoint Rapid Requests
# ---------------------------------------------------------------------------

def test_scenario_12_same_endpoint_rapid_requests():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=10)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"rapid-{i}", path="/api/v1/search", ts_offset_seconds=-i * 0.5, base_time=now)
        for i in range(1, 7)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].analyzed_endpoint == "/api/v1/search"
    assert result.evidences[0].request_count == 6


# ---------------------------------------------------------------------------
# 13. Mixed HTTP Status Codes
# ---------------------------------------------------------------------------

def test_scenario_13_mixed_http_status_codes():
    config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=20)
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)
    statuses = [200, 201, 304, 400, 404, 500]
    events = [
        make_event(f"stat-{i}", status_code=statuses[i % len(statuses)], ts_offset_seconds=-i, base_time=now)
        for i in range(6)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.evidences[0].request_count == 6
    assert set(result.evidences[0].status_codes) == set(statuses)


# ---------------------------------------------------------------------------
# 14. UTC Timestamp Handling
# ---------------------------------------------------------------------------

def test_scenario_14_utc_timestamp_handling():
    config = RateAnomalyDetectorConfig(request_threshold=3, time_window_seconds=10)
    detector = RateAnomalyDetector(config)

    # Mix of naive (UTC without tzinfo attached) and timezone-aware datetimes
    now_aware = datetime.now(timezone.utc)
    now_naive = now_aware.replace(tzinfo=None)

    events = [
        make_event("ts-1", timestamp=now_aware - timedelta(seconds=2)),
        make_event("ts-2", timestamp=now_naive - timedelta(seconds=1)),
        make_event("ts-3", timestamp=now_aware),
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    for ts in result.evidences[0].timestamps:
        assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# 15. Configurable Threshold
# ---------------------------------------------------------------------------

def test_scenario_15_configurable_threshold():
    config_low = RateAnomalyDetectorConfig(request_threshold=3)
    detector_low = RateAnomalyDetector(config_low)

    config_high = RateAnomalyDetectorConfig(request_threshold=20)
    detector_high = RateAnomalyDetector(config_high)

    events = [make_event(f"r-{i}") for i in range(5)]

    res_low = detector_low.analyze_events(events)
    assert res_low.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY

    res_high = detector_high.analyze_events(events)
    assert res_high.verdict == RateAnomalyVerdict.NO_ANOMALY


# ---------------------------------------------------------------------------
# 16. Configurable Time Window
# ---------------------------------------------------------------------------

def test_scenario_16_configurable_time_window():
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"w-{i}", ts_offset_seconds=-i * 10, base_time=now)
        for i in range(5)  # timestamps at 0s, -10s, -20s, -30s, -40s
    ]

    # 15s window captures only 2 events (< threshold of 4)
    det_narrow = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=4, time_window_seconds=15))
    res_narrow = det_narrow.analyze_events(events)
    assert res_narrow.verdict == RateAnomalyVerdict.NO_ANOMALY

    # 60s window captures all 5 events (>= threshold of 4)
    det_wide = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=4, time_window_seconds=60))
    res_wide = det_wide.analyze_events(events)
    assert res_wide.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY


# ---------------------------------------------------------------------------
# 17. Deterministic Result
# ---------------------------------------------------------------------------

def test_scenario_17_deterministic_result():
    detector = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30))
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"det-{i}", ts_offset_seconds=-i, base_time=now)
        for i in range(6)
    ]
    res1 = detector.analyze_events(events)
    res2 = detector.analyze_events(events)

    assert res1.verdict == res2.verdict
    assert res1.analyzed_event_count == res2.analyzed_event_count
    assert res1.anomalous_request_count == res2.anomalous_request_count
    assert len(res1.evidences) == len(res2.evidences)
    assert res1.evidences[0].confidence_score == res2.evidences[0].confidence_score
    assert res1.evidences[0].explanation == res2.evidences[0].explanation


# ---------------------------------------------------------------------------
# 18. No Sensitive Credentials in Result
# ---------------------------------------------------------------------------

def test_scenario_18_no_sensitive_credentials_in_result():
    detector = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=30))
    now = datetime.now(timezone.utc)

    # Actor ID containing accidental credential string
    secret_str = "Bearer secret-token-xyz123"
    events = [
        make_event(f"sec-{i}", actor_id=secret_str, ts_offset_seconds=-i, base_time=now)
        for i in range(6)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY

    ev = result.evidences[0]
    assert secret_str not in ev.explanation
    assert secret_str not in result.summary


# ---------------------------------------------------------------------------
# 19. Malformed / Missing Timestamp Handling
# ---------------------------------------------------------------------------

def test_scenario_19_missing_timestamp_handling():
    detector = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=3, time_window_seconds=60))
    events = [
        make_event("ts-none-1", timestamp=None),
        make_event("ts-none-2", timestamp=None),
        make_event("ts-none-3", timestamp=None),
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.analyzed_event_count == 3


# ---------------------------------------------------------------------------
# 20. Explanation / Evidence Correctness
# ---------------------------------------------------------------------------

def test_scenario_20_explanation_and_evidence_correctness():
    detector = RateAnomalyDetector(RateAnomalyDetectorConfig(request_threshold=10, time_window_seconds=20))
    now = datetime.now(timezone.utc)
    events = [
        make_event(f"ev-{i}", client_ip="198.51.100.77", path="/api/v1/data", actor_id="user_admin", ts_offset_seconds=-i, base_time=now)
        for i in range(12)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    ev = result.evidences[0]

    assert ev.client_ip == "198.51.100.77"
    assert ev.actor_id == "user_admin"
    assert ev.analyzed_endpoint == "/api/v1/data"
    assert ev.request_count == 12
    assert ev.time_window_seconds == 20.0
    assert ev.requests_per_second == 0.6
    assert ev.requests_per_minute == 36.0
    assert "198.51.100.77" in ev.explanation
    assert "/api/v1/data" in ev.explanation
    assert "0.6 req/sec" in ev.explanation
    assert "12 requests" in ev.explanation


# ---------------------------------------------------------------------------
# 21. Client-Wide Scope
# ---------------------------------------------------------------------------

def test_scenario_21_client_wide_scope():
    config = RateAnomalyDetectorConfig(request_threshold=6, time_window_seconds=30, scope="client_wide")
    detector = RateAnomalyDetector(config)
    now = datetime.now(timezone.utc)

    # 3 requests to /endpointA + 3 requests to /endpointB
    events = [
        make_event(f"a-{i}", path="/api/v1/endpointA", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 4)
    ] + [
        make_event(f"b-{i}", path="/api/v1/endpointB", ts_offset_seconds=-i, base_time=now)
        for i in range(1, 4)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert len(result.evidences) == 1
    assert result.evidences[0].analyzed_endpoint == "CLIENT_WIDE"
    assert result.evidences[0].request_count == 6


# ---------------------------------------------------------------------------
# Helper Unit Tests
# ---------------------------------------------------------------------------

def test_normalise_path_helper():
    assert _normalise_path("/API/V1/Users/") == "/api/v1/users"
    assert _normalise_path("/") == "/"
    assert _normalise_path("") == "/"


def test_ensure_utc_helper():
    dt_aware = datetime.now(timezone.utc)
    assert _ensure_utc(dt_aware) == dt_aware

    dt_naive = datetime(2026, 1, 1, 12, 0, 0)
    res = _ensure_utc(dt_naive)
    assert res.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Verification: Batch-Anchored Time Window Behavior on Trailing Events
# ---------------------------------------------------------------------------

class TestBatchAnchoredWindowBehavior:
    """
    Verifies the exact behavior of the Step 1 batch-anchored time window algorithm.
    The current Step 1 implementation filters the entire batch using:
        window_start = latest_event_timestamp - time_window_seconds
    """

    def test_trailing_single_request_anchors_window_away_from_earlier_burst(self):
        """
        Configuration: threshold=5, window=60s, scope=client_wide.
        Events:
          12:00:00 -> 5 requests
          12:00:01 -> 1 request
          12:01:00 -> 1 request
          12:05:00 -> 1 request (trailing event 4 minutes later)

        Under the Step 1 batch-anchored window:
          - latest_ts = 12:05:00
          - window_start = 12:04:00
          - Only the single 12:05:00 request falls into [12:04:00, 12:05:00]
          - Result: NO_ANOMALY (the earlier 12:00 burst is excluded by the batch anchor).
        """
        config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=60, scope="client_wide")
        detector = RateAnomalyDetector(config)

        base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            # 12:00:00 -> 5 requests
            make_event(f"e-0-{i}", timestamp=base_time, client_ip="client_A")
            for i in range(5)
        ] + [
            # 12:00:01 -> 1 request
            make_event("e-1", timestamp=base_time + timedelta(seconds=1), client_ip="client_A"),
            # 12:01:00 -> 1 request
            make_event("e-60", timestamp=base_time + timedelta(seconds=60), client_ip="client_A"),
            # 12:05:00 -> 1 request
            make_event("e-300", timestamp=base_time + timedelta(seconds=300), client_ip="client_A"),
        ]

        result = detector.analyze_events(events)
        assert result.verdict == RateAnomalyVerdict.NO_ANOMALY
        assert len(result.evidences) == 0

    def test_burst_with_trailing_request_five_minutes_later(self):
        """
        Events:
          12:00:00 -> 5 rapid requests from client A
          12:00:10 -> 1 request from client A
          12:05:00 -> 1 request from client A (5 minutes later)

        Under the batch-anchored window:
          - latest_ts is 12:05:00
          - window_start is 12:04:00
          - Only the 12:05:00 request is in window (count=1 < 5)
          - Original burst is NOT detected in this batch run.
        """
        config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=60, scope="client_wide")
        detector = RateAnomalyDetector(config)

        base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            # 12:00:00 -> 5 requests
            make_event(f"b-{i}", timestamp=base_time, client_ip="client_A")
            for i in range(5)
        ] + [
            # 12:00:10 -> 1 request
            make_event("b-10", timestamp=base_time + timedelta(seconds=10), client_ip="client_A"),
            # 12:05:00 -> 1 request
            make_event("b-300", timestamp=base_time + timedelta(seconds=300), client_ip="client_A"),
        ]

        result = detector.analyze_events(events)
        assert result.verdict == RateAnomalyVerdict.NO_ANOMALY

    def test_burst_without_distant_trailing_event_is_detected(self):
        """
        When the batch contains only the burst window [12:00:00 - 12:00:10]:
          - latest_ts is 12:00:10
          - window_start is 11:59:10
          - All 6 requests fall in window -> SUSPICIOUS_RATE_ANOMALY.
        """
        config = RateAnomalyDetectorConfig(request_threshold=5, time_window_seconds=60, scope="client_wide")
        detector = RateAnomalyDetector(config)

        base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            make_event(f"b-{i}", timestamp=base_time, client_ip="client_A")
            for i in range(5)
        ] + [
            make_event("b-10", timestamp=base_time + timedelta(seconds=10), client_ip="client_A"),
        ]

        result = detector.analyze_events(events)
        assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
        assert len(result.evidences) == 1
        assert result.evidences[0].request_count == 6
