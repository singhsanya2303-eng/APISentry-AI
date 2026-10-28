from datetime import datetime, timedelta, timezone
import pytest
from app.services.resource_extractor import extract_resource_access_event
from app.detection.bola_detector import BolaDetector, BolaDetectorConfig
from app.schemas.bola import DetectionVerdict


def create_event(
    request_id: str,
    path: str,
    actor_id: str = "actor_100",
    status_code: int = 200,
    method: str = "GET",
    timestamp: datetime = None
):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    headers = {"X-User-ID": actor_id} if actor_id else {}
    return extract_resource_access_event(
        request_id=request_id,
        timestamp=timestamp,
        method=method,
        path=path,
        client_ip="192.168.1.10",
        status_code=status_code,
        headers=headers
    )


def test_scenario_1_same_actor_single_object():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_2_same_actor_multiple_distinct_objects():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/105", actor_id="user_a"),
        create_event("req-3", "/users/109", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    ev = result.evidences[0]
    assert ev.actor_id == "user_a"
    assert ev.resource_type == "users"
    assert ev.distinct_object_count == 3
    assert set(ev.accessed_object_ids) == {"101", "105", "109"}
    assert ev.is_sequential is False


def test_scenario_3_sequential_object_ids():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/102", actor_id="user_a"),
        create_event("req-3", "/users/103", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    ev = result.evidences[0]
    assert ev.is_sequential is True
    assert ev.confidence_score >= 0.90
    assert "Sequential access pattern detected" in ev.explanation


def test_scenario_4_different_actors_different_objects():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/102", actor_id="user_b"),
        create_event("req-3", "/users/103", actor_id="user_c")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_5_missing_actor_identity():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id=None),
        create_event("req-2", "/users/102", actor_id=None),
        create_event("req-3", "/users/103", actor_id=None)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.INSUFFICIENT_EVIDENCE
    assert len(result.evidences) == 0
    assert "lacked non-sensitive actor identity" in result.explanation


def test_scenario_6_same_object_repeatedly_accessed():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/101", actor_id="user_a"),
        create_event("req-3", "/users/101", actor_id="user_a"),
        create_event("req-4", "/users/101", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_7_different_resource_types():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/orders/201", actor_id="user_a"),
        create_event("req-3", "/accounts/301", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_8_static_endpoints():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/health", actor_id="user_a"),
        create_event("req-2", "/users/profile", actor_id="user_a"),
        create_event("req-3", "/api/v1/docs", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_9_low_confidence_resource_extraction():
    detector = BolaDetector(BolaDetectorConfig(min_extraction_confidence=0.70))
    # /123/456 yields confidence 0.40
    events = [
        create_event("req-1", "/123/456", actor_id="user_a"),
        create_event("req-2", "/123/457", actor_id="user_a"),
        create_event("req-3", "/123/458", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_10_successful_multi_object_access():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/orders/5001", actor_id="user_a", status_code=200),
        create_event("req-2", "/orders/5002", actor_id="user_a", status_code=200),
        create_event("req-3", "/orders/5003", actor_id="user_a", status_code=200)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    ev = result.evidences[0]
    assert ev.successful_access_count == 3
    assert ev.client_error_count == 0
    assert ev.confidence_score >= 0.90


def test_scenario_11_failed_multi_object_requests():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/orders/5001", actor_id="user_a", status_code=403),
        create_event("req-2", "/orders/5002", actor_id="user_a", status_code=404),
        create_event("req-3", "/orders/5003", actor_id="user_a", status_code=403)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    ev = result.evidences[0]
    assert ev.successful_access_count == 0
    assert ev.client_error_count == 3
    assert ev.confidence_score < 0.85
    assert "were unsuccessful" in ev.explanation


def test_scenario_12_nested_resources():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/api/v1/accounts/42/orders/91", actor_id="user_a"),
        create_event("req-2", "/api/v1/accounts/42/orders/92", actor_id="user_a"),
        create_event("req-3", "/api/v1/accounts/42/orders/93", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    ev = result.evidences[0]
    assert ev.resource_type == "orders"
    assert ev.normalized_endpoint == "/api/v1/accounts/{account_id}/orders/{order_id}"
    assert ev.distinct_object_count == 3


def test_scenario_13_multiple_actors_in_same_window():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/102", actor_id="user_a"),
        create_event("req-3", "/users/103", actor_id="user_a"),
        create_event("req-4", "/users/200", actor_id="user_b")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].actor_id == "user_a"


def test_scenario_14_explanation_and_evidence_population():
    detector = BolaDetector()
    events = [
        create_event("req-1", "/orders/10", actor_id="user_7", status_code=200),
        create_event("req-2", "/orders/11", actor_id="user_7", status_code=200),
        create_event("req-3", "/orders/12", actor_id="user_7", status_code=500)
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    ev = result.evidences[0]
    assert ev.actor_id == "user_7"
    assert ev.resource_type == "orders"
    assert ev.distinct_object_count == 3
    assert ev.request_ids == ["req-1", "req-2", "req-3"]
    assert ev.methods == ["GET", "GET", "GET"]
    assert ev.status_codes == [200, 200, 500]
    assert ev.successful_access_count == 2
    assert ev.server_error_count == 1
    assert "user_7" in ev.explanation
    assert "orders" in ev.explanation


def test_scenario_15_threshold_configuration():
    # Lower threshold to min_distinct_objects = 2
    custom_config = BolaDetectorConfig(min_distinct_objects=2)
    detector = BolaDetector(custom_config)

    events = [
        create_event("req-1", "/users/101", actor_id="user_a"),
        create_event("req-2", "/users/102", actor_id="user_a")
    ]
    result = detector.analyze_events(events)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].distinct_object_count == 2
