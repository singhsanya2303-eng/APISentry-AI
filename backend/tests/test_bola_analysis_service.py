from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.models.traffic import APITrafficLog
from app.services.bola_analysis_service import analyze_traffic_for_bola, analyze_events_directly
from app.schemas.bola import DetectionVerdict
from app.detection.bola_detector import BolaDetectorConfig


@pytest.fixture
def db_session():
    """Fixture creating an in-memory SQLite database for integration testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()


def test_scenario_1_empty_traffic_dataset(db_session):
    result = analyze_traffic_for_bola(db=db_session)
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert result.analyzed_event_count == 0
    assert len(result.evidences) == 0
    assert "No traffic events" in result.explanation


def test_scenario_2_one_normal_object_request(db_session):
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="req-single-1",
        timestamp=now,
        method="GET",
        path="/users/101",
        query_params={},
        client_ip="192.168.1.10",
        user_agent="TestClient",
        status_code=200,
        response_time_ms=12.0
    )
    db_session.add(log)
    db_session.commit()

    headers = {"req-single-1": {"X-User-ID": "actor_99"}}
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert result.analyzed_event_count == 1
    assert len(result.evidences) == 0


def test_scenario_3_same_actor_accessing_multiple_objects(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now - timedelta(minutes=5), method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now - timedelta(minutes=3), method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now - timedelta(minutes=1), method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {
        "r1": {"X-User-ID": "actor_1"},
        "r2": {"X-User-ID": "actor_1"},
        "r3": {"X-User-ID": "actor_1"},
    }
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert result.analyzed_event_count == 3
    assert len(result.evidences) == 1
    ev = result.evidences[0]
    assert ev.actor_id == "actor_1"
    assert ev.distinct_object_count == 3


def test_scenario_4_missing_actor_identity(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    # No headers mapping provided -> missing actor_id
    result = analyze_traffic_for_bola(headers_map={}, db=db_session)

    assert result.verdict == DetectionVerdict.INSUFFICIENT_EVIDENCE
    assert result.analyzed_event_count == 3
    assert len(result.evidences) == 0


def test_scenario_5_nested_resource_access(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now - timedelta(minutes=5), method="GET", path="/api/v1/accounts/42/orders/91", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now - timedelta(minutes=3), method="GET", path="/api/v1/accounts/42/orders/92", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now - timedelta(minutes=1), method="GET", path="/api/v1/accounts/42/orders/93", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-Actor-ID": "actor_nest"} for r in logs}
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    ev = result.evidences[0]
    assert ev.resource_type == "orders"
    assert ev.normalized_endpoint == "/api/v1/accounts/{account_id}/orders/{order_id}"


def test_scenario_6_multiple_actors(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r4", timestamp=now, method="GET", path="/users/200", query_params={}, client_ip="10.0.0.2", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {
        "r1": {"X-User-ID": "actor_a"},
        "r2": {"X-User-ID": "actor_a"},
        "r3": {"X-User-ID": "actor_a"},
        "r4": {"X-User-ID": "actor_b"},
    }
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].actor_id == "actor_a"


def test_scenario_7_static_endpoints(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/health", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/health", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/health", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_a"} for r in logs}
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_8_low_confidence_resource_extraction(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/123/456", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/123/457", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/123/458", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_a"} for r in logs}
    config = BolaDetectorConfig(min_extraction_confidence=0.70)
    result = analyze_traffic_for_bola(detector_config=config, headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
    assert len(result.evidences) == 0


def test_scenario_9_mixed_successful_failed_responses(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/orders/10", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/orders/11", query_params={}, client_ip="10.0.0.1", status_code=403, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/orders/12", query_params={}, client_ip="10.0.0.1", status_code=500, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_mix"} for r in logs}
    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    ev = result.evidences[0]
    assert ev.successful_access_count == 1
    assert ev.client_error_count == 1
    assert ev.server_error_count == 1


def test_scenario_10_custom_detector_configuration(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_thresh"} for r in logs}
    config = BolaDetectorConfig(min_distinct_objects=2)
    result = analyze_traffic_for_bola(detector_config=config, headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1


def test_scenario_11_time_window_filtering(db_session):
    now = datetime.now(timezone.utc)
    t_start = now - timedelta(minutes=15)
    t_end = now

    logs = [
        APITrafficLog(request_id="r_old", timestamp=now - timedelta(hours=3), method="GET", path="/users/1", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r1", timestamp=now - timedelta(minutes=10), method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now - timedelta(minutes=5), method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now - timedelta(minutes=1), method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_window"} for r in logs}
    result = analyze_traffic_for_bola(start_time=t_start, end_time=t_end, headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert result.analyzed_event_count == 3
    assert "r_old" not in result.evidences[0].request_ids


def test_scenario_12_existing_traffic_query_filters(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r4", timestamp=now, method="POST", path="/users/104", query_params={}, client_ip="10.0.0.99", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_ip"} for r in logs}
    result = analyze_traffic_for_bola(client_ip="192.168.1.50", headers_map=headers, db=db_session)

    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert result.analyzed_event_count == 3
    assert set(result.evidences[0].accessed_object_ids) == {"101", "102", "103"}


def test_scenario_13_no_sensitive_credential_data_in_analysis(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={"password": "***MASKED***"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={"token": "***MASKED***"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={"secret": "***MASKED***"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {
        "r1": {"Authorization": "Bearer sensitive_token_xyz", "X-User-ID": "actor_safe"},
        "r2": {"Cookie": "session=secret_session", "X-User-ID": "actor_safe"},
        "r3": {"X-API-Key": "secret_key_123", "X-User-ID": "actor_safe"},
    }

    result = analyze_traffic_for_bola(headers_map=headers, db=db_session)
    result_json = result.model_dump_json()

    assert "sensitive_token_xyz" not in result_json
    assert "secret_session" not in result_json
    assert "secret_key_123" not in result_json
    assert "actor_safe" in result_json


def test_scenario_14_detector_result_consistency(db_session):
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    db_session.add_all(logs)
    db_session.commit()

    headers = {r.request_id: {"X-User-ID": "actor_const"} for r in logs}

    result1 = analyze_traffic_for_bola(headers_map=headers, db=db_session)
    result2 = analyze_traffic_for_bola(headers_map=headers, db=db_session)

    assert result1.verdict == result2.verdict
    assert result1.evidences[0].confidence_score == result2.evidences[0].confidence_score
    assert result1.evidences[0].explanation == result2.evidences[0].explanation


def test_scenario_15_defensive_malformed_input_handling(db_session, monkeypatch):
    now = datetime.now(timezone.utc)
    valid_log = APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0)
    malformed_log = APITrafficLog(request_id=None, timestamp=now, method="GET", path=None, query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0)

    # Patch get_traffic_logs to return valid_log, malformed_log, and None
    monkeypatch.setattr("app.services.bola_analysis_service.get_traffic_logs", lambda **kwargs: [valid_log, malformed_log, None])

    result = analyze_traffic_for_bola(headers_map={"r1": {"X-User-ID": "actor_def"}}, db=db_session)
    assert result.analyzed_event_count == 1
    assert result.verdict == DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
