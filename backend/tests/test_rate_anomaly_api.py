"""
Tests for Rate Anomaly FastAPI Endpoint — Module 6, Step 3.

Endpoint:
    GET /api/v1/security/rate-anomaly/analyze

Scenarios covered:
  1. Endpoint exists (HTTP 200)
  2. Empty traffic result
  3. Normal low-rate traffic
  4. Threshold-level traffic
  5. Suspicious high-rate traffic
  6. Missing client IP
  7. Multiple client IPs
  8. Different endpoints
  9. Endpoint scope
  10. Client-wide scope
  11. Mixed HTTP status codes
  12. Query filters
  13. Date/time filtering
  14. Invalid page (422)
  15. Invalid page_size (422)
  16. Invalid status_code (422)
  17. Invalid scope (422)
  18. Invalid detector threshold (422)
  19. Invalid time window (422)
  20. Invalid confidence (422)
  21. Detector configuration override
  22. Response schema validation
  23. No sensitive credential information
  24. Existing BOLA API still works
  25. Existing Brute-Force API still works
  26. Existing health endpoints still work
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models.traffic import APITrafficLog

client = TestClient(app)


@pytest.fixture
def override_db():
    """Fixture overriding get_db dependency with isolated in-memory SQLite database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def _get_test_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_test_db
    yield TestingSessionLocal
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. Endpoint Exists
# ---------------------------------------------------------------------------

def test_scenario_1_endpoint_exists(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert "analyzed_event_count" in data
    assert "summary" in data


# ---------------------------------------------------------------------------
# 2. Empty Traffic Result
# ---------------------------------------------------------------------------

def test_scenario_2_empty_traffic(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_anomaly"
    assert data["analyzed_event_count"] == 0
    assert data["anomalous_request_count"] == 0
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 3. Normal Low-Rate Traffic
# ---------------------------------------------------------------------------

def test_scenario_3_normal_low_rate_traffic(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"r-{i}", timestamp=now - timedelta(seconds=i * 10), method="GET", path="/api/v1/search", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 5)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_anomaly"
    assert data["analyzed_event_count"] == 4
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 4. Threshold-Level Traffic
# ---------------------------------------------------------------------------

def test_scenario_4_threshold_level_traffic(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"t-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/search", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=5&time_window_seconds=30")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert data["analyzed_event_count"] == 5
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["request_count"] == 5


# ---------------------------------------------------------------------------
# 5. Suspicious High-Rate Traffic
# ---------------------------------------------------------------------------

def test_scenario_5_suspicious_high_rate_traffic(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"flood-{i}", timestamp=now - timedelta(seconds=i * 0.1), method="POST", path="/api/v1/orders", query_params={}, client_ip="198.51.100.99", user_agent="Bot", status_code=200, response_time_ms=5.0)
        for i in range(1, 26)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=20&time_window_seconds=10")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert data["anomalous_request_count"] == 25
    assert data["evidences"][0]["requests_per_second"] == 2.5


# ---------------------------------------------------------------------------
# 6. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_6_missing_client_ip(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"noip-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/search", query_params={}, client_ip="", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "insufficient_evidence"
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 7. Multiple Client IPs
# ---------------------------------------------------------------------------

def test_scenario_7_multiple_client_ips(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs_a = [
        APITrafficLog(request_id=f"ipA-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/search", query_params={}, client_ip="10.0.0.1", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 6)
    ]
    logs_b = [
        APITrafficLog(request_id=f"ipB-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/search", query_params={}, client_ip="10.0.0.2", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 3)
    ]
    session.add_all(logs_a + logs_b)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=5&time_window_seconds=30")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["client_ip"] == "10.0.0.1"
    assert data["distinct_client_count"] == 1


# ---------------------------------------------------------------------------
# 8. Different Endpoints
# ---------------------------------------------------------------------------

def test_scenario_8_different_endpoints(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"e1-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/orders", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 4)
    ] + [
        APITrafficLog(request_id=f"e2-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/users", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 4)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    # Scope=endpoint (default) with threshold=5 -> neither reaches 5
    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=5&time_window_seconds=30&scope=endpoint")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_anomaly"


# ---------------------------------------------------------------------------
# 9. Endpoint Scope
# ---------------------------------------------------------------------------

def test_scenario_9_endpoint_scope(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"ep-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/items", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=5&time_window_seconds=30&scope=endpoint")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert data["evidences"][0]["analyzed_endpoint"] == "/api/v1/items"


# ---------------------------------------------------------------------------
# 10. Client-Wide Scope
# ---------------------------------------------------------------------------

def test_scenario_10_client_wide_scope(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"cw1-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/orders", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 4)
    ] + [
        APITrafficLog(request_id=f"cw2-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/users", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 4)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    # Client-wide scope pools requests across all endpoints
    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=6&time_window_seconds=30&scope=client_wide")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert data["evidences"][0]["analyzed_endpoint"] == "CLIENT_WIDE"
    assert data["evidences"][0]["request_count"] == 6


# ---------------------------------------------------------------------------
# 11. Mixed HTTP Status Codes
# ---------------------------------------------------------------------------

def test_scenario_11_mixed_http_status_codes(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    statuses = [200, 201, 304, 400, 500]
    logs = [
        APITrafficLog(request_id=f"mix-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/feed", query_params={}, client_ip="192.168.1.10", user_agent="C", status_code=statuses[i], response_time_ms=5.0)
        for i in range(5)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=5&time_window_seconds=30")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert set(data["evidences"][0]["status_codes"]) == set(statuses)


# ---------------------------------------------------------------------------
# 12. Query Filters
# ---------------------------------------------------------------------------

def test_scenario_12_query_filters(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="q1", timestamp=now, method="POST", path="/api/v1/search", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="q2", timestamp=now, method="POST", path="/api/v1/search", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="q3", timestamp=now, method="GET", path="/api/v1/search", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="q4", timestamp=now, method="POST", path="/api/v1/other", query_params={}, client_ip="10.0.0.1", user_agent="C", status_code=200, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?client_ip=192.168.1.100&method=POST")
    assert response.status_code == 200
    data = response.json()
    assert data["analyzed_event_count"] == 2


# ---------------------------------------------------------------------------
# 13. Date/Time Filtering
# ---------------------------------------------------------------------------

def test_scenario_13_datetime_filtering(override_db):
    now = datetime.now(timezone.utc)
    t1 = quote((now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    t2 = quote((now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))

    response = client.get(f"/api/v1/security/rate-anomaly/analyze?start_time={t1}&end_time={t2}")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 14. Invalid Page (422)
# ---------------------------------------------------------------------------

def test_scenario_14_invalid_page(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze?page=0")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 15. Invalid Page Size (422)
# ---------------------------------------------------------------------------

def test_scenario_15_invalid_page_size(override_db):
    response_large = client.get("/api/v1/security/rate-anomaly/analyze?page_size=1000")
    assert response_large.status_code == 422

    response_zero = client.get("/api/v1/security/rate-anomaly/analyze?page_size=0")
    assert response_zero.status_code == 422


# ---------------------------------------------------------------------------
# 16. Invalid Status Code (422)
# ---------------------------------------------------------------------------

def test_scenario_16_invalid_status_code(override_db):
    response_low = client.get("/api/v1/security/rate-anomaly/analyze?status_code=99")
    assert response_low.status_code == 422

    response_high = client.get("/api/v1/security/rate-anomaly/analyze?status_code=600")
    assert response_high.status_code == 422


# ---------------------------------------------------------------------------
# 17. Invalid Scope (422)
# ---------------------------------------------------------------------------

def test_scenario_17_invalid_scope(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze?scope=invalid_scope_name")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 18. Invalid Detector Threshold (422)
# ---------------------------------------------------------------------------

def test_scenario_18_invalid_detector_threshold(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=1")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 19. Invalid Time Window (422)
# ---------------------------------------------------------------------------

def test_scenario_19_invalid_time_window(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze?time_window_seconds=0")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 20. Invalid Confidence (422)
# ---------------------------------------------------------------------------

def test_scenario_20_invalid_confidence(override_db):
    response_high = client.get("/api/v1/security/rate-anomaly/analyze?min_confidence=1.5")
    assert response_high.status_code == 422

    response_low = client.get("/api/v1/security/rate-anomaly/analyze?min_confidence=-0.1")
    assert response_low.status_code == 422


# ---------------------------------------------------------------------------
# 21. Detector Configuration Override
# ---------------------------------------------------------------------------

def test_scenario_21_detector_config_override(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"ov-{i}", timestamp=now - timedelta(seconds=i), method="GET", path="/api/v1/test", query_params={}, client_ip="192.168.99.1", user_agent="C", status_code=200, response_time_ms=5.0)
        for i in range(1, 3)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze?request_threshold=2&time_window_seconds=10&min_confidence=0.75&scope=client_wide")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_rate_anomaly"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["request_count"] == 2
    assert data["evidences"][0]["analyzed_endpoint"] == "CLIENT_WIDE"


# ---------------------------------------------------------------------------
# 22. Response Schema Validation
# ---------------------------------------------------------------------------

def test_scenario_22_response_schema_validation(override_db):
    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    data = response.json()

    assert "verdict" in data
    assert "analyzed_event_count" in data
    assert "anomalous_request_count" in data
    assert "distinct_client_count" in data
    assert "distinct_actor_count" in data
    assert "evidences" in data
    assert "summary" in data
    assert isinstance(data["evidences"], list)


# ---------------------------------------------------------------------------
# 23. No Sensitive Credentials in Response
# ---------------------------------------------------------------------------

def test_scenario_23_no_sensitive_credentials(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"sec-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={"token": "***MASKED***", "password": "***MASKED***"},
            client_ip="192.168.1.10",
            user_agent="SecTest",
            status_code=200,
            response_time_ms=5.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/rate-anomaly/analyze")
    assert response.status_code == 200
    text_content = response.text

    assert "Bearer" not in text_content
    assert "Authorization" not in text_content
    assert "password" not in text_content or "***MASKED***" in text_content


# ---------------------------------------------------------------------------
# 24. Existing BOLA API Still Works
# ---------------------------------------------------------------------------

def test_scenario_24_existing_bola_api_works(override_db):
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert data["verdict"] == "no_suspicious_behavior"


# ---------------------------------------------------------------------------
# 25. Existing Brute-Force API Still Works
# ---------------------------------------------------------------------------

def test_scenario_25_existing_bruteforce_api_works(override_db):
    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert data["verdict"] == "no_bruteforce_detected"


# ---------------------------------------------------------------------------
# 26. Existing Health Endpoints Still Work
# ---------------------------------------------------------------------------

def test_scenario_26_existing_health_endpoints_work(override_db):
    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "healthy"

    res_v1 = client.get("/api/v1/health")
    assert res_v1.status_code == 200
    assert res_v1.json()["status"] == "healthy"
