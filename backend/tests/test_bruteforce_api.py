"""
Tests for Brute-Force FastAPI Endpoint — Module 5, Step 3.

Endpoint:
    GET /api/v1/security/bruteforce/analyze

Scenarios covered:
  1. Endpoint exists (HTTP 200)
  2. Empty traffic returns valid empty result
  3. Single failed login (below threshold)
  4. Suspicious brute-force candidate (threshold met)
  5. Below-threshold attempts
  6. Missing client IP handling (insufficient evidence)
  7. Multiple client IPs analyzed independently
  8. 403 Forbidden responses handling
  9. Successful 200 login responses handling
  10. Non-authentication 401 handling
  11. Query filters (method, path, status_code, client_ip)
  12. Date/time filtering (start_time, end_time)
  13. Invalid page (422)
  14. Invalid page_size (422)
  15. Invalid status_code (422)
  16. Detector configuration override query params
  17. Complete response schema validation
  18. No sensitive credentials in response payload
  19. Existing BOLA API remains operational
  20. Existing health endpoints remain operational
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
    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert "analyzed_event_count" in data
    assert "summary" in data


# ---------------------------------------------------------------------------
# 2. Empty Traffic
# ---------------------------------------------------------------------------

def test_scenario_2_empty_traffic(override_db):
    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["analyzed_event_count"] == 0
    assert data["failed_attempt_count"] == 0
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 3. Single Failed Login
# ---------------------------------------------------------------------------

def test_scenario_3_single_failed_login(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="r-single",
        timestamp=now,
        method="POST",
        path="/api/v1/auth/login",
        query_params={},
        client_ip="192.168.1.50",
        user_agent="TestClient",
        status_code=401,
        response_time_ms=10.0
    )
    session.add(log)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["analyzed_event_count"] == 1
    assert data["failed_attempt_count"] == 1
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 4. Suspicious Brute-Force Candidate
# ---------------------------------------------------------------------------

def test_scenario_4_suspicious_bruteforce_candidate(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"bf-{i}",
            timestamp=now - timedelta(minutes=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="198.51.100.25",
            user_agent="AttackerBot",
            status_code=401,
            response_time_ms=12.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bruteforce_candidate"
    assert data["analyzed_event_count"] == 5
    assert data["failed_attempt_count"] == 5
    assert len(data["evidences"]) == 1

    ev = data["evidences"][0]
    assert ev["client_ip"] == "198.51.100.25"
    assert ev["auth_endpoint"] == "/api/v1/auth/login"
    assert ev["failed_attempt_count"] == 5
    assert ev["confidence_score"] >= 0.70


# ---------------------------------------------------------------------------
# 5. Below-Threshold Attempts
# ---------------------------------------------------------------------------

def test_scenario_5_below_threshold_attempts(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"sub-{i}",
            timestamp=now - timedelta(minutes=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="198.51.100.25",
            user_agent="TestUser",
            status_code=401,
            response_time_ms=12.0
        )
        for i in range(1, 4)  # 3 failures < 5
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["failed_attempt_count"] == 3
    assert len(data["evidences"]) == 0


# ---------------------------------------------------------------------------
# 6. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_6_missing_client_ip(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"noip-{i}",
            timestamp=now - timedelta(minutes=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="",  # Empty string represents missing client_ip
            user_agent="Test",
            status_code=401,
            response_time_ms=10.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
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
    logs_ip1 = [
        APITrafficLog(request_id=f"ip1-{i}", timestamp=now - timedelta(minutes=i), method="POST", path="/api/v1/auth/login", query_params={}, client_ip="10.0.0.1", user_agent="Bot1", status_code=401, response_time_ms=10.0)
        for i in range(1, 6)
    ]
    logs_ip2 = [
        APITrafficLog(request_id=f"ip2-{i}", timestamp=now - timedelta(minutes=i), method="POST", path="/api/v1/auth/login", query_params={}, client_ip="10.0.0.2", user_agent="Bot2", status_code=401, response_time_ms=10.0)
        for i in range(1, 3)
    ]
    session.add_all(logs_ip1 + logs_ip2)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bruteforce_candidate"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["client_ip"] == "10.0.0.1"
    assert data["distinct_client_count"] == 2


# ---------------------------------------------------------------------------
# 8. 403 Forbidden Responses Handling
# ---------------------------------------------------------------------------

def test_scenario_8_403_handling(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"forb-{i}", timestamp=now - timedelta(minutes=i), method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.1.10", user_agent="Client", status_code=403, response_time_ms=10.0)
        for i in range(1, 8)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["failed_attempt_count"] == 0


# ---------------------------------------------------------------------------
# 9. Successful 200 Login Responses Handling
# ---------------------------------------------------------------------------

def test_scenario_9_successful_login_handling(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"succ-{i}", timestamp=now - timedelta(minutes=i), method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.1.10", user_agent="Client", status_code=200, response_time_ms=10.0)
        for i in range(1, 8)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["failed_attempt_count"] == 0


# ---------------------------------------------------------------------------
# 10. Non-Authentication 401 Handling
# ---------------------------------------------------------------------------

def test_scenario_10_non_auth_401_handling(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id=f"user-{i}", timestamp=now - timedelta(minutes=i), method="GET", path="/api/v1/users/99", query_params={}, client_ip="192.168.1.10", user_agent="Client", status_code=401, response_time_ms=10.0)
        for i in range(1, 8)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_bruteforce_detected"
    assert data["failed_attempt_count"] == 0


# ---------------------------------------------------------------------------
# 11. Query Filters
# ---------------------------------------------------------------------------

def test_scenario_11_query_filters(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="q1", timestamp=now, method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=401, response_time_ms=5.0),
        APITrafficLog(request_id="q2", timestamp=now, method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=401, response_time_ms=5.0),
        APITrafficLog(request_id="q3", timestamp=now, method="GET", path="/api/v1/auth/login", query_params={}, client_ip="192.168.1.100", user_agent="C", status_code=401, response_time_ms=5.0),
        APITrafficLog(request_id="q4", timestamp=now, method="POST", path="/api/v1/other", query_params={}, client_ip="10.0.0.1", user_agent="C", status_code=401, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze?client_ip=192.168.1.100&method=POST")
    assert response.status_code == 200
    data = response.json()
    assert data["analyzed_event_count"] == 2


# ---------------------------------------------------------------------------
# 12. Date/Time Filtering
# ---------------------------------------------------------------------------

def test_scenario_12_datetime_filtering(override_db):
    now = datetime.now(timezone.utc)
    t1 = quote((now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    t2 = quote((now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))

    response = client.get(f"/api/v1/security/bruteforce/analyze?start_time={t1}&end_time={t2}")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 13. Invalid Page
# ---------------------------------------------------------------------------

def test_scenario_13_invalid_page(override_db):
    response = client.get("/api/v1/security/bruteforce/analyze?page=0")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 14. Invalid Page Size
# ---------------------------------------------------------------------------

def test_scenario_14_invalid_page_size(override_db):
    response = client.get("/api/v1/security/bruteforce/analyze?page_size=1000")
    assert response.status_code == 422

    response_neg = client.get("/api/v1/security/bruteforce/analyze?page_size=0")
    assert response_neg.status_code == 422


# ---------------------------------------------------------------------------
# 15. Invalid Status Code
# ---------------------------------------------------------------------------

def test_scenario_15_invalid_status_code(override_db):
    response_low = client.get("/api/v1/security/bruteforce/analyze?status_code=99")
    assert response_low.status_code == 422

    response_high = client.get("/api/v1/security/bruteforce/analyze?status_code=600")
    assert response_high.status_code == 422


# ---------------------------------------------------------------------------
# 16. Detector Configuration Override
# ---------------------------------------------------------------------------

def test_scenario_16_detector_config_override(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="ov-1", timestamp=now - timedelta(minutes=1), method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.9.9", user_agent="C", status_code=401, response_time_ms=5.0),
        APITrafficLog(request_id="ov-2", timestamp=now, method="POST", path="/api/v1/auth/login", query_params={}, client_ip="192.168.9.9", user_agent="C", status_code=401, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    # Threshold override to 2
    response = client.get("/api/v1/security/bruteforce/analyze?failure_threshold=2&time_window_minutes=5&min_confidence=0.75")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bruteforce_candidate"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["failed_attempt_count"] == 2


# ---------------------------------------------------------------------------
# 17. Response Schema Validation
# ---------------------------------------------------------------------------

def test_scenario_17_response_schema_validation(override_db):
    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    data = response.json()

    assert "verdict" in data
    assert "analyzed_event_count" in data
    assert "failed_attempt_count" in data
    assert "distinct_client_count" in data
    assert "distinct_actor_count" in data
    assert "evidences" in data
    assert "summary" in data
    assert isinstance(data["evidences"], list)


# ---------------------------------------------------------------------------
# 18. No Sensitive Credentials in Response
# ---------------------------------------------------------------------------

def test_scenario_18_no_sensitive_credentials_in_response(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"sec-{i}",
            timestamp=now - timedelta(minutes=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={"token": "***MASKED***", "password": "***MASKED***"},
            client_ip="192.168.1.10",
            user_agent="SecTest",
            status_code=401,
            response_time_ms=5.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bruteforce/analyze")
    assert response.status_code == 200
    text_content = response.text

    assert "Bearer" not in text_content
    assert "Authorization" not in text_content
    assert "password" not in text_content or "***MASKED***" in text_content


# ---------------------------------------------------------------------------
# 19. Existing BOLA API Still Works
# ---------------------------------------------------------------------------

def test_scenario_19_existing_bola_api_works(override_db):
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert data["verdict"] == "no_suspicious_behavior"


# ---------------------------------------------------------------------------
# 20. Existing Health Endpoints Still Work
# ---------------------------------------------------------------------------

def test_scenario_20_existing_health_endpoints_work(override_db):
    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "healthy"

    res_v1 = client.get("/api/v1/health")
    assert res_v1.status_code == 200
    assert res_v1.json()["status"] == "healthy"
