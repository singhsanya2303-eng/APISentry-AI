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
    """Fixture overriding get_db dependency with isolated SQLite in-memory DB using StaticPool."""
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


def test_scenario_1_endpoint_exists(override_db):
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "evidences" in data
    assert "analyzed_event_count" in data


def test_scenario_2_empty_traffic_result(override_db):
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "no_suspicious_behavior"
    assert data["analyzed_event_count"] == 0
    assert len(data["evidences"]) == 0


def test_scenario_3_normal_traffic(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="r1",
        timestamp=now,
        method="GET",
        path="/users/101",
        query_params={},
        client_ip="192.168.1.10",
        user_agent="Test",
        status_code=200,
        response_time_ms=5.0
    )
    session.add(log)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "insufficient_evidence"


def test_scenario_4_suspicious_multi_object_access(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now - timedelta(minutes=3), method="GET", path="/users/101", query_params={"user_id": "actor_xyz"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now - timedelta(minutes=2), method="GET", path="/users/102", query_params={"user_id": "actor_xyz"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now - timedelta(minutes=1), method="GET", path="/users/103", query_params={"user_id": "actor_xyz"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bola_candidate"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["actor_id"] == "actor_xyz"
    assert data["evidences"][0]["distinct_object_count"] == 3


def test_scenario_5_missing_actor_identity(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "insufficient_evidence"


def test_scenario_6_nested_resource_access(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now - timedelta(minutes=3), method="GET", path="/api/v1/accounts/42/orders/91", query_params={"user_id": "actor_nest"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now - timedelta(minutes=2), method="GET", path="/api/v1/accounts/42/orders/92", query_params={"user_id": "actor_nest"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now - timedelta(minutes=1), method="GET", path="/api/v1/accounts/42/orders/93", query_params={"user_id": "actor_nest"}, client_ip="10.0.0.1", status_code=200, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bola_candidate"
    assert data["evidences"][0]["normalized_endpoint"] == "/api/v1/accounts/{account_id}/orders/{order_id}"


def test_scenario_7_query_filters(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(request_id="r1", timestamp=now, method="GET", path="/users/101", query_params={"user_id": "actor_1"}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r2", timestamp=now, method="GET", path="/users/102", query_params={"user_id": "actor_1"}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r3", timestamp=now, method="GET", path="/users/103", query_params={"user_id": "actor_1"}, client_ip="192.168.1.50", status_code=200, response_time_ms=5.0),
        APITrafficLog(request_id="r4", timestamp=now, method="POST", path="/users/104", query_params={"user_id": "actor_1"}, client_ip="10.0.0.99", status_code=200, response_time_ms=5.0),
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze?client_ip=192.168.1.50&method=GET")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious_bola_candidate"
    assert data["analyzed_event_count"] == 3


def test_scenario_8_invalid_page(override_db):
    response = client.get("/api/v1/security/bola/analyze?page=0")
    assert response.status_code == 422


def test_scenario_9_invalid_page_size(override_db):
    response = client.get("/api/v1/security/bola/analyze?page_size=1000")
    assert response.status_code == 422


def test_scenario_10_invalid_status_code(override_db):
    response = client.get("/api/v1/security/bola/analyze?status_code=999")
    assert response.status_code == 422


def test_scenario_11_datetime_filtering(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    t1 = quote((now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    t2 = quote((now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))

    response = client.get(f"/api/v1/security/bola/analyze?start_time={t1}&end_time={t2}")
    assert response.status_code == 200


def test_scenario_12_response_schema_validation(override_db):
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    data = response.json()

    assert "verdict" in data
    assert "evidences" in data
    assert "analyzed_event_count" in data
    assert "explanation" in data


def test_scenario_13_no_sensitive_credentials_in_response(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="r1",
        timestamp=now,
        method="POST",
        path="/users/101",
        query_params={"password": "***MASKED***", "token": "***MASKED***"},
        client_ip="192.168.1.10",
        user_agent="Test",
        status_code=200,
        response_time_ms=5.0
    )
    session.add(log)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 200
    text_content = response.text

    assert "Bearer" not in text_content
    assert "password" not in text_content or "***MASKED***" in text_content


def test_scenario_14_api_v1_health_works(override_db):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scenario_15_root_health_works(override_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
