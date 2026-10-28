from datetime import datetime, timezone
from app.schemas.traffic import APITrafficLogCreate, APITrafficLogResponse
from app.models.traffic import APITrafficLog


def test_pydantic_traffic_schema_instantiation():
    now = datetime.now(timezone.utc)
    log_data = {
        "request_id": "req-1234567890",
        "timestamp": now,
        "method": "GET",
        "path": "/api/v1/health",
        "query_params": {"sanitized_param": "safe_value"},
        "client_ip": "127.0.0.1",
        "user_agent": "Pytest/1.0",
        "status_code": 200,
        "response_time_ms": 4.52
    }
    log_obj = APITrafficLogCreate(**log_data)
    assert log_obj.request_id == "req-1234567890"
    assert log_obj.method == "GET"
    assert log_obj.path == "/api/v1/health"
    assert log_obj.query_params["sanitized_param"] == "safe_value"
    assert log_obj.client_ip == "127.0.0.1"
    assert log_obj.status_code == 200
    assert log_obj.response_time_ms == 4.52


def test_pydantic_traffic_response_schema():
    response_data = {
        "id": 1,
        "request_id": "req-abc-999",
        "timestamp": datetime.now(timezone.utc),
        "method": "POST",
        "path": "/api/v1/login",
        "query_params": {},
        "client_ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "status_code": 401,
        "response_time_ms": 12.3
    }
    resp_obj = APITrafficLogResponse(**response_data)
    assert resp_obj.id == 1
    assert resp_obj.status_code == 401


def test_sqlalchemy_model_instantiation():
    model_obj = APITrafficLog(
        request_id="req-orm-001",
        method="GET",
        path="/api/v1/users",
        query_params={"page": "1"},
        client_ip="10.0.0.1",
        user_agent="TestAgent",
        status_code=200,
        response_time_ms=8.7
    )
    assert model_obj.request_id == "req-orm-001"
    assert model_obj.method == "GET"
    assert model_obj.path == "/api/v1/users"
    assert model_obj.query_params == {"page": "1"}
    assert model_obj.client_ip == "10.0.0.1"
    assert model_obj.status_code == 200
    assert model_obj.response_time_ms == 8.7
