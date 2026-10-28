from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.models.traffic import APITrafficLog
from app.services.traffic_service import save_traffic_log


def test_save_traffic_log_isolated_db(monkeypatch):
    """Test persistence logic using an isolated SQLite in-memory database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Patch SessionLocal in traffic_service to use our in-memory DB
    monkeypatch.setattr("app.services.traffic_service.SessionLocal", TestingSessionLocal)

    success = save_traffic_log(
        request_id="req-persist-test-100",
        method="POST",
        path="/api/v1/data",
        query_params={"search": "safe_term", "password": "***MASKED***"},
        client_ip="192.168.1.50",
        user_agent="Pytest-Isolated",
        status_code=201,
        response_time_ms=15.4,
        timestamp=datetime.now(timezone.utc)
    )

    assert success is True

    # Verify database record
    db = TestingSessionLocal()
    try:
        record = db.query(APITrafficLog).filter_by(request_id="req-persist-test-100").first()
        assert record is not None
        assert record.request_id == "req-persist-test-100"
        assert record.method == "POST"
        assert record.path == "/api/v1/data"
        assert record.status_code == 201
        assert record.response_time_ms == 15.4
        assert record.query_params == {"search": "safe_term", "password": "***MASKED***"}
        assert record.client_ip == "192.168.1.50"
    finally:
        db.close()


def test_save_traffic_log_failure_fault_tolerance(monkeypatch):
    """Test that database error returns False, rolls back, and does not crash application."""
    def mock_broken_session():
        class BrokenSession:
            def add(self, obj):
                raise Exception("Simulated Database Connection Crash")
            def rollback(self):
                pass
            def close(self):
                pass
        return BrokenSession()

    monkeypatch.setattr("app.services.traffic_service.SessionLocal", mock_broken_session)

    result = save_traffic_log(
        request_id="req-broken-000",
        method="GET",
        path="/health",
        query_params={},
        client_ip="127.0.0.1",
        user_agent="Test",
        status_code=200,
        response_time_ms=1.0
    )

    assert result is False
