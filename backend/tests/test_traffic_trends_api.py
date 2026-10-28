
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models.traffic import APITrafficLog
from app.services import traffic_trend_analysis_service
from app.api.v1.routes import traffic_trends


@pytest.fixture
def override_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    def get_test_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = get_test_db
    yield TestingSessionLocal
    app.dependency_overrides.clear()
    engine.dispose()


@pytest.fixture
def client():
    return TestClient(app)


def add_logs(session, prefix, start, count):
    logs = [
        APITrafficLog(
            request_id=f"{prefix}-{i}",
            timestamp=start + timedelta(seconds=10 * i),
            method="GET",
            path="/api/v1/test",
            query_params={},
            client_ip="192.0.2.10",
            user_agent="TestAgent",
            status_code=200,
            response_time_ms=100.0,
        )
        for i in range(count)
    ]
    session.add_all(logs)
    session.commit()


def test_traffic_trend_route_is_registered():
    from app.main import app

    schema = app.openapi()

    assert (
        "/api/v1/security/traffic-trends/analyze"
        in schema["paths"]
    )

def test_traffic_trend_rejects_invalid_time_order(override_db, client):
    response = client.get(
        "/api/v1/security/traffic-trends/analyze",
        params={
            "baseline_start": "2026-01-01T00:00:00Z",
            "baseline_end": "2026-01-01T01:00:00Z",
            "target_start": "2026-01-01T00:30:00Z",
            "target_end": "2026-01-01T02:00:00Z",
        },
    )
    assert response.status_code == 422


def test_traffic_trend_empty_baseline_returns_422(override_db, client):
    response = client.get(
        "/api/v1/security/traffic-trends/analyze",
        params={
            "baseline_start": "2026-01-01T00:00:00Z",
            "baseline_end": "2026-01-01T01:00:00Z",
            "target_start": "2026-01-01T01:00:01Z",
            "target_end": "2026-01-01T02:00:00Z",
        },
    )
    assert response.status_code == 422
    assert "baseline_logs must not be empty" in response.json()["detail"]


def test_traffic_trend_success_uses_separate_baseline_and_target(
    override_db,
    client,
    monkeypatch,
):
    session = override_db()
    baseline_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    target_start = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)

    add_logs(session, "baseline", baseline_start, 12)
    add_logs(session, "target", target_start, 2)
    session.close()

    captured = {}

    def fake_analyze(baseline_logs, target_logs, threshold_percentile=95.0):
        captured["baseline_count"] = len(baseline_logs)
        captured["target_count"] = len(target_logs)
        captured["percentile"] = threshold_percentile
        return {
            "baseline_window_count": 12,
            "target_window_count": 2,
            "anomaly_count": 1,
            "threshold": 0.5,
            "predictions": [
                {
                    "reconstruction_error": 0.1,
                    "threshold": 0.5,
                    "is_anomaly": False,
                },
                {
                    "reconstruction_error": 0.8,
                    "threshold": 0.5,
                    "is_anomaly": True,
                },
            ],
            "summary": "Analyzed 2 target traffic windows; 1 flagged as anomalous.",
        }

    monkeypatch.setattr(
        traffic_trends,
        "analyze_traffic_trends",
        fake_analyze,
    )

    response = client.get(
        "/api/v1/security/traffic-trends/analyze",
        params={
            "baseline_start": baseline_start.isoformat(),
            "baseline_end": (
                baseline_start + timedelta(minutes=10)
            ).isoformat(),
            "target_start": target_start.isoformat(),
            "target_end": (
                target_start + timedelta(minutes=10)
            ).isoformat(),
            "threshold_percentile": 95,
        },
    )

    assert response.status_code == 200
    assert captured == {
        "baseline_count": 12,
        "target_count": 2,
        "percentile": 95.0,
    }
    assert response.json()["anomaly_count"] == 1
    assert len(response.json()["predictions"]) == 2


def test_traffic_trend_maps_insufficient_baseline_to_422(
    override_db,
    client,
):
    session = override_db()
    baseline_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    target_start = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)

    add_logs(session, "baseline", baseline_start, 3)
    add_logs(session, "target", target_start, 1)
    session.close()

    response = client.get(
        "/api/v1/security/traffic-trends/analyze",
        params={
            "baseline_start": baseline_start.isoformat(),
            "baseline_end": (
                baseline_start + timedelta(minutes=10)
            ).isoformat(),
            "target_start": target_start.isoformat(),
            "target_end": (
                target_start + timedelta(minutes=10)
            ).isoformat(),
        },
    )

    assert response.status_code == 422
    assert "At least 10 baseline windows are required" in response.json()["detail"]
