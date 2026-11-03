import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.services.bola_analysis_service import analyze_traffic_for_bola
from app.services.bruteforce_analysis_service import analyze_traffic_for_bruteforce
from app.services.rate_anomaly_analysis_service import analyze_traffic_for_rate_anomaly
from app.services.behavior_analysis_service import analyze_traffic_for_behavior_risk

client = TestClient(app)


# ---------------------------------------------------------------------------
# Service-level database error tests
# ---------------------------------------------------------------------------

def test_bola_analysis_service_raises_on_database_error():
    """Verify that analyze_traffic_for_bola raises RuntimeError instead of returning NO_SUSPICIOUS_BEHAVIOR on DB failure."""
    with patch("app.services.bola_analysis_service.get_traffic_logs", side_effect=SQLAlchemyError("Connection terminated")):
        with pytest.raises(RuntimeError, match="Database query failure during BOLA analysis"):
            analyze_traffic_for_bola()


def test_bruteforce_analysis_service_raises_on_database_error():
    """Verify that analyze_traffic_for_bruteforce raises RuntimeError instead of returning NO_BRUTEFORCE_DETECTED on DB failure."""
    with patch("app.services.bruteforce_analysis_service.get_traffic_logs", side_effect=SQLAlchemyError("Connection terminated")):
        with pytest.raises(RuntimeError, match="Database query failure during brute-force analysis"):
            analyze_traffic_for_bruteforce()


def test_rate_anomaly_analysis_service_raises_on_database_error():
    """Verify that analyze_traffic_for_rate_anomaly raises RuntimeError instead of returning NO_ANOMALY on DB failure."""
    with patch("app.services.rate_anomaly_analysis_service._fetch_traffic_records", side_effect=SQLAlchemyError("Connection terminated")):
        with pytest.raises(RuntimeError, match="Database query failure during rate anomaly analysis"):
            analyze_traffic_for_rate_anomaly()


def test_behavior_analysis_service_raises_on_database_error():
    """Verify that analyze_traffic_for_behavior_risk raises RuntimeError instead of returning empty results on DB failure."""
    with patch("app.services.behavior_analysis_service.get_traffic_logs", side_effect=SQLAlchemyError("Connection terminated")):
        with pytest.raises(RuntimeError, match="Database query failure during behavioral risk analysis"):
            analyze_traffic_for_behavior_risk()


# ---------------------------------------------------------------------------
# API Route-level database error tests (HTTP 500)
# ---------------------------------------------------------------------------

def test_bola_api_returns_500_on_database_failure():
    """Verify BOLA API route returns HTTP 500 when database failure occurs."""
    with patch("app.api.v1.routes.bola.analyze_traffic_for_bola", side_effect=RuntimeError("Simulated DB Crash")):
        response = client.get("/api/v1/security/bola/analyze")
        assert response.status_code == 500
        assert "Database query failure during BOLA analysis" in response.json()["detail"]


def test_bruteforce_api_returns_500_on_database_failure():
    """Verify Brute-Force API route returns HTTP 500 when database failure occurs."""
    with patch("app.api.v1.routes.bruteforce.analyze_traffic_for_bruteforce", side_effect=RuntimeError("Simulated DB Crash")):
        response = client.get("/api/v1/security/bruteforce/analyze")
        assert response.status_code == 500
        assert "Database query failure during brute-force analysis" in response.json()["detail"]


def test_rate_anomaly_api_returns_500_on_database_failure():
    """Verify Rate Anomaly API route returns HTTP 500 when database failure occurs."""
    with patch("app.api.v1.routes.rate_anomaly.analyze_traffic_for_rate_anomaly", side_effect=RuntimeError("Simulated DB Crash")):
        response = client.get("/api/v1/security/rate-anomaly/analyze")
        assert response.status_code == 500
        assert "Database query failure during rate anomaly analysis" in response.json()["detail"]


def test_behavior_api_returns_500_on_database_failure():
    """Verify Behavior API route returns HTTP 500 when database failure occurs."""
    with patch("app.api.v1.routes.behavior.analyze_traffic_for_behavior_risk", side_effect=RuntimeError("Simulated DB Crash")):
        response = client.get("/api/v1/security/behavior/analyze")
        assert response.status_code == 500
        assert "Database query failure during behavioral risk analysis" in response.json()["detail"]
