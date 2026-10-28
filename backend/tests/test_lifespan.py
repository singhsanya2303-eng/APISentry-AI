from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from app.main import app


def test_lifespan_triggers_init_db_without_connecting(monkeypatch):
    """
    Verify that FastAPI lifespan startup executes init_db() exactly once,
    safely isolated from PostgreSQL using monkeypatch.
    """
    mock_init_db = MagicMock()
    monkeypatch.setattr("app.main.init_db", mock_init_db)

    with TestClient(app) as client:
        mock_init_db.assert_called_once()
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
