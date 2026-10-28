
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


def test_health_endpoint_is_public():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200


def test_protected_endpoint_rejects_missing_api_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "unit-test-key")
    client = TestClient(app)

    response = client.post("/api/v1/security/clustering/analyze")

    assert response.status_code == 401


def test_protected_endpoint_rejects_invalid_api_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "unit-test-key")
    client = TestClient(app)

    response = client.post(
        "/api/v1/security/clustering/analyze",
        headers={"X-API-Key": "wrong-key"},
    )

    assert response.status_code == 401


def test_protected_endpoint_accepts_correct_api_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "unit-test-key")
    client = TestClient(app)

    response = client.post(
        "/api/v1/security/clustering/analyze",
        headers={"X-API-Key": "unit-test-key"},
    )

    # Authentication should pass; request validation may still fail
    # because this request intentionally has no JSON body.
    assert response.status_code != 401
