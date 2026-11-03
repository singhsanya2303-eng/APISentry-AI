import pytest
from unittest.mock import MagicMock
from starlette.requests import Request
from starlette.responses import Response
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.utils.middleware import (
    RequestLoggingMiddleware,
    extract_verified_actor_identity,
)
from app.models.traffic import APITrafficLog
from app.services.resource_extractor import extract_from_traffic_log
from app.services.bola_analysis_service import analyze_traffic_for_bola
from app.schemas.bola import DetectionVerdict
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base


def test_extract_verified_actor_identity_rejects_untrusted_headers():
    """Verify that unverified client headers like X-User-ID are never treated as authenticated identity."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/v1/users/1",
        "raw_path": b"/api/v1/users/1",
        "query_string": b"user_id=spoofed_query_user",
        "headers": [
            (b"x-user-id", b"spoofed_header_user"),
            (b"x-actor-id", b"spoofed_actor_user"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    # No verified state set
    assert extract_verified_actor_identity(request) is None


def test_extract_verified_actor_identity_accepts_verified_request_state():
    """Verify that verified identity stored on request.state by auth dependencies is trusted."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/users/1",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    request = Request(scope)
    request.state.actor_id = "verified_corp_user_42"
    assert extract_verified_actor_identity(request) == "verified_corp_user_42"


def test_extract_verified_actor_identity_accepts_authenticated_user_object():
    """Verify that an authenticated user object on request.state is safely resolved."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/users/1",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    request = Request(scope)

    class AuthenticatedUser:
        is_authenticated = True
        identity = "user_auth_777"

    request.state.user = AuthenticatedUser()
    assert extract_verified_actor_identity(request) == "user_auth_777"


def test_extract_verified_actor_identity_rejects_unauthenticated_user_object():
    """Verify that an unauthenticated user object on request.state returns None."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/users/1",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    request = Request(scope)

    class UnauthenticatedUser:
        is_authenticated = False
        identity = "anonymous"

    request.state.user = UnauthenticatedUser()
    assert extract_verified_actor_identity(request) is None


def test_middleware_does_not_persist_unverified_x_user_id(monkeypatch):
    """
    Test that RequestLoggingMiddleware does NOT persist client-supplied X-User-ID
    as actor_id when no server-side authentication context was established.
    """
    mock_save = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_save)

    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/test-endpoint")
    def sample_route():
        return {"status": "ok"}

    client = TestClient(app)
    response = client.get(
        "/test-endpoint?user_id=arbitrary_query_val",
        headers={"X-User-ID": "spoofed_actor_val"}
    )
    assert response.status_code == 200
    assert mock_save.called
    kwargs = mock_save.call_args.kwargs
    assert kwargs.get("actor_id") is None


def test_middleware_persists_verified_actor_identity(monkeypatch):
    """
    Test that RequestLoggingMiddleware persists actor_id when a trusted
    authentication handler attaches the verified actor to request.state.
    """
    mock_save = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_save)

    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/authenticated-endpoint")
    def secure_route(request: Request):
        # Simulated server-side auth verification
        request.state.actor_id = "verified_actor_999"
        return {"authenticated": True}

    client = TestClient(app)
    response = client.get("/authenticated-endpoint")
    assert response.status_code == 200
    assert mock_save.called
    kwargs = mock_save.call_args.kwargs
    assert kwargs.get("actor_id") == "verified_actor_999"


def test_resource_extractor_prioritizes_verified_actor_id():
    """Verify that persisted verified actor_id takes precedence over query params."""
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="req-verified-01",
        timestamp=now,
        method="GET",
        path="/users/55",
        query_params={"user_id": "unverified_query_user"},
        client_ip="10.0.0.1",
        user_agent="Agent",
        status_code=200,
        response_time_ms=5.0,
        actor_id="verified_auth_user"
    )

    event = extract_from_traffic_log(log)
    assert event.actor_id == "verified_auth_user"
