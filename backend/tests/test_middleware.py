import asyncio
import logging
import pytest
from starlette.requests import Request
from app.utils.middleware import RequestLoggingMiddleware
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from starlette.requests import Request
from app.main import app, create_app
from app.core.config import settings
from app.utils.middleware import (
    sanitize_query_params,
    extract_client_ip,
    is_trusted_proxy,
)

client = TestClient(app)


def test_health_endpoint_returns_x_request_id():
    response = client.get("/health")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Request-ID"] != ""


def test_custom_x_request_id_preserved():
    custom_id = "test-custom-request-id-12345"
    response = client.get("/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_id


def test_process_time_header_attached():
    response = client.get("/health")
    assert response.status_code == 200
    assert "X-Process-Time" in response.headers
    assert response.headers["X-Process-Time"].endswith("ms")


def test_query_params_sanitization():
    raw_params = {
        "search": "test_query",
        "password": "my_secret_password",
        "token": "bearer_xyz_123",
        "user_id": "42"
    }
    sanitized = sanitize_query_params(raw_params)
    assert sanitized["search"] == "test_query"
    assert sanitized["user_id"] == "42"
    assert sanitized["password"] == "***MASKED***"
    assert sanitized["token"] == "***MASKED***"


def test_client_ip_no_forwarded_header(monkeypatch):
    """Direct peer IP is recorded when no X-Forwarded-For header is present."""
    mock_persist = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_persist)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [])

    test_peer = "198.51.100.10"
    peer_client = TestClient(app, client=(test_peer, 50000))
    response = peer_client.get("/health")

    assert response.status_code == 200
    assert mock_persist.called
    recorded_client_ip = mock_persist.call_args.kwargs["client_ip"]
    assert recorded_client_ip == test_peer


def test_client_ip_spoofed_header_untrusted_peer(monkeypatch):
    """Spoofed X-Forwarded-For from an untrusted peer is ignored; direct peer IP is recorded."""
    mock_persist = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_persist)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [])

    untrusted_peer = "198.51.100.99"
    peer_client = TestClient(app, client=(untrusted_peer, 50000))
    response = peer_client.get("/health", headers={"X-Forwarded-For": "203.0.113.195"})

    assert response.status_code == 200
    assert mock_persist.called
    recorded_client_ip = mock_persist.call_args.kwargs["client_ip"]
    assert recorded_client_ip == untrusted_peer


def test_client_ip_forwarded_header_trusted_peer(monkeypatch):
    """X-Forwarded-For is trusted and parsed when connecting peer is in TRUSTED_PROXIES."""
    mock_persist = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_persist)

    trusted_proxy_ip = "10.0.0.1"
    real_client_ip = "203.0.113.50"
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [trusted_proxy_ip])

    proxy_client = TestClient(app, client=(trusted_proxy_ip, 50000))
    response = proxy_client.get(
        "/health",
        headers={"X-Forwarded-For": f"{real_client_ip}, {trusted_proxy_ip}"}
    )

    assert response.status_code == 200
    assert mock_persist.called
    recorded_client_ip = mock_persist.call_args.kwargs["client_ip"]
    assert recorded_client_ip == real_client_ip


def test_client_ip_malformed_forwarded_ip_trusted_peer(monkeypatch):
    """Malformed forwarded IP from a trusted proxy is rejected, falling back to direct peer IP."""
    mock_persist = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_persist)

    trusted_proxy_ip = "10.0.0.1"
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [trusted_proxy_ip])

    proxy_client = TestClient(app, client=(trusted_proxy_ip, 50000))
    response = proxy_client.get(
        "/health",
        headers={"X-Forwarded-For": "malformed_ip_address_payload"}
    )

    assert response.status_code == 200
    assert mock_persist.called
    recorded_client_ip = mock_persist.call_args.kwargs["client_ip"]
    assert recorded_client_ip == trusted_proxy_ip


def test_extract_client_ip_cidr_and_edge_cases():
    """Unit tests for extract_client_ip and is_trusted_proxy covering CIDR and edge cases."""
    # CIDR network matching
    assert is_trusted_proxy("10.1.2.3", ["10.0.0.0/8"]) is True
    assert is_trusted_proxy("172.16.0.5", ["10.0.0.0/8"]) is False
    assert is_trusted_proxy("invalid_ip", ["10.0.0.0/8"]) is False
    assert is_trusted_proxy("", ["10.0.0.0/8"]) is False
    assert is_trusted_proxy("127.0.0.1", []) is False

    # IPv6 support
    assert is_trusted_proxy("::1", ["::1"]) is True
    assert is_trusted_proxy("2001:db8::1", ["2001:db8::/32"]) is True

    # Mock request without client
    class DummyRequest:
        client = None
        headers = {"x-forwarded-for": "203.0.113.1"}

    assert extract_client_ip(DummyRequest(), trusted_proxies=["10.0.0.1"]) == "unknown"

def test_exception_logging_does_not_expose_raw_error(monkeypatch, caplog):
    middleware = RequestLoggingMiddleware(app)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/test",
        "raw_path": b"/test",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    secret_detail = "SECRET_DATABASE_PASSWORD_DETAIL"

    async def failing_call_next(request):
        raise RuntimeError(secret_detail)

    async def fake_run_sync(func, *args, **kwargs):
        return None

    monkeypatch.setattr(
        "app.utils.middleware.anyio.to_thread.run_sync",
        fake_run_sync,
    )

    with caplog.at_level(logging.INFO, logger="apisentry.middleware"):
        with pytest.raises(RuntimeError, match=secret_detail):
            asyncio.run(middleware.dispatch(request, failing_call_next))

    assert secret_detail not in caplog.text
    assert "RuntimeError" in caplog.text



def test_cors_allows_configured_origin():
    test_app = create_app(
        cors_origins=["http://localhost:5173"]
    )

    test_client = TestClient(test_app)

    response = test_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        == "http://localhost:5173"
    )
    assert "X-API-Key" in response.headers.get(
        "access-control-allow-headers", ""
    )
    
def test_configured_app_rejects_unconfigured_origin():
    test_app = create_app(
        cors_origins=["http://localhost:5173"]
    )

    test_client = TestClient(test_app)

    response = test_client.options(
        "/health",
        headers={
            "Origin": "http://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_cors_rejects_unconfigured_origin(monkeypatch):
    monkeypatch.setattr(settings, "CORS_ORIGINS", [])

    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers




def test_main_app_cors_rejects_unconfigured_origin():
    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers
