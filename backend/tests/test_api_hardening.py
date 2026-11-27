from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


client = TestClient(app)


def test_security_headers_present_on_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("referrer-policy") == "no-referrer"
    assert "content-security-policy" in {k.lower() for k in r.headers.keys()}


def test_readiness_endpoint_shape():
    r = client.get("/ready")
    assert r.status_code in (200, 503)
    body = r.json()
    assert body["service"] == settings.PROJECT_NAME
    assert "checks" in body
    assert "database" in body["checks"]
    assert body["status"] in ("ready", "not_ready")


def test_request_size_limit_rejects_large_payload(monkeypatch):
    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 64)
    # middleware reads setting at init in our impl? RequestSizeLimitMiddleware takes max_body_bytes at init; app already created.
    # Use a fresh app to pick up limit.
    from app.main import create_app

    local = TestClient(create_app())
    r = local.post("/api/v1/auth/login", json={"username": "u" * 200, "password": "p" * 200})
    assert r.status_code == 413
    assert r.json()["detail"] == "Request payload too large"


def test_auth_rate_limit_returns_429(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.core.rate_limit import reset_auth_rate_limits
    from app.db.base import Base
    from app.db.session import get_db
    from app.main import create_app

    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)
    reset_auth_rate_limits()

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    local_app = create_app()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    local_app.dependency_overrides[get_db] = override_get_db
    with TestClient(local_app) as local:
        payload = {"username": "missing_user", "password": "bad-password"}
        r1 = local.post("/api/v1/auth/login", json=payload)
        r2 = local.post("/api/v1/auth/login", json=payload)
        r3 = local.post("/api/v1/auth/login", json=payload)
        assert r1.status_code in (401, 403)
        assert r2.status_code in (401, 403)
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers
    reset_auth_rate_limits()


def test_request_size_limit_rejects_chunked_oversized_body(monkeypatch):
    from app.main import create_app

    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 64)
    local = TestClient(create_app())

    def big_body():
        yield b"a" * 40
        yield b"b" * 40

    r = local.post(
        "/api/v1/auth/login",
        content=big_body(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["detail"] == "Request payload too large"


def test_request_size_limit_rejects_invalid_content_length(monkeypatch):
    from app.main import create_app

    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 1024)
    local = TestClient(create_app())
    r = local.post(
        "/api/v1/auth/login",
        content=b"{}",
        headers={"content-length": "not-a-number", "content-type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid Content-Length header"


def test_auth_rate_limit_ignores_spoofed_xff_from_untrusted_peer(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.core.rate_limit import reset_auth_rate_limits
    from app.db.base import Base
    from app.db.session import get_db
    from app.main import create_app

    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [])
    reset_auth_rate_limits()

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    local_app = create_app()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    local_app.dependency_overrides[get_db] = override_get_db
    with TestClient(local_app) as local:
        payload = {"username": "missing_user", "password": "bad-password"}
        h1 = {"X-Forwarded-For": "1.2.3.4"}
        h2 = {"X-Forwarded-For": "5.6.7.8"}
        h3 = {"X-Forwarded-For": "9.9.9.9"}
        r1 = local.post("/api/v1/auth/login", json=payload, headers=h1)
        r2 = local.post("/api/v1/auth/login", json=payload, headers=h2)
        r3 = local.post("/api/v1/auth/login", json=payload, headers=h3)
        assert r1.status_code in (401, 403)
        assert r2.status_code in (401, 403)
        # Same untrusted peer should be limited despite spoofed XFF.
        assert r3.status_code == 429
    reset_auth_rate_limits()


def test_security_headers_include_hardened_csp():
    r = client.get("/health")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_unhandled_exception_handler_does_not_leak(monkeypatch):
    from app.main import create_app

    local_app = create_app()

    @local_app.get("/__boom")
    def boom():
        raise RuntimeError("secret-internals")

    local = TestClient(local_app, raise_server_exceptions=False)
    r = local.get("/__boom")
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error"}
    assert "secret-internals" not in r.text


def test_security_event_redaction_masks_sensitive_fields():
    from app.core.security_events import redact_sensitive

    payload = {
        "username": "alice",
        "password": "supersecret",
        "authorization": "Bearer abc.def.ghi",
        "nested": {"api_key": "k", "ok": "v"},
        "token": "tok",
    }
    redacted = redact_sensitive(payload)
    assert redacted["username"] == "alice"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["authorization"] == "***REDACTED***"
    assert redacted["nested"]["api_key"] == "***REDACTED***"
    assert redacted["nested"]["ok"] == "v"
    assert redacted["token"] == "***REDACTED***"


def test_cors_wildcard_rejected_by_settings_validation():
    import pytest
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises((ValueError, ValidationError)):
        Settings(CORS_ORIGINS=["*"], _env_file=None)


def test_validation_error_redacts_sensitive_input():
    from app.main import create_app

    local = TestClient(create_app())
    r = local.post("/api/v1/auth/login", json={"username": "u", "password": "secret-password"})
    # May be 401 or 422 depending on validation; force a 422 with invalid payload shape
    r2 = local.post("/api/v1/auth/login", json={"username": "u", "password": {"bad": "secret-password"}})
    assert r2.status_code == 422
    body = r2.text
    assert "secret-password" not in body


def test_request_size_limit_rejects_negative_content_length(monkeypatch):
    from app.main import create_app

    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 1024)
    local = TestClient(create_app())
    r = local.post(
        "/api/v1/auth/login",
        content=b"{}",
        headers={"content-length": "-1", "content-type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid Content-Length header"


def test_request_size_limit_rejects_misleading_small_content_length(monkeypatch):
    import asyncio
    from app.main import create_app

    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 64)
    app_local = create_app()

    body = b"x" * 200
    sent = False
    messages = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "raw_path": b"/api/v1/auth/login",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"content-length", b"10"),  # misleading small
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }

    asyncio.run(app_local(scope, receive, send))

    start = next(m for m in messages if m.get("type") == "http.response.start")
    assert start["status"] == 413
    body_bytes = b"".join(m.get("body", b"") for m in messages if m.get("type") == "http.response.body")
    assert b"Request payload too large" in body_bytes