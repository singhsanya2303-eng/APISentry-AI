from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.security import (
    authenticate_user,
    create_access_token,
    decode_access_token,
    hash_password,
    register_user,
    require_api_key,
    verify_password,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.traffic import APITrafficLog
from app.schemas.bola import DetectionVerdict
from app.services.bola_analysis_service import analyze_traffic_for_bola

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Password Hashing and Verification Unit Tests
# ---------------------------------------------------------------------------

def test_password_hashing_and_verification():
    """Verify PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(password, "") is False
    assert verify_password(password, "malformed$hash") is False


def test_registered_users_authentication():
    """Verify explicitly registered users authenticate correctly."""
    register_user("alice", "AlicePassword123!", actor_id="user_alice")
    user = authenticate_user("alice", "AlicePassword123!")
    assert user is not None
    assert user["actor_id"] == "user_alice"

    register_user("bob", "BobPassword123!", actor_id="user_bob")
    user_bob = authenticate_user("bob", "BobPassword123!")
    assert user_bob is not None
    assert user_bob["actor_id"] == "user_bob"

    # Invalid password returns None
    assert authenticate_user("alice", "WrongPassword") is None
    # Unknown user returns None
    assert authenticate_user("nonexistent_user", "password") is None

    # Dynamic user registration
    register_user("charlie", "CharliePass456!", actor_id="user_charlie")
    user_charlie = authenticate_user("charlie", "CharliePass456!")
    assert user_charlie is not None
    assert user_charlie["actor_id"] == "user_charlie"


# ---------------------------------------------------------------------------
# 2. JWT Generation, Signature, and Expiration Unit Tests
# ---------------------------------------------------------------------------

def test_create_and_decode_valid_access_token():
    """Verify that a freshly minted JWT token decodes with correct claims."""
    token = create_access_token(subject="user_12345", extra_claims={"username": "alice", "role": "admin"})
    payload = decode_access_token(token)

    assert payload["sub"] == "user_12345"
    assert payload["username"] == "alice"
    assert payload["role"] == "admin"
    assert "exp" in payload
    assert "iat" in payload


def test_decode_rejects_expired_token():
    """Verify that tokens past their expiration are rejected."""
    expired_token = create_access_token(
        subject="user_expired",
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )
    with pytest.raises(ValueError, match="expired"):
        decode_access_token(expired_token)


def test_decode_rejects_tampered_payload():
    """Verify that any modification to payload bytes triggers signature mismatch."""
    token = create_access_token(subject="user_original")
    parts = token.split(".")
    # Tamper payload part by flipping characters
    tampered_payload = parts[1][:-2] + ("aa" if not parts[1].endswith("aa") else "bb")
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(ValueError, match="tampered"):
        decode_access_token(tampered_token)


def test_decode_rejects_tampered_signature():
    """Verify that any modification to signature bytes is rejected."""
    token = create_access_token(subject="user_original")
    parts = token.split(".")
    tampered_sig = parts[2][:-2] + ("xx" if not parts[2].endswith("xx") else "yy")
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(ValueError, match="tampered"):
        decode_access_token(tampered_token)


def test_decode_rejects_none_algorithm():
    """Verify that tokens specifying the 'none' algorithm attack are strictly rejected."""
    import base64
    import json
    header_none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "attacker", "exp": 9999999999}).encode()).rstrip(b"=").decode()
    fake_token = f"{header_none}.{payload}."

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        decode_access_token(fake_token)


# ---------------------------------------------------------------------------
# 3. User Login & Protected Endpoints API Tests
# ---------------------------------------------------------------------------

def test_login_endpoint_success():
    """Verify POST /api/v1/auth/login returns valid JWT access token."""
    register_user("alice", "AlicePassword123!", actor_id="user_alice")
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "AlicePassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["actor_id"] == "user_alice"
    assert data["expires_in"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_login_endpoint_invalid_credentials_returns_401():
    """Verify POST /api/v1/auth/login rejects wrong credentials with HTTP 401."""
    register_user("alice", "AlicePassword123!", actor_id="user_alice")
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert "Invalid username or password" in response.json()["detail"]


def test_protected_route_with_valid_jwt():
    """Verify GET /api/v1/auth/me succeeds with valid Bearer token."""
    token = create_access_token(subject="user_alice", extra_claims={"username": "alice", "role": "user"})
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["actor_id"] == "user_alice"
    assert data["username"] == "alice"


def test_protected_route_missing_authentication_returns_401():
    """Verify GET /api/v1/auth/me returns 401 when Authorization header is absent."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "Missing authentication credentials" in response.json()["detail"]


def test_protected_route_expired_token_returns_401():
    """Verify GET /api/v1/auth/me returns 401 with explicit expired message."""
    expired_token = create_access_token(
        subject="user_alice",
        expires_delta=timedelta(seconds=-30),
    )
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_protected_route_tampered_token_returns_401():
    """Verify GET /api/v1/auth/me returns 401 with explicit invalid/tampered message."""
    token = create_access_token(subject="user_alice")
    tampered_token = token[:-4] + "zzzz"
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401
    assert "invalid or tampered" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 4. Identity Spoofing Protection Tests
# ---------------------------------------------------------------------------

def test_unauthenticated_request_does_not_trust_client_supplied_identity():
    """Client-supplied X-User-ID or query parameters are never trusted as identity."""
    response = client.get(
        "/api/v1/auth/me?user_id=spoofed_victim",
        headers={"X-User-ID": "spoofed_admin", "X-Actor-ID": "spoofed_actor"},
    )
    assert response.status_code == 401


def test_authenticated_request_overrides_client_spoofed_headers(monkeypatch):
    """
    When authenticated as Bob, even if the client sends X-User-ID: Alice,
    the verified actor_id persisted by middleware is Bob.
    """
    mock_persist = MagicMock(return_value=True)
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", mock_persist)

    token = create_access_token(subject="user_bob", extra_claims={"username": "bob"})
    response = client.get(
        "/api/v1/auth/me?user_id=attacker_param",
        headers={
            "Authorization": f"Bearer {token}",
            "X-User-ID": "victim_alice",
            "X-Actor-ID": "victim_alice",
        },
    )
    assert response.status_code == 200
    assert mock_persist.called
    persisted_actor_id = mock_persist.call_args.kwargs.get("actor_id")
    # Must be the verified subject from the token, NEVER the spoofed header or query param
    assert persisted_actor_id == "user_bob"


# ---------------------------------------------------------------------------
# 5. Actor Identity Persistence & End-to-End BOLA Integration Tests
# ---------------------------------------------------------------------------

def test_authenticated_traffic_persists_actor_and_triggers_bola(monkeypatch):
    """
    End-to-End BOLA Integration Test:
    1. Uses an isolated SQLite database.
    2. Issues a valid JWT access token for an authenticated actor ('attacker_actor_1').
    3. The authenticated actor accesses 3 distinct user resources via the API:
       GET /api/v1/auth/users/101
       GET /api/v1/auth/users/102
       GET /api/v1/auth/users/103
    4. Middleware attaches verified request.state.actor_id and persists it to the DB.
    5. BOLA analysis runs against the DB and detects SUSPICIOUS_BOLA_CANDIDATE.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Patch SessionLocal across traffic persistence and query layers to use our test DB
    monkeypatch.setattr("app.services.traffic_service.SessionLocal", TestingSessionLocal)

    token = create_access_token(subject="attacker_actor_1", extra_claims={"username": "attacker"})

    # Make 3 distinct authenticated object requests through the live API
    for obj_id in ["101", "102", "103"]:
        res = client.get(
            f"/api/v1/auth/users/{obj_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert res.json()["user_id"] == obj_id
        assert res.json()["accessed_by"] == "attacker_actor_1"

    # Verify that the traffic logs in the DB genuinely contain the verified actor_id
    db = TestingSessionLocal()
    try:
        logs = db.query(APITrafficLog).filter(APITrafficLog.actor_id == "attacker_actor_1").all()
        assert len(logs) == 3
        for log in logs:
            assert log.actor_id == "attacker_actor_1"
            assert "/api/v1/auth/users/" in log.path

        # Run BOLA detection analysis on the database
        bola_result = analyze_traffic_for_bola(db=db)
        assert bola_result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
        assert len(bola_result.evidences) == 1
        evidence = bola_result.evidences[0]
        assert evidence.actor_id == "attacker_actor_1"
        assert evidence.distinct_object_count == 3
        assert set(evidence.accessed_object_ids) == {"101", "102", "103"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 6. Existing API-Key Authentication Compatibility Tests
# ---------------------------------------------------------------------------

def test_api_key_compatibility_rejects_missing_api_key(monkeypatch):
    """Verify that protected security analysis routes still require X-API-Key."""
    monkeypatch.setattr(settings, "API_KEY", "system-test-key-999")
    response = client.get("/api/v1/security/bola/analyze")
    assert response.status_code == 401
    assert "Invalid or missing API key" in response.json()["detail"]


def test_api_key_compatibility_accepts_valid_api_key(monkeypatch):
    """Verify that protected security analysis routes accept correct X-API-Key."""
    monkeypatch.setattr(settings, "API_KEY", "system-test-key-999")
    response = client.get(
        "/api/v1/security/bola/analyze",
        headers={"X-API-Key": "system-test-key-999"},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] in ("no_suspicious_behavior", "insufficient_evidence", "suspicious_bola_candidate")
