"""Task 11 regression tests for JWT validation before logout revocation.

Invalid bearer strings must never become revocation records. All persistence
is isolated in-memory SQLite; no configured database is contacted.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routes import auth as auth_route
from app.core.security import (
    _REVOKED_TOKEN_EXPIRY,
    _REVOKED_TOKENS,
    create_access_token,
)
from app.main import app
from app.models.revoked_token import RevokedToken

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clean_revocation_state():
    previous_hashes = set(_REVOKED_TOKENS)
    previous_expiries = dict(_REVOKED_TOKEN_EXPIRY)
    _REVOKED_TOKENS.clear()
    _REVOKED_TOKEN_EXPIRY.clear()
    try:
        yield
    finally:
        _REVOKED_TOKENS.clear()
        _REVOKED_TOKEN_EXPIRY.clear()
        _REVOKED_TOKENS.update(previous_hashes)
        _REVOKED_TOKEN_EXPIRY.update(previous_expiries)


@pytest.fixture
def _revoke_calls(monkeypatch):
    calls: list[str] = []
    real_revoke = auth_route.revoke_token

    def _spy(token: str, db=None) -> None:
        calls.append(token)
        real_revoke(token, db=db)

    monkeypatch.setattr(auth_route, "revoke_token", _spy)
    return calls


def _db_revocation_count(factory) -> int:
    db = factory()
    try:
        return db.query(RevokedToken).count()
    finally:
        db.close()


def _logout(token: str):
    return client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.parametrize(
    ("token", "expected_detail"),
    [
        ("definitely-not-a-jwt", "Invalid or tampered authentication token"),
        ("a.b.c", "Invalid or tampered authentication token"),
    ],
)
def test_arbitrary_and_malformed_tokens_are_not_revoked(
    testing_session_factory,
    _revoke_calls,
    token,
    expected_detail,
):
    response = _logout(token)

    assert response.status_code == 401
    assert response.json()["detail"] == expected_detail
    assert _revoke_calls == []
    assert _db_revocation_count(testing_session_factory) == 0
    assert _REVOKED_TOKENS == set()


def test_invalid_signature_token_is_not_revoked(testing_session_factory, _revoke_calls):
    token = create_access_token(
        subject="signature-user",
        extra_claims={"username": "signature-user", "role": "viewer"},
    )
    parts = token.split(".")
    bad_signature = "A" * len(parts[2])
    assert bad_signature != parts[2]
    tampered = f"{parts[0]}.{parts[1]}.{bad_signature}"

    response = _logout(tampered)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or tampered authentication token"
    assert _revoke_calls == []
    assert _db_revocation_count(testing_session_factory) == 0
    assert _REVOKED_TOKENS == set()


def test_expired_token_is_not_revoked(testing_session_factory, _revoke_calls):
    expired = create_access_token(
        subject="expired-user",
        expires_delta=timedelta(seconds=-30),
        extra_claims={"username": "expired-user", "role": "viewer"},
    )

    response = _logout(expired)

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication token has expired"
    assert _revoke_calls == []
    assert _db_revocation_count(testing_session_factory) == 0
    assert _REVOKED_TOKENS == set()


def test_valid_authenticated_logout_still_revokes_once(testing_session_factory, _revoke_calls):
    token = create_access_token(
        subject="valid-logout-user",
        extra_claims={"username": "valid-logout-user", "role": "viewer"},
    )
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    response = _logout(token)
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}
    assert _revoke_calls == [token]
    assert _db_revocation_count(testing_session_factory) == 1

    reused = client.get("/api/v1/auth/me", headers=headers)
    assert reused.status_code == 401
    assert reused.json()["detail"] == "Authentication token has been revoked"
