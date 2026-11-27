from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    _REVOKED_TOKEN_EXPIRY,
    _REVOKED_TOKENS,
    create_access_token,
    decode_access_token,
    is_token_revoked,
    revoke_token,
)
from app.main import app
from app.models.revoked_token import RevokedToken


client = TestClient(app)


@pytest.fixture(autouse=True)
def _isolated_db(testing_session_factory):
    yield testing_session_factory


def _clear_revocation_state():
    _REVOKED_TOKENS.clear()
    _REVOKED_TOKEN_EXPIRY.clear()


def test_logout_revokes_token_and_rejects_reuse(testing_session_factory):
    _clear_revocation_state()
    token = create_access_token(subject="u1", extra_claims={"username": "u1", "role": "viewer"})
    headers = {"Authorization": f"Bearer {token}"}

    ok = client.get("/api/v1/auth/me", headers=headers)
    assert ok.status_code == 200

    out = client.post("/api/v1/auth/logout", headers=headers)
    assert out.status_code == 200
    assert "logged out" in out.json()["message"].lower()

    rejected = client.get("/api/v1/auth/me", headers=headers)
    assert rejected.status_code == 401
    assert "revoked" in rejected.json()["detail"].lower()

    db = testing_session_factory()
    try:
        rows = db.query(RevokedToken).all()
        assert len(rows) == 1
        assert rows[0].token_hash
        assert rows[0].expires_at is not None
    finally:
        db.close()


def test_revoked_token_rejected_by_decode_with_db(testing_session_factory):
    _clear_revocation_state()
    token = create_access_token(subject="u2", extra_claims={"username": "u2", "role": "analyst"})
    db = testing_session_factory()
    try:
        revoke_token(token, db=db)
        with pytest.raises(ValueError, match="revoked"):
            decode_access_token(token, db=db)
        assert is_token_revoked(token, db=db) is True
    finally:
        db.close()


def test_expired_token_is_not_treated_as_active_revocation(testing_session_factory):
    _clear_revocation_state()
    expired = create_access_token(subject="u3", expires_delta=timedelta(seconds=-30))
    db = testing_session_factory()
    try:
        revoke_token(expired, db=db)
        # Expired token should fail for expiry; revocation entry should not make it "validly revoked" forever.
        with pytest.raises(ValueError, match="expired"):
            decode_access_token(expired, db=db)
        # cleanup should remove expired in-memory entries
        _clear_revocation_state()
        # DB row may exist; is_token_revoked ignores expired rows
        assert is_token_revoked(expired, db=db) is False
    finally:
        db.close()


def test_restart_behavior_uses_db_revocation(testing_session_factory):
    _clear_revocation_state()
    token = create_access_token(subject="u4", extra_claims={"username": "u4", "role": "admin"})
    db = testing_session_factory()
    try:
        revoke_token(token, db=db)
        assert is_token_revoked(token, db=db) is True
    finally:
        db.close()

    # Simulate process restart: in-memory revocation cache lost.
    _clear_revocation_state()
    assert token not in _REVOKED_TOKENS

    db2 = testing_session_factory()
    try:
        assert is_token_revoked(token, db=db2) is True
        with pytest.raises(ValueError, match="revoked"):
            decode_access_token(token, db=db2)
    finally:
        db2.close()


def test_revocation_cleanup_removes_expired_in_memory_entries(testing_session_factory):
    _clear_revocation_state()
    token = create_access_token(subject="u5", expires_delta=timedelta(minutes=5))
    revoke_token(token)
    assert is_token_revoked(token) is True
    # Force expiry in memory
    for h in list(_REVOKED_TOKEN_EXPIRY.keys()):
        _REVOKED_TOKEN_EXPIRY[h] = int(datetime.now(timezone.utc).timestamp()) - 10
    assert is_token_revoked(token) is False
    assert len(_REVOKED_TOKEN_EXPIRY) == 0


def test_db_lookup_error_fails_closed(testing_session_factory, monkeypatch):
    _clear_revocation_state()
    token = create_access_token(subject="u6", extra_claims={"username": "u6", "role": "viewer"})
    db = testing_session_factory()
    try:
        # Simulate a real DB lookup failure (not missing-table migration case).
        class BrokenQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                raise RuntimeError("db connection lost")

        monkeypatch.setattr(db, "query", lambda *args, **kwargs: BrokenQuery())
        assert is_token_revoked(token, db=db) is True
        with pytest.raises(ValueError, match="revoked"):
            decode_access_token(token, db=db)
    finally:
        db.close()


def test_missing_revocation_store_falls_back_to_in_memory(testing_session_factory, monkeypatch):
    _clear_revocation_state()
    token = create_access_token(subject="u7", extra_claims={"username": "u7", "role": "viewer"})
    db = testing_session_factory()
    try:
        from sqlalchemy.exc import OperationalError

        class MissingTableQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                raise OperationalError(
                    "SELECT 1", {}, Exception("no such table: revoked_tokens")
                )

        monkeypatch.setattr(db, "query", lambda *args, **kwargs: MissingTableQuery())
        # Store not deployed: in-memory fallback should apply (no durable guarantee).
        assert is_token_revoked(token, db=db) is False
        revoke_token(token)  # in-memory only
        assert is_token_revoked(token, db=db) is True
    finally:
        db.close()


def test_revocation_lookup_error_rolls_back_session(testing_session_factory, monkeypatch):
    _clear_revocation_state()
    token = create_access_token(subject="u8", extra_claims={"username": "u8", "role": "viewer"})
    db = testing_session_factory()
    try:
        from sqlalchemy.exc import OperationalError

        real_query = db.query

        class BrokenQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                raise OperationalError("SELECT 1", {}, Exception("db down"))

        monkeypatch.setattr(db, "query", lambda *args, **kwargs: BrokenQuery())
        # DB lookup failure should fail closed and rollback so session remains usable.
        assert is_token_revoked(token, db=db) is True
        monkeypatch.setattr(db, "query", real_query)
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
    finally:
        db.close()