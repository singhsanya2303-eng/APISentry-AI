"""Regression tests for bounded cleanup of expired database revocation rows.

All sessions come from the isolated in-memory SQLite fixtures. No real database,
Alembic command, or background job is used.
"""

from datetime import datetime, timezone
import hashlib
from unittest.mock import MagicMock

import pytest

from app.core import security
from app.core.security import (
    _REVOKED_TOKENS,
    cleanup_expired_revoked_tokens,
    create_access_token,
    is_token_revoked,
    revoke_token,
)
from app.models.revoked_token import RevokedToken


@pytest.fixture(autouse=True)
def _reset_db_cleanup_throttle(monkeypatch):
    monkeypatch.setattr(security, "_last_db_revocation_cleanup_monotonic", 0.0)
    monkeypatch.setattr(security, "_DB_REVOCATION_CLEANUP_INTERVAL_SECONDS", 300)
    _REVOKED_TOKENS.clear()
    yield
    _REVOKED_TOKENS.clear()


def _add_revoked_row(db, label: str, expires_at: datetime) -> str:
    token_hash = hashlib.sha256(label.encode("utf-8")).hexdigest()
    db.add(
        RevokedToken(
            token_hash=token_hash,
            expires_at=expires_at,
            revoked_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    return token_hash


def test_cleanup_deletes_expired_rows_and_preserves_active_rows(testing_session_factory):
    db = testing_session_factory()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expired_hash = _add_revoked_row(
        db,
        "expired",
        datetime.fromtimestamp(now_ts - 60, tz=timezone.utc),
    )
    active_hash = _add_revoked_row(
        db,
        "active",
        datetime.fromtimestamp(now_ts + 600, tz=timezone.utc),
    )

    deleted = cleanup_expired_revoked_tokens(db, now_ts=now_ts, force=True)

    assert deleted == 1
    remaining = {row.token_hash for row in db.query(RevokedToken).all()}
    assert expired_hash not in remaining
    assert active_hash in remaining


def test_cleanup_is_throttled_but_force_runs_again(testing_session_factory):
    db = testing_session_factory()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    first_hash = _add_revoked_row(
        db,
        "first-expired",
        datetime.fromtimestamp(now_ts - 60, tz=timezone.utc),
    )

    assert cleanup_expired_revoked_tokens(db, now_ts=now_ts, force=True) == 1

    second_hash = _add_revoked_row(
        db,
        "second-expired",
        datetime.fromtimestamp(now_ts - 30, tz=timezone.utc),
    )
    assert cleanup_expired_revoked_tokens(db, now_ts=now_ts) == 0
    assert any(row.token_hash == second_hash for row in db.query(RevokedToken).all())

    assert cleanup_expired_revoked_tokens(db, now_ts=now_ts, force=True) == 1
    remaining = {row.token_hash for row in db.query(RevokedToken).all()}
    assert first_hash not in remaining
    assert second_hash not in remaining


def test_cleanup_limits_each_batch(testing_session_factory, monkeypatch):
    db = testing_session_factory()
    monkeypatch.setattr(security, "_DB_REVOCATION_CLEANUP_BATCH_SIZE", 2)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    for index in range(4):
        _add_revoked_row(
            db,
            f"batch-{index}",
            datetime.fromtimestamp(now_ts - 60 - index, tz=timezone.utc),
        )

    assert cleanup_expired_revoked_tokens(db, now_ts=now_ts, force=True) == 2
    assert db.query(RevokedToken).count() == 2


def test_revoke_token_stores_only_hash_and_keeps_expired_rows_bounded(
    testing_session_factory, monkeypatch
):
    db = testing_session_factory()
    cleanup = MagicMock()
    monkeypatch.setattr(security, "cleanup_expired_revoked_tokens", cleanup)

    token = create_access_token(
        subject="cleanup-user",
        extra_claims={"username": "cleanup-user", "role": "viewer"},
    )
    revoke_token(token, db=db)

    expected_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    rows = db.query(RevokedToken).all()
    assert len(rows) == 1
    assert rows[0].token_hash == expected_hash
    assert token not in {rows[0].token_hash, str(rows[0].id)}
    assert expected_hash in _REVOKED_TOKENS
    assert token not in _REVOKED_TOKENS
    cleanup.assert_called_once()
    assert cleanup.call_args.args == (db,)
    assert isinstance(cleanup.call_args.kwargs["now_ts"], int)


def test_db_revocation_survives_cleared_in_memory_state(testing_session_factory):
    db = testing_session_factory()
    token = create_access_token(
        subject="restart-user",
        extra_claims={"username": "restart-user", "role": "viewer"},
    )
    revoke_token(token, db=db)

    _REVOKED_TOKENS.clear()

    assert is_token_revoked(token, db=db) is True


def test_cleanup_failure_does_not_prevent_logout_revocation(
    testing_session_factory, monkeypatch
):
    db = testing_session_factory()

    def _raise(*args, **kwargs):
        raise RuntimeError("cleanup unavailable")

    monkeypatch.setattr(security, "cleanup_expired_revoked_tokens", _raise)
    token = create_access_token(
        subject="cleanup-failure-user",
        extra_claims={"username": "cleanup-failure-user", "role": "viewer"},
    )

    revoke_token(token, db=db)

    assert db.query(RevokedToken).count() == 1
    assert hashlib.sha256(token.strip().encode("utf-8")).hexdigest() in _REVOKED_TOKENS


class _FailingSession:
    def __init__(self, message: str = "boom"):
        self.message = message
        self.rolled_back = False

    def query(self, *args, **kwargs):
        raise RuntimeError(self.message)

    def rollback(self):
        self.rolled_back = True


def test_cleanup_rolls_back_and_returns_zero_on_query_failure():
    session = _FailingSession()

    assert cleanup_expired_revoked_tokens(session, force=True) == 0
    assert session.rolled_back is True


def test_missing_revocation_table_is_tolerated_during_cleanup():
    session = _FailingSession("no such table: revoked_tokens")

    assert cleanup_expired_revoked_tokens(session, force=True) == 0
    assert session.rolled_back is True
