"""Task 12A regression tests for claims-only fallback principals.

All database access uses the disposable in-memory SQLite harness. These tests
prove that registry-backed and stale-ID fallback principals never inherit an
unrelated database user's identity or role.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    _USER_REGISTRY,
    create_access_token,
    decode_access_token,
    hash_password,
    register_user,
)
from app.main import app
from app.models.user import User

client = TestClient(app)


@pytest.fixture(autouse=True)
def _isolated_registry():
    previous = dict(_USER_REGISTRY)
    _USER_REGISTRY.clear()
    try:
        yield
    finally:
        _USER_REGISTRY.clear()
        _USER_REGISTRY.update(previous)


def _add_user(factory, *, email: str, username: str, role: str) -> int:
    db = factory()
    try:
        user = User(
            email=email,
            username=username,
            hashed_password=hash_password("SecurePass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return int(user.id)
    finally:
        db.close()


def _token(*, sub: str, username: str, role: str, user_id: int | None = None, actor_id: str | None = None) -> str:
    claims: dict[str, Any] = {
        "username": username,
        "role": role,
        "is_active": True,
    }
    if user_id is not None:
        claims["user_id"] = user_id
    if actor_id is not None:
        claims["actor_id"] = actor_id
    return create_access_token(subject=sub, extra_claims=claims)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_claims_only_token_with_registry_metadata_does_not_inherit_db_admin(testing_session_factory):
    admin_id = _add_user(
        testing_session_factory,
        email="fallback-admin@example.test",
        username="fallback_db_admin",
        role="admin",
    )
    assert admin_id == 1

    register_user(
        "legacy_viewer",
        "LegacyPass123!",
        actor_id="legacy_viewer_actor",
        role="viewer",
    )
    token = _token(
        sub="legacy_viewer_actor",
        username="legacy_viewer",
        role="viewer",
        actor_id="legacy_viewer_actor",
    )

    payload = decode_access_token(token)
    assert "user_id" not in payload

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["actor_id"] == "legacy_viewer_actor"
    assert profile.json()["role"] == "viewer"

    admin_route = client.get("/api/v1/users", headers=_auth_header(token))
    assert admin_route.status_code == 403


def test_registry_role_precedence_for_claims_only_principal_is_documented(testing_session_factory):
    _add_user(
        testing_session_factory,
        email="precedence-admin@example.test",
        username="precedence_db_admin",
        role="admin",
    )
    register_user(
        "registry_viewer",
        "RegistryPass123!",
        actor_id="registry_viewer_actor",
        role="viewer",
    )

    # The signed token claims admin, but registry metadata intentionally wins
    # for claims-only principals. The unrelated database admin is still not
    # inherited: the effective role remains the registry's viewer role.
    token = _token(
        sub="registry_viewer_actor",
        username="registry_viewer",
        role="admin",
        actor_id="registry_viewer_actor",
    )
    assert decode_access_token(token)["role"] == "admin"

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["role"] == "viewer"
    assert profile.json()["actor_id"] == "registry_viewer_actor"

    admin_route = client.get("/api/v1/users", headers=_auth_header(token))
    assert admin_route.status_code == 403


def test_stale_signed_user_id_without_database_row_falls_back_without_db_role(testing_session_factory):
    admin_id = _add_user(
        testing_session_factory,
        email="stale-admin@example.test",
        username="stale_db_admin",
        role="admin",
    )
    assert admin_id == 1

    stale_id = admin_id + 1_000_000
    token = _token(
        sub="stale_ghost_actor",
        username="stale_ghost",
        role="viewer",
        user_id=stale_id,
    )

    assert decode_access_token(token)["user_id"] == stale_id

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["actor_id"] == "stale_ghost_actor"
    assert profile.json()["role"] == "viewer"

    admin_route = client.get("/api/v1/users", headers=_auth_header(token))
    assert admin_route.status_code == 403


def test_stale_user_id_conflicting_with_resolved_database_user_is_rejected(testing_session_factory):
    _add_user(
        testing_session_factory,
        email="conflict-admin@example.test",
        username="conflict_db_admin",
        role="admin",
    )
    _add_user(
        testing_session_factory,
        email="resolved-user@example.test",
        username="resolved_user",
        role="viewer",
    )

    token = _token(
        sub="resolved-user@example.test",
        username="resolved_user",
        role="admin",
        user_id=9_000_000,
    )

    response = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Contradictory identity claims"
