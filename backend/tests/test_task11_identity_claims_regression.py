"""Task 11 regression tests for fallback identity and role confusion.

All database access is routed to disposable in-memory SQLite by conftest. No
configured database, production initializer, or network service is used.
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
    """Keep registry-backed identities isolated to one test."""
    previous = dict(_USER_REGISTRY)
    _USER_REGISTRY.clear()
    try:
        yield
    finally:
        _USER_REGISTRY.clear()
        _USER_REGISTRY.update(previous)


def _add_user(factory, *, email: str, username: str, role: str, password: str = "SecurePass123!") -> int:
    db = factory()
    try:
        user = User(
            email=email,
            username=username,
            hashed_password=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return int(user.id)
    finally:
        db.close()


def _token(*, user_id: int | None, sub: str, username: str, role: str = "admin") -> str:
    claims: dict[str, Any] = {
        "username": username,
        "role": role,
        "is_active": True,
    }
    if user_id is not None:
        claims["user_id"] = user_id
    return create_access_token(subject=sub, extra_claims=claims)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_fallback_identity_cannot_inherit_database_user_one_role(testing_session_factory):
    admin_id = _add_user(
        testing_session_factory,
        email="db-admin@example.test",
        username="db_admin",
        role="admin",
    )
    assert admin_id == 1

    register_user(
        "fallback_viewer",
        "FallbackPass123!",
        actor_id="actor_fallback_viewer",
        role="viewer",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "fallback_viewer", "password": "FallbackPass123!"},
    )
    assert login.status_code == 200

    token = login.json()["access_token"]
    payload = decode_access_token(token)
    assert "user_id" not in payload
    assert payload["sub"] == "actor_fallback_viewer"

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["role"] == "viewer"
    assert profile.json()["actor_id"] == "actor_fallback_viewer"

    admin_route = client.get("/api/v1/users", headers=_auth_header(token))
    assert admin_route.status_code == 403


def test_user_id_claim_with_foreign_sub_and_username_is_rejected(testing_session_factory):
    victim_id = _add_user(
        testing_session_factory,
        email="victim-admin@example.test",
        username="victim_admin",
        role="admin",
    )
    token = _token(user_id=victim_id, sub="attacker", username="attacker", role="admin")

    response = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Contradictory identity claims"


def test_user_id_claim_cannot_point_to_another_username_resolved_user(testing_session_factory):
    first_id = _add_user(
        testing_session_factory,
        email="first@example.test",
        username="first_user",
        role="viewer",
    )
    second_id = _add_user(
        testing_session_factory,
        email="second@example.test",
        username="second_user",
        role="admin",
    )
    assert first_id != second_id

    token = _token(
        user_id=first_id,
        sub=f"user_{second_id}",
        username="second_user",
        role="admin",
    )
    response = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Contradictory identity claims"


def test_username_resolution_with_contradictory_subject_is_rejected(testing_session_factory):
    _add_user(
        testing_session_factory,
        email="target@example.test",
        username="target_user",
        role="admin",
    )
    token = _token(user_id=None, sub="attacker", username="target_user", role="admin")

    response = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Contradictory identity claims"


def test_valid_database_backed_identity_still_resolves_with_rbac(testing_session_factory):
    user_id = _add_user(
        testing_session_factory,
        email="real-admin@example.test",
        username="real_admin",
        role="admin",
        password="RealAdminPass123!",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "real_admin", "password": "RealAdminPass123!"},
    )
    assert login.status_code == 200
    assert login.json()["user"]["id"] == user_id

    token = login.json()["access_token"]
    payload = decode_access_token(token)
    assert payload["user_id"] == user_id
    assert payload["sub"] == f"user_{user_id}"

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["role"] == "admin"

    admin_route = client.get("/api/v1/users", headers=_auth_header(token))
    assert admin_route.status_code == 200
