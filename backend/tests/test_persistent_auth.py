"""End-to-end tests for persistent registration, login, JWT sessions, and RBAC."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services.user_service import get_user_by_email, get_user_by_id, update_user


client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_traffic_logging(monkeypatch):
    """Keep request logging out of the configured PostgreSQL database."""
    monkeypatch.setattr(
        "app.utils.middleware.save_traffic_log",
        MagicMock(return_value=True),
    )


def _register(email, username, password="SecurePass123!", role=None):
    payload = {
        "email": email,
        "username": username,
        "password": password,
    }
    if role is not None:
        payload["role"] = role
    return client.post("/api/v1/auth/register", json=payload)


def _login(identifier, password="SecurePass123!"):
    return client.post(
        "/api/v1/auth/login",
        json={"username": identifier, "password": password},
    )


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_registration_persists_and_login_works_from_a_new_session(
    testing_session_factory,
):
    response = _register("Alice@Example.com", "Alice.User")

    assert response.status_code == 201
    registered = response.json()
    assert registered["email"] == "alice@example.com"
    assert registered["username"] == "alice.user"
    assert registered["role"] == "viewer"
    assert registered["is_active"] is True

    # Confirm the row is visible from a completely separate database session.
    db = testing_session_factory()
    try:
        persisted = get_user_by_email(db, "alice@example.com")
        assert persisted is not None
        assert persisted.username == "alice.user"
        assert persisted.role == "viewer"
        assert persisted.hashed_password != "SecurePass123!"
        assert persisted.hashed_password.startswith("$2b$")
    finally:
        db.close()

    login = _login("alice@example.com")
    assert login.status_code == 200
    token_data = login.json()
    assert token_data["user"]["id"] == registered["id"]
    assert token_data["user"]["email"] == "alice@example.com"

    profile = client.get("/api/v1/auth/me", headers=_auth_header(token_data["access_token"]))
    assert profile.status_code == 200
    assert profile.json()["actor_id"] == registered["actor_id"]
    assert profile.json()["role"] == "viewer"
    assert profile.json()["username"] == "alice.user"


def test_duplicate_email_and_username_are_rejected_with_409(testing_session_factory):
    first = _register("duplicate@example.com", "duplicate_user")
    assert first.status_code == 201

    duplicate_email = _register("DUPLICATE@example.com", "another_user")
    assert duplicate_email.status_code == 409
    assert "already exists" in duplicate_email.json()["detail"]

    duplicate_username = _register("different@example.com", "Duplicate_User")
    assert duplicate_username.status_code == 409
    assert "already exists" in duplicate_username.json()["detail"]


def test_emailstr_validation_is_still_enforced(testing_session_factory):
    response = _register("not-an-email", "valid_username")

    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any(error.get("loc", [])[-1] == "email" for error in errors)


def test_disabled_account_cannot_login_and_existing_token_is_rejected(
    testing_session_factory,
):
    registered = _register("disabled@example.com", "disabled_user").json()

    login = _login("disabled_user")
    assert login.status_code == 200
    token = login.json()["access_token"]

    db = testing_session_factory()
    try:
        user = get_user_by_id(db, registered["id"])
        assert user is not None
        update_user(db, user, is_active=False)
    finally:
        db.close()

    blocked_login = _login("disabled_user")
    assert blocked_login.status_code == 403
    assert blocked_login.json()["detail"] == "User account is inactive"

    blocked_profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert blocked_profile.status_code == 403
    assert blocked_profile.json()["detail"] == "User account is inactive"


def _provision_role(testing_session_factory, user_id, role):
    db = testing_session_factory()
    try:
        user = get_user_by_id(db, user_id)
        assert user is not None
        update_user(db, user, role=role)
    finally:
        db.close()


def test_admin_analyst_viewer_authorization(testing_session_factory):
    admin = _register("admin@example.com", "admin_user").json()
    analyst = _register("analyst@example.com", "analyst_user").json()
    viewer = _register("viewer@example.com", "viewer_user").json()

    assert admin["role"] == "viewer"
    assert analyst["role"] == "viewer"
    assert viewer["role"] == "viewer"

    _provision_role(testing_session_factory, admin["id"], "admin")
    _provision_role(testing_session_factory, analyst["id"], "analyst")

    admin_token = _login("admin_user").json()["access_token"]
    analyst_token = _login("analyst_user").json()["access_token"]
    viewer_token = _login("viewer_user").json()["access_token"]

    viewer_list = client.get("/api/v1/users", headers=_auth_header(viewer_token))
    assert viewer_list.status_code == 403

    analyst_list = client.get("/api/v1/users", headers=_auth_header(analyst_token))
    assert analyst_list.status_code == 403

    admin_list = client.get("/api/v1/users", headers=_auth_header(admin_token))
    assert admin_list.status_code == 200
    listed_ids = {entry["id"] for entry in admin_list.json()}
    assert {admin["id"], analyst["id"], viewer["id"]}.issubset(listed_ids)

    own_record = client.get(
        f"/api/v1/users/{viewer['id']}",
        headers=_auth_header(viewer_token),
    )
    assert own_record.status_code == 200

    other_record = client.get(
        f"/api/v1/users/{analyst['id']}",
        headers=_auth_header(viewer_token),
    )
    assert other_record.status_code == 403


def test_logout_revokes_the_access_token(testing_session_factory):
    _register("logout@example.com", "logout_user")
    token = _login("logout_user").json()["access_token"]

    assert client.get("/api/v1/auth/me", headers=_auth_header(token)).status_code == 200

    logout = client.post("/api/v1/auth/logout", headers=_auth_header(token))
    assert logout.status_code == 200

    after_logout = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert after_logout.status_code == 401
    assert after_logout.json()["detail"] == "Authentication token has been revoked"


def test_analysis_route_accepts_analyst_jwt_and_rejects_viewer(
    testing_session_factory,
    monkeypatch,
):
    """JWT-only access to analysis routes follows admin/analyst/viewer RBAC."""
    monkeypatch.setattr(settings, "API_KEY", "")

    analyst = _register("jwt-analyst@example.com", "jwt_analyst").json()
    viewer = _register("jwt-viewer@example.com", "jwt_viewer").json()
    assert analyst["role"] == "viewer"
    assert viewer["role"] == "viewer"
    _provision_role(testing_session_factory, analyst["id"], "analyst")

    analyst_token = _login("jwt_analyst").json()["access_token"]
    viewer_token = _login("jwt_viewer").json()["access_token"]
    path = "/api/v1/security/bola/analyze"

    analyst_response = client.get(path, headers=_auth_header(analyst_token))
    assert analyst_response.status_code == 200

    viewer_response = client.get(path, headers=_auth_header(viewer_token))
    assert viewer_response.status_code == 403
    assert "Operation not permitted" in viewer_response.json()["detail"]


@pytest.mark.parametrize(
    ("email", "username", "payload_role"),
    [
        ("no-role@example.com", "no_role_user", None),
        ("admin-role@example.com", "admin_role_user", "admin"),
        ("analyst-role@example.com", "analyst_role_user", "analyst"),
        ("viewer-role@example.com", "viewer_role_user", "viewer"),
        ("unknown-role@example.com", "unknown_role_user", "superadmin"),
        ("empty-role@example.com", "empty_role_user", ""),
    ],
)
def test_public_registration_always_persists_viewer_role(
    testing_session_factory, email, username, payload_role
):
    payload = {
        "email": email,
        "username": username,
        "password": "SecurePass123!",
    }
    if payload_role is not None:
        payload["role"] = payload_role

    response = client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 201
    registered = response.json()
    assert registered["role"] == "viewer"

    db = testing_session_factory()
    try:
        persisted = get_user_by_email(db, email.lower())
        assert persisted is not None
        assert persisted.role == "viewer"
    finally:
        db.close()

    login = _login(username)
    assert login.status_code == 200
    token = login.json()["access_token"]
    profile = client.get("/api/v1/auth/me", headers=_auth_header(token))
    assert profile.status_code == 200
    assert profile.json()["role"] == "viewer"


def test_public_registration_ignores_unknown_role_value_without_elevation(
    testing_session_factory,
):
    payload = {
        "email": "weird-role@example.com",
        "username": "weird_role_user",
        "password": "SecurePass123!",
        "role": {"unexpected": "object"},
    }

    response = client.post("/api/v1/auth/register", json=payload)

    # The public registration schema ignores client-supplied role data for
    # compatibility; registration must never create a privileged account.
    assert response.status_code == 201
    registered = response.json()
    assert registered["role"] == "viewer"

    db = testing_session_factory()
    try:
        persisted = get_user_by_id(db, registered["id"])
        assert persisted is not None
        assert persisted.role == "viewer"
    finally:
        db.close()


def test_duplicate_registration_behavior_unchanged_when_role_supplied(
    testing_session_factory,
):
    first = _register("dupe-role@example.com", "dupe_role_user", role="admin")
    assert first.status_code == 201
    assert first.json()["role"] == "viewer"

    duplicate_email = _register("DUPE-ROLE@example.com", "other_user", role="admin")
    assert duplicate_email.status_code == 409
    assert "already exists" in duplicate_email.json()["detail"]

    duplicate_username = _register("different-dupe@example.com", "Dupe_Role_User", role="analyst")
    assert duplicate_username.status_code == 409
    assert "already exists" in duplicate_username.json()["detail"]


def test_authorized_admin_can_still_manage_roles_via_controlled_endpoint(
    testing_session_factory,
):
    admin = _register("ctrl-admin@example.com", "ctrl_admin").json()
    target = _register("ctrl-target@example.com", "ctrl_target").json()
    viewer = _register("ctrl-viewer@example.com", "ctrl_viewer").json()

    _provision_role(testing_session_factory, admin["id"], "admin")

    admin_token = _login("ctrl_admin").json()["access_token"]
    viewer_token = _login("ctrl_viewer").json()["access_token"]
    target_token_before = _login("ctrl_target").json()["access_token"]

    viewer_attempt = client.patch(
        f"/api/v1/users/{target['id']}",
        json={"role": "admin"},
        headers=_auth_header(viewer_token),
    )
    assert viewer_attempt.status_code == 403

    promote = client.patch(
        f"/api/v1/users/{target['id']}",
        json={"role": "analyst"},
        headers=_auth_header(admin_token),
    )
    assert promote.status_code == 200
    assert promote.json()["id"] == target["id"]
    assert promote.json()["role"] == "analyst"

    db = testing_session_factory()
    try:
        persisted = get_user_by_id(db, target["id"])
        assert persisted is not None
        assert persisted.role == "analyst"
    finally:
        db.close()

    # A still-valid token for a persistent user resolves against the current
    # controlled account state, so the promoted role is reflected immediately.
    promoted_profile = client.get(
        "/api/v1/auth/me", headers=_auth_header(target_token_before)
    )
    assert promoted_profile.status_code == 200
    assert promoted_profile.json()["role"] == "analyst"

    refreshed_token = _login("ctrl_target").json()["access_token"]
    refreshed_profile = client.get("/api/v1/auth/me", headers=_auth_header(refreshed_token))
    assert refreshed_profile.status_code == 200
    assert refreshed_profile.json()["role"] == "analyst"

    # Analyst (non-admin) still cannot use admin management endpoints.
    analyst_attempt = client.patch(
        f"/api/v1/users/{viewer['id']}",
        json={"role": "analyst"},
        headers=_auth_header(refreshed_token),
    )
    assert analyst_attempt.status_code == 403

    admin_list = client.get("/api/v1/users", headers=_auth_header(admin_token))
    assert admin_list.status_code == 200
    roles_by_id = {entry["id"]: entry["role"] for entry in admin_list.json()}
    assert roles_by_id[target["id"]] == "analyst"
