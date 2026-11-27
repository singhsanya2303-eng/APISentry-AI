"""MW4-C P1 focused RBAC/security regression tests.

Uses existing TestClient patterns; no PostgreSQL, no external exposure.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routes import mitigation_policy_admin as policy_admin_module
from app.core.security import create_access_token, require_analyst_or_api_key
from app.db.session import get_db
from app.main import app
from app.schemas.mitigation import MitigationPolicyConfig
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services.mitigation_demo_service import reset_for_tests
from app.services.mitigation_policy_lifecycle_service import MitigationPolicyLifecycleService
from tests.mitigation_persistence_helpers import sqlite_session_factory

client = TestClient(app)
FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ADMIN_ACTOR = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash="sha256:" + "a" * 64)


@pytest.fixture(autouse=True)
def _isolate():
    engine, SessionFactory = sqlite_session_factory()
    policy_admin_module._lifecycle_service = MitigationPolicyLifecycleService()
    reset_for_tests()

    def override_get_db():
        db = SessionFactory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield
    finally:
        reset_for_tests()
        app.dependency_overrides.pop(get_db, None)
        policy_admin_module._lifecycle_service = None
        engine.dispose()


def _token(role: str) -> str:
    return create_access_token(
        subject=f"{role}@example.test",
        extra_claims={"user_id": 1, "username": role, "role": role, "is_active": True},
    )


def _hdr(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(role)}"}


def _seed_active_policy():
    svc = policy_admin_module.get_lifecycle_service()
    cfg = MitigationPolicyConfig(
        policy_version="rbac-p1-1.0.0", enabled=True, mode="enforce",
        monitoring_score_threshold=20.0, throttling_score_threshold=60.0, blocking_score_threshold=80.0,
        minimum_authentication_failures=3, require_grouped_brute_force=False,
        throttle_enabled=True, throttle_limit=10, throttle_window_seconds=60, throttle_duration_seconds=60,
        block_enabled=True, block_duration_seconds=60, max_block_duration_seconds=300,
        admin_protection_enabled=True, max_evidence_references=10,
    )
    for fn in [
        lambda: svc.propose_policy(actor=ADMIN_ACTOR, config=cfg, created_at=FIXED_NOW - timedelta(days=1)),
        lambda: svc.validate_policy(actor=ADMIN_ACTOR, version="rbac-p1-1.0.0", at=FIXED_NOW),
        lambda: svc.activate_policy(actor=ADMIN_ACTOR, version="rbac-p1-1.0.0", at=FIXED_NOW),
    ]:
        r = fn()
        assert r.ok, getattr(r, "error", None)


def test_demo_mutations_require_admin_role():
    _seed_active_policy()
    payload = {
        "confirmation": "ENABLE_LOCAL_DEMO", "policy_version": "rbac-p1-1.0.0",
        "max_requests": 5, "max_duration_seconds": 60, "synthetic_only_ack": True, "loopback_only_ack": True,
    }
    for role in ("viewer", "analyst"):
        r = client.post("/api/v1/security/mitigation/demo/enable", headers=_hdr(role), json=payload)
        assert r.status_code in (401, 403)
    # analyst can read status
    s = client.get("/api/v1/security/mitigation/demo/status", headers=_hdr("analyst"))
    assert s.status_code == 200


def test_viewer_cannot_read_demo_status():
    r = client.get("/api/v1/security/mitigation/demo/status", headers=_hdr("viewer"))
    assert r.status_code in (401, 403)


def test_demo_kill_switch_requires_admin():
    r = client.post("/api/v1/security/mitigation/demo/kill-switch", headers=_hdr("analyst"))
    assert r.status_code in (401, 403)


def test_mitigation_runtime_analyze_rejects_missing_auth():
    # This file is not in conftest auth-skip allowlist, so restore real auth dep.
    prev = app.dependency_overrides.pop(require_analyst_or_api_key, None)
    try:
        r = client.get("/api/v1/security/mitigation/runtime-analyze")
        assert r.status_code in (401, 503)
    finally:
        if prev is None:
            app.dependency_overrides[require_analyst_or_api_key] = lambda: None
        else:
            app.dependency_overrides[require_analyst_or_api_key] = prev


def test_mitigation_runtime_analyze_rejects_viewer_jwt():
    prev = app.dependency_overrides.pop(require_analyst_or_api_key, None)
    try:
        r = client.get("/api/v1/security/mitigation/runtime-analyze", headers=_hdr("viewer"))
        assert r.status_code == 403
    finally:
        if prev is None:
            app.dependency_overrides[require_analyst_or_api_key] = lambda: None
        else:
            app.dependency_overrides[require_analyst_or_api_key] = prev
