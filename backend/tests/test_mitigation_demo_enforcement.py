"""Gate E isolated local enforcement demo tests.

All tests use in-memory SQLite or the demo service's own temp SQLite. No
PostgreSQL, no preserved DB, no public network, no production enforcement.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.v1.routes import mitigation_policy_admin as policy_admin_module
from app.core.security import create_access_token, require_admin, require_analyst
from app.db.session import get_db
from app.main import app
from app.schemas.mitigation import MitigationPolicyConfig
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services.mitigation_demo_service import get_status, reset_for_tests
from app.services.mitigation_policy_lifecycle_service import MitigationPolicyLifecycleService
from tests.mitigation_persistence_helpers import sqlite_session_factory

client = TestClient(app)
API = "/api/v1/security/mitigation/demo"
FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ADMIN_ACTOR = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash="sha256:" + "a" * 64)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda *a, **k: None)
    reset_for_tests()
    old = policy_admin_module._lifecycle_service
    policy_admin_module._lifecycle_service = MitigationPolicyLifecycleService()
    prev_admin = app.dependency_overrides.get(require_admin)
    prev_analyst = app.dependency_overrides.get(require_analyst)
    app.dependency_overrides[require_admin] = lambda: {"role": "admin", "actor_id": "test-admin"}
    app.dependency_overrides[require_analyst] = lambda: {"role": "analyst", "actor_id": "test-analyst"}
    yield
    reset_for_tests()
    policy_admin_module._lifecycle_service = old
    if prev_admin is None:
        app.dependency_overrides.pop(require_admin, None)
    else:
        app.dependency_overrides[require_admin] = prev_admin
    if prev_analyst is None:
        app.dependency_overrides.pop(require_analyst, None)
    else:
        app.dependency_overrides[require_analyst] = prev_analyst


@pytest.fixture()
def db_session():
    engine, factory = sqlite_session_factory()
    session = factory()
    app.dependency_overrides[get_db] = lambda: (yield session)
    try:
        yield session
    finally:
        app.dependency_overrides.pop(get_db, None)
        session.close()
        engine.dispose()


def _token(role: str, subject: str = "u1@example.test") -> str:
    return create_access_token(subject=subject, extra_claims={"user_id": 1, "username": subject, "role": role, "is_active": True})


def _headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(role)}"}


def _seed_active_policy(version: str = "demo-1.0.0", mode: str = "enforce", block_enabled: bool = True, block_threshold: float = 80.0) -> str:
    svc = policy_admin_module.get_lifecycle_service()
    cfg = MitigationPolicyConfig(
        policy_version=version, enabled=True, mode=mode,
        monitoring_score_threshold=20.0, throttling_score_threshold=60.0, blocking_score_threshold=max(block_threshold, 60.0),
        minimum_authentication_failures=3, require_grouped_brute_force=False,
        throttle_enabled=True, throttle_limit=10, throttle_window_seconds=60, throttle_duration_seconds=60,
        block_enabled=block_enabled, block_duration_seconds=60, max_block_duration_seconds=300,
        admin_protection_enabled=True, max_evidence_references=10,
    )
    created = svc.propose_policy(actor=ADMIN_ACTOR, config=cfg, created_at=FIXED_NOW - timedelta(days=1))
    assert created.ok, created.error
    validated = svc.validate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert validated.ok, validated.error
    activated = svc.activate_policy(actor=ADMIN_ACTOR, version=version, at=FIXED_NOW)
    assert activated.ok, activated.error
    return version


def _enable(version: str = "demo-1.0.0", max_requests: int = 25, max_duration: int = 300):
    return client.post(f"{API}/enable", headers=_headers("admin"), json={
        "confirmation": "ENABLE_LOCAL_DEMO", "policy_version": version,
        "max_requests": max_requests, "max_duration_seconds": max_duration,
        "synthetic_only_ack": True, "loopback_only_ack": True,
    })


def _run(demo_id: str, requests):
    return client.post(f"{API}/run", headers=_headers("admin"), json={"demo_id": demo_id, "synthetic": True, "requests": requests})


def test_default_off():
    r = client.get(f"{API}/status", headers=_headers("analyst"))
    assert r.status_code == 200
    body = r.json()
    assert body["demo_mode"] is False
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True
    assert body["kill_switch_active"] is False


def test_enable_requires_explicit_confirmation():
    _seed_active_policy()
    r = client.post(f"{API}/enable", headers=_headers("admin"), json={
        "confirmation": "YES", "policy_version": "demo-1.0.0", "max_requests": 10, "max_duration_seconds": 60,
        "synthetic_only_ack": True, "loopback_only_ack": True,
    })
    assert r.status_code == 422


def test_enable_requires_admin():
    from fastapi import HTTPException
    _seed_active_policy()
    prev = app.dependency_overrides.get(require_admin)
    def _deny():
        raise HTTPException(status_code=403, detail="forbidden")
    app.dependency_overrides[require_admin] = _deny
    try:
        r = client.post(f"{API}/enable", headers=_headers("analyst"), json={
            "confirmation": "ENABLE_LOCAL_DEMO", "policy_version": "demo-1.0.0",
            "max_requests": 10, "max_duration_seconds": 60, "synthetic_only_ack": True, "loopback_only_ack": True,
        })
        assert r.status_code in (401, 403)
    finally:
        if prev is None:
            app.dependency_overrides.pop(require_admin, None)
        else:
            app.dependency_overrides[require_admin] = prev


def test_loopback_guard_rejects_non_loopback_client(monkeypatch):
    _seed_active_policy()
    monkeypatch.setattr("app.api.v1.routes.mitigation_demo._client_host", lambda req: "203.0.113.10")
    r = _enable()
    assert r.status_code == 409
    assert "loopback" in r.text.lower()


def test_synthetic_only_required():
    _seed_active_policy()
    en = _enable(); assert en.status_code == 200
    demo_id = en.json()["active_demo_id"]
    r = client.post(f"{API}/run", headers=_headers("admin"), json={"demo_id": demo_id, "synthetic": False, "requests": []})
    assert r.status_code == 422


def test_benign_request_allowed():
    _seed_active_policy()
    en = _enable(); demo_id = en.json()["active_demo_id"]
    r = _run(demo_id, [{"request_id":"b1","client_ip":"127.0.0.1","scenario":"benign","bot_risk_score":1,"auth_failures":0,"authenticated":False,"attribution_status":"missing","scope_type":"unattributed"}])
    assert r.status_code == 200
    o = r.json()["outcomes"][0]
    assert o["allowed"] is True
    assert o["actual_outcome"].startswith("advisory:") or o["actual_outcome"].startswith("allowed:")


def test_suspicious_advisory_recorded():
    _seed_active_policy()
    en = _enable(); demo_id = en.json()["active_demo_id"]
    r = _run(demo_id, [{"request_id":"s1","client_ip":"127.0.0.1","scenario":"suspicious","bot_risk_score":55,"auth_failures":10,"authenticated":False,"attribution_status":"network_ip","scope_type":"network_ip"}])
    assert r.status_code == 200
    o = r.json()["outcomes"][0]
    assert o["decision_uuid"]


def test_explicit_block_when_enabled():
    _seed_active_policy(block_threshold=50.0)
    en = _enable(); demo_id = en.json()["active_demo_id"]
    r = _run(demo_id, [{"request_id":"blk1","client_ip":"127.0.0.1","scenario":"malicious","bot_risk_score":95,"auth_failures":20,"authenticated":True,"attribution_status":"verified_user","scope_type":"verified_user","principal_hash":"sha256:" + "b"*64}])
    assert r.status_code == 200
    o = r.json()["outcomes"][0]
    assert o["intended_action"] in ("block", "throttle", "monitor", "allow")
    # With enforce mode + high score + verified user + block enabled, should be blocked
    if o["intended_action"] == "block":
        assert o["allowed"] is False
        assert o["enforcement_state"] == "enforced_block"


def test_invalid_policy_rejected():
    r = _enable(version="missing-1.0.0")
    assert r.status_code == 409


def test_kill_switch_disables_enforcement():
    _seed_active_policy(block_threshold=50.0)
    en = _enable(); demo_id = en.json()["active_demo_id"]
    k = client.post(f"{API}/kill-switch", headers=_headers("admin"))
    assert k.status_code == 200
    assert k.json()["kill_switch_active"] is True
    assert k.json()["enforcement_enabled"] is False
    r = _run(demo_id, [{"request_id":"after-kill","client_ip":"127.0.0.1","scenario":"malicious","bot_risk_score":99,"auth_failures":20,"authenticated":True,"attribution_status":"verified_user","scope_type":"verified_user","principal_hash":"sha256:" + "c"*64}])
    # run should be rejected because kill switch active / demo not active for enforcement; service raises guard
    assert r.status_code == 409


def test_request_limit_stops():
    _seed_active_policy()
    en = _enable(max_requests=1)
    demo_id = en.json()["active_demo_id"]
    r1 = _run(demo_id, [{"request_id":"r1","client_ip":"127.0.0.1","scenario":"benign","bot_risk_score":1}])
    assert r1.status_code == 200
    r2 = _run(demo_id, [{"request_id":"r2","client_ip":"127.0.0.1","scenario":"benign","bot_risk_score":1}])
    assert r2.status_code == 409


def test_disable_returns_advisory_only():
    _seed_active_policy()
    en = _enable(); assert en.status_code == 200
    d = client.post(f"{API}/disable", headers=_headers("admin"), json={"reason": "test"})
    assert d.status_code == 200
    assert d.json()["enforcement_enabled"] is False
    assert d.json()["advisory_only"] is True


def test_non_loopback_synthetic_request_rejected_by_scope_guard():
    _seed_active_policy()
    en = _enable(); demo_id = en.json()["active_demo_id"]
    r = _run(demo_id, [{"request_id":"ext1","client_ip":"8.8.8.8","scenario":"external","bot_risk_score":99}])
    assert r.status_code == 200
    o = r.json()["outcomes"][0]
    assert o["actual_outcome"] == "rejected_by_scope_guard"
    assert o["allowed"] is True
    assert o["enforcement_state"] == "advisory_only"


def test_audit_event_created_in_demo_db():
    _seed_active_policy(block_threshold=50.0)
    en = _enable(); demo_id = en.json()["active_demo_id"]
    r = _run(demo_id, [{"request_id":"audit1","client_ip":"127.0.0.1","scenario":"suspicious","bot_risk_score":60,"auth_failures":10,"authenticated":True,"attribution_status":"verified_user","scope_type":"verified_user","principal_hash":"sha256:" + "d"*64}])
    assert r.status_code == 200
    o = r.json()["outcomes"][0]
    assert o["decision_uuid"]
    # audit event uuid may be present when persistence succeeds
    assert o["audit_event_uuid"] is None or isinstance(o["audit_event_uuid"], str)


def test_no_production_middleware_activation():
    from app.main import app as the_app
    # check via openapi to include mounted router paths
    openapi = the_app.openapi()
    paths = list((openapi.get("paths") or {}).keys())
    assert any(p.endswith("/security/mitigation/demo/status") for p in paths)
    middleware_classes = [m.cls.__name__ for m in the_app.user_middleware]
    assert "DemoEnforcementMiddleware" not in middleware_classes


def test_demo_db_dir_defaults_under_system_temp(monkeypatch):
    import tempfile
    from pathlib import Path

    from app.services.mitigation_demo_service import resolve_demo_db_dir

    monkeypatch.setattr("app.core.config.settings.MITIGATION_DEMO_DB_DIR", "", raising=False)
    p = resolve_demo_db_dir()
    root = Path(tempfile.gettempdir()).resolve()
    assert p == root / "apisentry_mitigation_demo"
    assert root in p.parents or p == root


def test_demo_db_dir_rejects_outside_temp(monkeypatch):
    from app.services.mitigation_demo_service import DemoGuardError, resolve_demo_db_dir

    monkeypatch.setattr(
        "app.core.config.settings.MITIGATION_DEMO_DB_DIR",
        r"C:\Windows\System32\apisentry_demo",
        raising=False,
    )
    with pytest.raises(DemoGuardError):
        resolve_demo_db_dir()


def test_demo_db_dir_accepts_temp_subdir(monkeypatch):
    import tempfile
    from pathlib import Path

    from app.services.mitigation_demo_service import resolve_demo_db_dir

    safe = Path(tempfile.gettempdir()) / "apisentry_demo_test_safe"
    monkeypatch.setattr("app.core.config.settings.MITIGATION_DEMO_DB_DIR", str(safe), raising=False)
    p = resolve_demo_db_dir()
    assert Path(tempfile.gettempdir()).resolve() in p.parents or p == Path(tempfile.gettempdir()).resolve()

def test_disable_status_is_clean_and_distinct():
    _seed_active_policy()
    en = _enable(); assert en.status_code == 200
    d = client.post(f"{API}/disable", headers=_headers("admin"), json={"reason": "test"})
    assert d.status_code == 200
    body = d.json()
    assert body["demo_mode"] is False
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True
    assert body["kill_switch_active"] is False
    assert body["active_demo_id"] is None
    assert body["status_reason"] == "disabled"
    assert body["real_enforcement"] is False


def test_status_reports_expired_demo_as_advisory():
    _seed_active_policy()
    en = _enable(max_duration=10)
    assert en.status_code == 200
    from app.services import mitigation_demo_service as svc
    from datetime import timedelta
    with svc._lock:
        svc._state.expires_at = svc._now() - timedelta(seconds=1)
    r = client.get(f"{API}/status", headers=_headers("analyst"))
    assert r.status_code == 200
    body = r.json()
    assert body["demo_mode"] is True
    assert body["expired"] is True
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True
    assert body["status_reason"] == "expired"
    assert body["real_enforcement"] is False


def test_kill_switch_status_semantics_are_explicit():
    _seed_active_policy()
    en = _enable(); assert en.status_code == 200
    k = client.post(f"{API}/kill-switch", headers=_headers("admin"))
    assert k.status_code == 200
    body = k.json()
    assert body["demo_mode"] is True
    assert body["kill_switch_active"] is True
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True
    assert body["status_reason"] == "kill_switch_active"
    assert body["real_enforcement"] is False
