"""WP9 dedicated isolated request-time enforcement demo tests.

All state is created by the demo service in a temp SQLite DB. Production
middleware is never registered and the configured database is never used.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.security import get_current_active_user, require_admin, require_analyst
from app.db.session import get_db
from app.main import app as production_app
from app.main import create_app
from app.models.mitigation import ALLOWED_AUDIT_DETAIL_KEYS
from app.services import request_enforcement_demo_service as demo_service
from app.services.request_enforcement_service import RequestEnforcementMiddleware

API = "/api/v1/security/mitigation/request-enforcement-demo"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda *a, **k: None)
    demo_service.reset_for_tests()
    previous_admin = production_app.dependency_overrides.get(require_admin)
    previous_analyst = production_app.dependency_overrides.get(require_analyst)
    production_app.dependency_overrides[require_admin] = lambda: {
        "role": "admin",
        "actor_id": "test-admin",
    }
    production_app.dependency_overrides[require_analyst] = lambda: {
        "role": "analyst",
        "actor_id": "test-analyst",
    }
    try:
        yield
    finally:
        demo_service.reset_for_tests()
        if previous_admin is None:
            production_app.dependency_overrides.pop(require_admin, None)
        else:
            production_app.dependency_overrides[require_admin] = previous_admin
        if previous_analyst is None:
            production_app.dependency_overrides.pop(require_analyst, None)
        else:
            production_app.dependency_overrides[require_analyst] = previous_analyst


client = TestClient(production_app, base_url="http://127.0.0.1")


def _enable_body(demo_id: str, version: str, scenario: str) -> dict[str, object]:
    return {
        "confirmation": "ENABLE_ISOLATED_REQUEST_ENFORCEMENT_DEMO",
        "demo_id": demo_id,
        "policy_version": version,
        "scenario": scenario,
        "max_requests": 12,
        "max_duration_seconds": 300,
        "synthetic_only_ack": True,
        "loopback_only_ack": True,
        "isolated_db_ack": True,
    }


def _enable(demo_id: str, version: str, scenario: str):
    response = client.post(f"{API}/enable", json=_enable_body(demo_id, version, scenario))
    assert response.status_code == 200, response.text
    return response.json()


def _run(demo_id: str, count: int):
    response = client.post(
        f"{API}/run",
        json={"demo_id": demo_id, "synthetic": True, "request_count": count},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _no_production_middleware() -> bool:
    return not any(
        getattr(getattr(item, "cls", None), "__name__", "") == "RequestEnforcementMiddleware"
        for item in production_app.user_middleware
    )


def test_default_is_off_and_production_middleware_is_unregistered() -> None:
    response = client.get(f"{API}/status")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["demo_enabled"] is False
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True
    assert body["real_enforcement"] is False
    assert body["production_middleware_registered"] is False
    assert body["persistence_db"] == "none"
    assert _no_production_middleware()


def test_viewer_is_denied_loopback_demo_reads_and_mutations() -> None:
    local_app = create_app()
    local_app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(
        role="viewer", is_active=True
    )
    viewer = TestClient(local_app, base_url="http://127.0.0.1")
    assert viewer.get(f"{API}/status").status_code == 403
    assert viewer.get(f"{API}/evidence").status_code == 403
    assert viewer.post(
        f"{API}/enable", json=_enable_body("viewer-demo", "viewer-policy", "allow")
    ).status_code == 403
    assert _no_production_middleware()


def test_explicit_confirmation_and_loopback_are_required() -> None:
    body = _enable_body("wp9-guard", "wp9-guard-policy", "allow")
    body["confirmation"] = "ENABLE_LOCAL_DEMO"
    assert client.post(f"{API}/enable", json=body).status_code == 422

    remote = TestClient(
        production_app, base_url="http://127.0.0.1", client=("203.0.113.10", 12345)
    )
    assert remote.get(f"{API}/status").status_code == 403
    assert remote.post(f"{API}/enable", json=_enable_body("x", "y", "allow")).status_code == 403
    assert client.post(
        f"{API}/run", json={"demo_id": "unknown", "synthetic": True, "request_count": 1}
    ).status_code == 409


def test_allow_scenario_preserves_handler_and_leaves_production_unmodified() -> None:
    enabled = _enable("wp9-allow", "wp9-allow-policy", "allow")
    assert enabled["enforcement_enabled"] is True
    assert enabled["scenario"] == "allow"
    assert _no_production_middleware()

    result = _run("wp9-allow", 1)
    outcome = result["outcomes"][0]
    assert outcome["status_code"] == 200
    assert outcome["enforcement_outcome"] == "allowed"
    assert outcome["handler_reached"] is True
    assert result["status"]["requests_executed"] == 1


def test_block_scenario_blocks_handler_and_persists_safe_evidence() -> None:
    _enable("wp9-block", "wp9-block-policy", "block")
    result = _run("wp9-block", 1)
    outcome = result["outcomes"][0]
    assert outcome["status_code"] == 403
    assert outcome["enforcement_outcome"] == "blocked"
    assert outcome["handler_reached"] is False
    assert outcome["decision_ref"]

    status = result["status"]
    assert status["decision_count"] >= 1
    assert status["audit_event_count"] >= 1

    evidence = client.get(f"{API}/evidence")
    assert evidence.status_code == 200, evidence.text
    body = evidence.json()
    assert body["decision_count"] >= 1
    audit = [
        item
        for item in body["audit_events"]
        if item["event_type"] == "enforcement_applied_reserved"
    ]
    assert audit
    details = audit[0]["details"]
    assert set(details).issubset(ALLOWED_AUDIT_DETAIL_KEYS)
    assert details["selected_action"] == "block"
    assert details["enforcement_outcome"] == "blocked"
    assert isinstance(details["risk_score"], float)
    assert details["mw1_status"] == "assessed"


def test_throttle_scenario_enforces_limit_and_window() -> None:
    _enable("wp9-throttle", "wp9-throttle-policy", "throttle")
    result = _run("wp9-throttle", 3)
    outcomes = result["outcomes"]
    assert [item["status_code"] for item in outcomes] == [200, 200, 429]
    assert [item["enforcement_outcome"] for item in outcomes] == [
        "throttle_permitted",
        "throttle_permitted",
        "throttled",
    ]
    assert [item["handler_reached"] for item in outcomes] == [True, True, False]


def test_kill_switch_returns_demo_to_advisory_only() -> None:
    _enable("wp9-kill", "wp9-kill-policy", "block")
    stopped = client.post(f"{API}/kill-switch")
    assert stopped.status_code == 200, stopped.text
    body = stopped.json()
    assert body["kill_switch_active"] is True
    assert body["enforcement_enabled"] is False
    assert body["advisory_only"] is True

    outcome = _run("wp9-kill", 1)["outcomes"][0]
    assert outcome["status_code"] == 200
    assert outcome["enforcement_outcome"] == "advisory_allowed"
    assert outcome["handler_reached"] is True


def test_fail_closed_dependency_behavior() -> None:
    _enable("wp9-fc", "wp9-fc-policy", "allow")
    response = client.post(f"{API}/fail-closed")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status_code"] == 503
    assert body["detail"] == "Enforcement dependency unavailable; request not allowed"
    assert body["enforcement_outcome"] == "fail_closed"
    assert body["handler_reached"] is False
    assert body["production_middleware_registered"] is False


def test_disable_cleans_up_and_demo_is_repeatable() -> None:
    _enable("wp9-clean", "wp9-clean-policy", "allow")
    db_path = demo_service._state.db_path
    assert db_path and Path(db_path).exists()

    disabled = client.post(f"{API}/disable", json={"reason": "test_disable"})
    assert disabled.status_code == 200, disabled.text
    body = disabled.json()
    assert body["demo_enabled"] is False
    assert body["persistence_db"] == "none"
    assert not Path(db_path).exists()
    assert demo_service._state.runtime is None
    assert demo_service._state.client is None
    assert client.post(
        f"{API}/run", json={"demo_id": "wp9-clean", "synthetic": True, "request_count": 1}
    ).status_code == 409

    assert _enable("wp9-clean-again", "wp9-clean-again-policy", "allow")["demo_enabled"] is True


def test_persisted_demo_rows_are_readable_by_existing_dashboard_endpoints() -> None:
    _enable("wp9-dash", "wp9-dash-policy", "block")
    assert _run("wp9-dash", 1)["outcomes"][0]["status_code"] == 403
    factory = demo_service._state.session_factory
    assert factory is not None

    def _db_override():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    production_app.dependency_overrides[get_db] = _db_override
    try:
        decisions = client.get(
            "/api/v1/security/mitigation/decisions",
            params={"policy_version": "wp9-dash-policy"},
        )
        audits = client.get(
            "/api/v1/security/mitigation/audit-events",
            params={"event_type": "enforcement_applied_reserved"},
        )
    finally:
        production_app.dependency_overrides.pop(get_db, None)

    assert decisions.status_code == 200, decisions.text
    assert audits.status_code == 200, audits.text
    assert decisions.json()["total"] >= 1
    assert audits.json()["total"] >= 1
