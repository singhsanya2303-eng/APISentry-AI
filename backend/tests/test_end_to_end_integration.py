"""Complete synthetic detection-to-enforcement integration test.

The test drives the real production API routes for traffic analysis and dashboard
visibility, then the dedicated WP9 isolated middleware harness for enforcement.
All persistence is injected into an in-memory SQLite database; production
middleware is never registered and no configured database is contacted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.security import require_admin, require_analyst, require_analyst_or_api_key
from app.db.session import get_db
from app.main import app as production_app
from app.models.mitigation import (
    MitigationAuditEvent,
    MitigationDecision as DecisionRow,
    MitigationPolicy,
)
from app.models.traffic import APITrafficLog
from app.schemas.mitigation import MitigationPolicyConfig, MitigationPolicyMode
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services import request_enforcement_demo_service as demo_service
from app.services.mitigation_policy_lifecycle_persistence_service import (
    persist_lifecycle_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)
from tests.mitigation_persistence_helpers import sqlite_session_factory

FIXED_NOW = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)
CLIENT_IP = "127.0.0.1"
V1 = "e2e-advisory-policy"
V2 = "e2e-isolated-policy"
E2E_ACTOR = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash="sha256:" + "e" * 64)


@pytest.fixture()
def integration_client(monkeypatch: pytest.MonkeyPatch):
    engine, factory = sqlite_session_factory()
    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda *a, **k: None)

    previous = {
        "db": production_app.dependency_overrides.get(get_db),
        "dual": production_app.dependency_overrides.get(require_analyst_or_api_key),
        "admin": production_app.dependency_overrides.get(require_admin),
        "analyst": production_app.dependency_overrides.get(require_analyst),
    }

    def _db_override():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    production_app.dependency_overrides[get_db] = _db_override
    production_app.dependency_overrides[require_analyst_or_api_key] = lambda: {
        "role": "analyst",
        "actor_id": "e2e-analyst",
    }
    production_app.dependency_overrides[require_admin] = lambda: {
        "role": "admin",
        "actor_id": "e2e-admin",
    }
    production_app.dependency_overrides[require_analyst] = lambda: {
        "role": "analyst",
        "actor_id": "e2e-analyst",
    }

    demo_service.reset_for_tests()
    try:
        yield TestClient(production_app, base_url="http://127.0.0.1"), factory
    finally:
        demo_service.reset_for_tests()
        for key, value in previous.items():
            dependency = {
                "db": get_db,
                "dual": require_analyst_or_api_key,
                "admin": require_admin,
                "analyst": require_analyst,
            }[key]
            if value is None:
                production_app.dependency_overrides.pop(dependency, None)
            else:
                production_app.dependency_overrides[dependency] = value
        engine.dispose()


def _seed_traffic(factory) -> None:
    # Use the same opaque demo actor so the isolated harness sees grouped,
    # single-actor brute-force evidence rather than deliberately dropped
    # cross-actor evidence from a shared network address.
    actor_hash = demo_service._ACTOR.actor_hash
    with factory() as session:
        for index in range(6):
            session.add(
                APITrafficLog(
                    request_id=f"e2e-traffic-{index}",
                    timestamp=FIXED_NOW - timedelta(seconds=60 - index),
                    method="POST",
                    path="/login",
                    query_params={},
                    client_ip=CLIENT_IP,
                    user_agent="APISentryE2E/1.0",
                    status_code=401,
                    response_time_ms=2.0,
                    actor_id=actor_hash,
                )
            )
        session.commit()


def _register_advisory_policy(factory) -> None:
    lifecycle = MitigationPolicyLifecycleService()
    config = MitigationPolicyConfig(
        enabled=True,
        mode=MitigationPolicyMode.MONITOR,
        policy_version=V1,
        monitoring_score_threshold=20.0,
        throttling_score_threshold=75.0,
        blocking_score_threshold=90.0,
        minimum_authentication_failures=5,
        require_grouped_brute_force=True,
    )
    proposed = lifecycle.propose_policy(
        actor=E2E_ACTOR, config=config, created_at=FIXED_NOW - timedelta(minutes=10)
    )
    assert proposed.ok, proposed.error
    validated = lifecycle.validate_policy(
        actor=E2E_ACTOR, version=V1, at=FIXED_NOW - timedelta(minutes=9)
    )
    assert validated.ok, validated.error
    activated = lifecycle.activate_policy(
        actor=E2E_ACTOR, version=V1, at=FIXED_NOW - timedelta(minutes=8)
    )
    assert activated.ok, activated.error
    with factory() as session:
        persisted = persist_lifecycle_result(session, activated, actor=E2E_ACTOR, at=FIXED_NOW)
        session.commit()
    assert persisted.ok, persisted.error


def _row_counts(factory, policy_version: str) -> tuple[int, int]:
    with factory() as session:
        policy = session.query(MitigationPolicy).filter_by(policy_version=policy_version).one_or_none()
        if policy is None:
            return 0, 0
        decisions = session.query(DecisionRow).filter_by(policy_id=policy.id).all()
        audits = session.query(MitigationAuditEvent).filter_by(policy_id=policy.id).all()
        decision_uuids = [row.decision_uuid for row in decisions]
        dedupe_keys = [row.dedupe_key for row in decisions]
        assert len(decision_uuids) == len(set(decision_uuids))
        assert len(dedupe_keys) == len(set(dedupe_keys))
        return len(decisions), len(audits)


def test_complete_pipeline_is_visible_and_enforced_only_in_isolation(integration_client):
    client, factory = integration_client
    _seed_traffic(factory)
    _register_advisory_policy(factory)

    # API request -> traffic query -> bot detection -> MW2 signals -> MW1 risk
    # assessment -> Stage A decision persistence, all through real API code.
    runtime = client.get(
        "/api/v1/security/mitigation/runtime-analyze",
        params={
            "client_ip": CLIENT_IP,
            "path": "/login",
            "status_code": 401,
            "brute_force_failure_threshold": 5,
        },
    )
    assert runtime.status_code == 200, runtime.text
    payload = runtime.json()
    assert payload["advisory_only"] is True
    assert payload["enforcement_executed"] is False
    assert payload["detection"]["results"]
    assert payload["runtime_results"]
    first = payload["runtime_results"][0]
    assert first["mw1_status"] == "assessed"
    assert first["mw1_unified_assessment"] is not None
    assert isinstance(first["mw2_advanced_detection"]["signals"], list)
    assert payload["provenance"]["mw1_service"].endswith("assess_risk")
    assert payload["uncertainty"]["mw1_result_statuses"]

    advisory_decisions, _ = _row_counts(factory, V1)
    assert advisory_decisions >= 1

    # Isolated harness: same persisted traffic and policy lifecycle, real request
    # middleware, and BLOCK behavior on the synthetic protected handler.
    status = demo_service.enable(
        demo_id="e2e-isolated",
        policy_version=V2,
        scenario="block",
        client_host=CLIENT_IP,
        target_host=CLIENT_IP,
        max_requests=5,
        max_duration_seconds=300,
        session_factory=factory,
        clock=lambda: FIXED_NOW,
    )
    assert status["enforcement_enabled"] is True
    assert status["production_middleware_registered"] is False
    assert status["real_enforcement"] is False

    run = demo_service.run(demo_id="e2e-isolated", request_count=1, client_host=CLIENT_IP)
    outcome = run["outcomes"][0]
    assert outcome["status_code"] == 403
    assert outcome["enforcement_outcome"] == "blocked"
    assert outcome["handler_reached"] is False
    assert outcome["decision_ref"]

    # Decision/audit persistence with input traceability and no duplicate decision.
    isolated_decisions, isolated_audits = _row_counts(factory, V2)
    assert isolated_decisions == 1
    assert isolated_audits >= 1
    with factory() as session:
        policy = session.query(MitigationPolicy).filter_by(policy_version=V2).one()
        decision = session.query(DecisionRow).filter_by(policy_id=policy.id).one()
        audit = (
            session.query(MitigationAuditEvent)
            .filter_by(policy_id=policy.id, event_type="enforcement_applied_reserved")
            .first()
        )
        assert decision.decision_type.value == "block"
        # The persisted decision table remains advisory-only by accepted schema;
        # actual isolated enforcement is recorded in the audit detail projection.
        assert decision.advisory_only is True
        assert isinstance(decision.evidence_references, list) and decision.evidence_references
        assert audit is not None
        details = dict(audit.details or {})
        assert details["selected_action"] == "block"
        assert details["enforcement_outcome"] == "blocked"
        assert details["advisory_only"] is False

    # Existing dashboard/API surfaces can read the persisted lifecycle rows when
    # scoped to the injected demo database; no new engine is introduced.
    decisions_view = client.get(
        "/api/v1/security/mitigation/decisions", params={"policy_version": V2}
    )
    audits_view = client.get(
        "/api/v1/security/mitigation/audit-events",
        params={"event_type": "enforcement_applied_reserved"},
    )
    assert decisions_view.status_code == 200, decisions_view.text
    assert audits_view.status_code == 200, audits_view.text
    assert decisions_view.json()["total"] >= 1
    assert audits_view.json()["total"] >= 1

    # Kill switch returns the isolated runtime to advisory-only without altering
    # production middleware registration.
    stopped = demo_service.kill_switch(client_host=CLIENT_IP)
    assert stopped["kill_switch_active"] is True
    assert stopped["enforcement_enabled"] is False
    assert stopped["advisory_only"] is True

    after_stop = demo_service.run(
        demo_id="e2e-isolated", request_count=1, client_host=CLIENT_IP
    )["outcomes"][0]
    assert after_stop["status_code"] == 200
    assert after_stop["enforcement_outcome"] == "advisory_allowed"
    assert after_stop["handler_reached"] is True

    cleaned = demo_service.disable(client_host=CLIENT_IP, reason="e2e_complete")
    assert cleaned["demo_enabled"] is False
    assert cleaned["persistence_db"] == "none"
    assert cleaned["production_middleware_registered"] is False


def test_invalid_signal_contract_is_rejected_without_creating_decisions(integration_client):
    client, factory = integration_client
    response = client.get(
        "/api/v1/security/mitigation/runtime-analyze",
        params={"page": 0, "page_size": 200},
    )
    assert response.status_code == 422
    with factory() as session:
        assert session.query(DecisionRow).count() == 0
        assert session.query(MitigationAuditEvent).count() == 0
