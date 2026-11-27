"""Isolated request-time enforcement harness.

Every test uses an in-memory SQLite database, a synthetic FastAPI application and
a loopback TestClient. Production middleware is never activated and no configured
database, Docker service or real traffic is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.mitigation import (
    ALLOWED_AUDIT_DETAIL_KEYS,
    MitigationAuditEvent,
    MitigationAuditEventType,
    MitigationDecision as MitigationDecisionRow,
)
from app.models.traffic import APITrafficLog
from app.schemas.mitigation import (
    MitigationPolicyConfig,
    MitigationPolicyMode,
    MitigationRequestContext,
    MitigationAttributionStatus,
)
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services.bot_detection_service import (
    BotScoringConfig,
    analyze_traffic_for_bot_detection,
)
from app.services.mitigation_policy_lifecycle_persistence_service import (
    persist_lifecycle_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)
from app.services.request_enforcement_service import (
    ISOLATED_HARNESS_ENVIRONMENT,
    EnforcementGuardError,
    IsolatedEnforcementRuntime,
    RequestEnforcementMiddleware,
)
from app.services.unified_risk_assessment_service import assess_risk, from_bot_detection_response

FIXED_NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
ACTOR_HASH = "sha256:" + "a" * 64
CLIENT_IP = "127.0.0.1"
VERSION = "request-enforce-1.0.0"


@dataclass
class Harness:
    app: FastAPI
    client: TestClient
    runtime: IsolatedEnforcementRuntime
    session_factory: Callable[[], Session]
    lifecycle: MitigationPolicyLifecycleService
    actor: LifecycleActor
    version: str

    @property
    def handler_calls(self) -> int:
        return int(self.app.state.handler_calls)


def _session_factory() -> Callable[[], Session]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _register_active_policy(
    factory: Callable[[], Session],
    lifecycle: MitigationPolicyLifecycleService,
    actor: LifecycleActor,
    config: MitigationPolicyConfig,
) -> None:
    proposed = lifecycle.propose_policy(
        actor=actor, config=config, created_at=FIXED_NOW - timedelta(minutes=5)
    )
    assert proposed.ok, proposed.error
    validated = lifecycle.validate_policy(
        actor=actor,
        version=config.policy_version,
        at=FIXED_NOW - timedelta(minutes=4),
    )
    assert validated.ok, validated.error
    activated = lifecycle.activate_policy(
        actor=actor,
        version=config.policy_version,
        at=FIXED_NOW - timedelta(minutes=3),
    )
    assert activated.ok, activated.error
    with factory() as session:
        persisted = persist_lifecycle_result(session, activated, actor=actor, at=FIXED_NOW)
        session.commit()
    assert persisted.ok, persisted.error


def _seed_auth_failures(
    factory: Callable[[], Session], count: int, actor_hash: str = ACTOR_HASH
) -> None:
    with factory() as session:
        for index in range(count):
            session.add(
                APITrafficLog(
                    request_id=f"synthetic-auth-{index}",
                    timestamp=FIXED_NOW - timedelta(seconds=30 - index),
                    method="POST",
                    path="/login",
                    query_params={},
                    client_ip=CLIENT_IP,
                    user_agent="synthetic-agent",
                    status_code=401,
                    response_time_ms=1.0,
                    actor_id=actor_hash,
                )
            )
        session.commit()


def _policy_config(
    *, version: str, block: bool, throttle: bool, limit: int = 2
) -> MitigationPolicyConfig:
    return MitigationPolicyConfig(
        enabled=True,
        mode=MitigationPolicyMode.ENFORCE,
        policy_version=version,
        monitoring_score_threshold=25.0,
        throttling_score_threshold=75.0,
        blocking_score_threshold=90.0,
        minimum_authentication_failures=5,
        require_grouped_brute_force=True,
        throttle_enabled=throttle,
        throttle_limit=limit,
        throttle_window_seconds=60,
        throttle_duration_seconds=300,
        block_enabled=block,
        block_duration_seconds=900,
        max_block_duration_seconds=3600,
    )


def _build_harness(
    *,
    version: str = VERSION,
    block: bool = True,
    throttle: bool = False,
    limit: int = 2,
    auth_failures: int = 5,
    enabled: bool = True,
    detector: Callable[..., Any] | None = None,
    audit_sink: Callable[..., Any] | None = None,
    max_requests: int = 50,
) -> Harness:
    factory = _session_factory()
    lifecycle = MitigationPolicyLifecycleService()
    actor = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash=ACTOR_HASH)
    config = _policy_config(version=version, block=block, throttle=throttle, limit=limit)
    _register_active_policy(factory, lifecycle, actor, config)
    if auth_failures:
        _seed_auth_failures(factory, auth_failures)

    runtime = IsolatedEnforcementRuntime()
    if enabled:
        runtime.enable(
            environment=ISOLATED_HARNESS_ENVIRONMENT,
            client_host=CLIENT_IP,
            target_host=CLIENT_IP,
            session_factory=factory,
            lifecycle=lifecycle,
            actor=actor,
            policy_version=version,
            isolated_environment_confirmation=True,
            detector=detector,
            audit_sink=audit_sink,
            clock=lambda: FIXED_NOW,
            scoring_config=BotScoringConfig(brute_force_weight=95.0),
            max_requests=max_requests,
            max_duration_seconds=300,
        )

    app = FastAPI()
    app.state.handler_calls = 0
    app.state.runtime = runtime

    @app.get("/protected")
    async def protected() -> dict[str, str]:
        app.state.handler_calls += 1
        return {"detail": "protected handler reached"}

    app.add_middleware(RequestEnforcementMiddleware, runtime=runtime)
    client = TestClient(app, base_url=f"http://{CLIENT_IP}", client=(CLIENT_IP, 54321))
    return Harness(app, client, runtime, factory, lifecycle, actor, version)


def _audit_rows(factory: Callable[[], Session]) -> list[dict[str, Any]]:
    with factory() as session:
        rows = (
            session.query(MitigationAuditEvent)
            .order_by(MitigationAuditEvent.id.asc())
            .all()
        )
        return [
            {
                "event_type": row.event_type.value,
                "entity_identifier": row.entity_identifier,
                "details": dict(row.details or {}),
                "created_at": row.created_at,
            }
            for row in rows
        ]


def _decision_rows(factory: Callable[[], Session]) -> list[dict[str, Any]]:
    with factory() as session:
        rows = session.query(MitigationDecisionRow).all()
        return [
            {
                "decision_type": row.decision_type.value,
                "policy_id": row.policy_id,
                "advisory_only": bool(row.advisory_only),
            }
            for row in rows
        ]


def _traffic_rows(factory: Callable[[], Session]) -> list[APITrafficLog]:
    with factory() as session:
        rows = session.query(APITrafficLog).all()
        return [
            APITrafficLog(
                request_id=row.request_id,
                method=row.method,
                path=row.path,
                query_params=dict(row.query_params),
                client_ip=row.client_ip,
                user_agent=row.user_agent,
                status_code=row.status_code,
                response_time_ms=row.response_time_ms,
                actor_id=row.actor_id,
            )
            for row in rows
        ]


def test_production_app_has_no_request_enforcement_middleware() -> None:
    from app.main import app as production_app

    middleware_classes = [middleware.cls for middleware in production_app.user_middleware]
    assert RequestEnforcementMiddleware not in middleware_classes


def test_enable_requires_explicit_isolated_confirmation_and_loopback() -> None:
    factory = _session_factory()
    lifecycle = MitigationPolicyLifecycleService()
    actor = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash=ACTOR_HASH)
    _register_active_policy(
        factory, lifecycle, actor, _policy_config(version="guard-check", block=True, throttle=False)
    )
    runtime = IsolatedEnforcementRuntime()

    with pytest.raises(EnforcementGuardError):
        runtime.enable(
            environment=ISOLATED_HARNESS_ENVIRONMENT,
            client_host=CLIENT_IP,
            target_host=CLIENT_IP,
            session_factory=factory,
            lifecycle=lifecycle,
            actor=actor,
            policy_version="guard-check",
        )

    with pytest.raises(EnforcementGuardError):
        runtime.enable(
            environment=ISOLATED_HARNESS_ENVIRONMENT,
            client_host="203.0.113.10",
            target_host=CLIENT_IP,
            session_factory=factory,
            lifecycle=lifecycle,
            actor=actor,
            policy_version="guard-check",
            isolated_environment_confirmation=True,
        )

    assert runtime.status()["mode"] == "disabled"
    assert runtime.status()["enforcement_enabled"] is False


def test_a_block_prevents_handler_and_records_decision_and_audit() -> None:
    harness = _build_harness(version="req-block", block=True)

    response = harness.client.get(
        "/protected", params={"token": "sensitive-query-value"}
    )

    assert response.status_code == 403
    assert harness.handler_calls == 0
    body = response.json()
    assert body["request_ref"]

    enforcement_events = [
        row
        for row in _audit_rows(harness.session_factory)
        if row["event_type"] == "enforcement_applied_reserved"
    ]
    assert len(enforcement_events) == 1
    details = enforcement_events[0]["details"]
    assert details["request_ref"] == body["request_ref"]
    assert uuid.UUID(details["risk_assessment_ref"]).version == 5
    assert details["policy_version"] == "req-block"
    assert details["selected_action"] == "block"
    assert details["enforcement_outcome"] == "blocked"
    assert details["enforced_at"] == FIXED_NOW.isoformat()
    assert "sensitive-query-value" not in str(details)

    decisions = _decision_rows(harness.session_factory)
    assert any(
        decision["decision_type"] == "block" and decision["advisory_only"]
        for decision in decisions
    )
    traffic = _traffic_rows(harness.session_factory)
    assert any(row.query_params.get("token") == "***MASKED***" for row in traffic)


def test_b_throttle_enforces_limit_and_window() -> None:
    harness = _build_harness(
        version="req-throttle", block=False, throttle=True, limit=2
    )

    responses = [harness.client.get("/protected") for _ in range(3)]

    assert [response.status_code for response in responses] == [200, 200, 429]
    assert harness.handler_calls == 2
    assert responses[2].headers["Retry-After"].isdigit()

    events = [
        row
        for row in _audit_rows(harness.session_factory)
        if row["event_type"] == "enforcement_applied_reserved"
    ]
    assert [row["details"]["enforcement_outcome"] for row in events] == [
        "throttle_permitted",
        "throttle_permitted",
        "throttled",
    ]
    assert all(row["details"]["selected_action"] == "throttle" for row in events)
    assert all(
        decision["decision_type"] == "throttle"
        for decision in _decision_rows(harness.session_factory)
    )


def test_c_allow_preserves_normal_processing_and_records_result() -> None:
    harness = _build_harness(version="req-allow", block=True, auth_failures=0)

    response = harness.client.get("/protected")

    assert response.status_code == 200
    assert response.json()["detail"] == "protected handler reached"
    assert harness.handler_calls == 1

    events = [
        row
        for row in _audit_rows(harness.session_factory)
        if row["event_type"] == "enforcement_applied_reserved"
    ]
    assert len(events) == 1
    assert events[0]["details"]["selected_action"] in {"allow", "monitor"}
    assert events[0]["details"]["enforcement_outcome"] == "allowed"
    assert events[0]["details"]["advisory_only"] is False


def test_d_disabled_mode_is_pass_through_and_advisory_pipeline_remains_available() -> None:
    harness = _build_harness(version="req-disabled", block=True, enabled=False)

    response = harness.client.get("/protected")

    assert response.status_code == 200
    assert harness.handler_calls == 1
    assert not [
        row
        for row in _audit_rows(harness.session_factory)
        if row["event_type"] == "enforcement_applied_reserved"
    ]

    with harness.session_factory() as session:
        detection_response = analyze_traffic_for_bot_detection(
            client_ip=CLIENT_IP,
            db=session,
            scoring_config=BotScoringConfig(brute_force_weight=95.0),
        )
        context = MitigationRequestContext(
            evaluated_at=FIXED_NOW,
            attribution_status=MitigationAttributionStatus.VERIFIED_USER,
            actor_key_hash=ACTOR_HASH,
        )
        evaluation = harness.lifecycle.evaluate_policy(
            actor=harness.actor,
            version=harness.version,
            at=FIXED_NOW,
            detection_result=detection_response.results[0],
            context=context,
            risk_assessment=assess_risk(
                {"bot_detection": from_bot_detection_response(detection_response)}
            ),
            dry_run=True,
        )

    assert evaluation.ok, evaluation.error
    assert evaluation.decision is not None
    assert evaluation.decision.decision.decision is not None
    assert evaluation.decision.decision.advisory_only is True


def test_e_kill_switch_stops_enforcement_without_stale_active_state() -> None:
    harness = _build_harness(version="req-kill", block=True)

    blocked = harness.client.get("/protected")
    assert blocked.status_code == 403
    assert harness.handler_calls == 0

    state = harness.runtime.kill_switch()
    assert state["mode"] == "advisory"
    assert state["enforcement_enabled"] is False
    assert state["kill_switch_active"] is True
    assert state["active_enforcement_version"] is None
    assert state["throttle_buckets"] == 0

    allowed = harness.client.get("/protected")
    assert allowed.status_code == 200
    assert harness.handler_calls == 1

    events = _audit_rows(harness.session_factory)
    assert any(
        row["event_type"] == "enforcement_removed_reserved"
        and row["details"]["enforcement_outcome"] == "advisory_only"
        for row in events
    )
    advisory = [
        row
        for row in events
        if row["event_type"] == "enforcement_applied_reserved"
        and row["details"]["enforcement_outcome"] == "advisory_allowed"
    ]
    assert len(advisory) == 1
    assert advisory[0]["details"]["advisory_only"] is True


def test_f_detector_policy_and_audit_failures_fail_closed() -> None:
    def failing_detector(**kwargs: Any) -> Any:
        raise RuntimeError("simulated detector failure")

    def failing_audit_sink(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated audit failure")

    detector_harness = _build_harness(
        version="fail-detector", block=True, detector=failing_detector
    )
    detector_response = detector_harness.client.get("/protected")
    assert detector_response.status_code == 503
    assert detector_harness.handler_calls == 0
    assert detector_response.headers["X-Enforcement-Outcome"] == "fail_closed"

    audit_harness = _build_harness(
        version="fail-audit", block=True, audit_sink=failing_audit_sink
    )
    audit_response = audit_harness.client.get("/protected")
    assert audit_response.status_code == 503
    assert audit_harness.handler_calls == 0
    assert audit_response.headers["X-Enforcement-Outcome"] == "fail_closed"

    policy_harness = _build_harness(version="fail-policy", block=True)

    def failing_evaluate(**kwargs: Any) -> Any:
        raise RuntimeError("simulated policy lookup failure")

    policy_harness.lifecycle.evaluate_policy = failing_evaluate  # type: ignore[method-assign]
    policy_response = policy_harness.client.get("/protected")
    assert policy_response.status_code == 503
    assert policy_harness.handler_calls == 0
    assert policy_response.headers["X-Enforcement-Outcome"] == "fail_closed"


def _enforcement_events(factory: Callable[[], Session]) -> list[dict[str, Any]]:
    return [
        row
        for row in _audit_rows(factory)
        if row["event_type"] == "enforcement_applied_reserved"
    ]


def test_g_risk_attribution_is_allowlisted_and_dashboard_readable(monkeypatch: Any) -> None:
    harness = _build_harness(version="req-risk", block=True)
    response = harness.client.get("/protected")
    assert response.status_code == 403

    events = _enforcement_events(harness.session_factory)
    assert len(events) == 1
    details = events[0]["details"]
    assert set(details).issubset(ALLOWED_AUDIT_DETAIL_KEYS)
    assert isinstance(details["risk_score"], float)
    assert details["risk_severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0.0 <= details["risk_coverage_ratio"] <= 1.0
    assert details["mw1_status"] == "assessed"
    assert isinstance(details["mw2_signal_count"], int)
    assert isinstance(details["mw2_high_severity_count"], int)

    # The same persisted rows are returned by the existing dashboard history
    # endpoints; no separate mock store or fabricated metric is introduced.
    from app.core.security import require_analyst
    from app.db.session import get_db
    from app.main import app as production_app

    monkeypatch.setattr("app.utils.middleware.save_traffic_log", lambda *a, **k: None)

    def _db_override() -> Any:
        session = harness.session_factory()
        try:
            yield session
        finally:
            session.close()

    production_app.dependency_overrides[get_db] = _db_override
    production_app.dependency_overrides[require_analyst] = lambda: {
        "role": "analyst",
        "actor_id": "test-analyst",
    }
    try:
        with TestClient(production_app, base_url=f"http://{CLIENT_IP}") as dashboard:
            decisions = dashboard.get(
                "/api/v1/security/mitigation/decisions",
                params={"policy_version": harness.version},
            )
            audits = dashboard.get(
                "/api/v1/security/mitigation/audit-events",
                params={"event_type": "enforcement_applied_reserved"},
            )
    finally:
        production_app.dependency_overrides.pop(get_db, None)
        production_app.dependency_overrides.pop(require_analyst, None)

    assert decisions.status_code == 200, decisions.text
    assert audits.status_code == 200, audits.text
    decision_body = decisions.json()
    audit_body = audits.json()
    assert decision_body["total"] >= 1
    assert audit_body["total"] >= 1
    assert any(
        item["decision_uuid"] == details["decision_ref"]
        for item in decision_body["items"]
    )
    assert any(
        item["event_uuid"] == events[0]["entity_identifier"]
        or item["event_type"] == "enforcement_applied_reserved"
        for item in audit_body["items"]
    )


def test_h_bounded_processing_falls_back_to_advisory_and_records_removal() -> None:
    harness = _build_harness(
        version="req-bound", block=True, auth_failures=5, max_requests=1
    )

    first = harness.client.get("/protected")
    second = harness.client.get("/protected")

    assert first.status_code == 403
    assert second.status_code == 200
    assert harness.handler_calls == 1
    assert second.headers["X-Enforcement-Outcome"] == "advisory_allowed"

    state = harness.runtime.status()
    assert state["mode"] == "advisory"
    assert state["kill_switch_active"] is True
    assert state["active_enforcement_version"] is None

    events = _audit_rows(harness.session_factory)
    assert any(
        row["event_type"] == "enforcement_removed_reserved"
        and row["details"]["selected_action"] == "bounded_limit"
        and row["details"]["enforcement_outcome"] == "advisory_only"
        for row in events
    )
    applied = _enforcement_events(harness.session_factory)
    assert [row["details"]["advisory_only"] for row in applied] == [False, True]


def test_i_restart_restores_throttle_bucket_without_duplicate_decisions() -> None:
    harness = _build_harness(
        version="req-restart", block=False, throttle=True, limit=2, auth_failures=5
    )

    first_two = [harness.client.get("/protected") for _ in range(2)]
    assert [response.status_code for response in first_two] == [200, 200]
    assert harness.handler_calls == 2

    restarted_lifecycle = MitigationPolicyLifecycleService()
    with harness.session_factory() as session:
        hydration = restarted_lifecycle.hydrate_from_persistence(session)
    assert hydration["ok"] is True
    assert hydration["persisted_active_version"] == harness.version
    restarted_runtime = IsolatedEnforcementRuntime()
    restarted_runtime.enable(
        environment=ISOLATED_HARNESS_ENVIRONMENT,
        client_host=CLIENT_IP,
        target_host=CLIENT_IP,
        session_factory=harness.session_factory,
        lifecycle=restarted_lifecycle,
        actor=harness.actor,
        policy_version=harness.version,
        isolated_environment_confirmation=True,
        clock=lambda: FIXED_NOW,
        scoring_config=BotScoringConfig(brute_force_weight=95.0),
        max_requests=50,
        max_duration_seconds=300,
    )
    restarted_state = restarted_runtime.status()
    assert restarted_state["mode"] == "enforcing"
    assert restarted_state["throttle_buckets"] >= 1

    restarted_app = FastAPI()
    restarted_app.state.handler_calls = 0

    @restarted_app.get("/protected")
    async def restarted_protected() -> dict[str, str]:
        restarted_app.state.handler_calls += 1
        return {"detail": "protected handler reached"}

    restarted_app.add_middleware(
        RequestEnforcementMiddleware, runtime=restarted_runtime
    )
    restarted_client = TestClient(
        restarted_app, base_url=f"http://{CLIENT_IP}", client=(CLIENT_IP, 54321)
    )
    third = restarted_client.get("/protected")

    assert third.status_code == 429
    assert restarted_app.state.handler_calls == 0
    assert third.headers["X-Enforcement-Outcome"] == "throttled"

    events = _enforcement_events(harness.session_factory)
    assert [row["details"]["enforcement_outcome"] for row in events] == [
        "throttle_permitted",
        "throttle_permitted",
        "throttled",
    ]
    decision_refs = [row["details"]["decision_ref"] for row in events]
    assert len(decision_refs) == len(set(decision_refs))
    assert all(row["details"]["selected_action"] == "throttle" for row in events)

    decision_rows = _decision_rows(harness.session_factory)
    assert len(decision_rows) == len(decision_refs)
    assert all(
        decision["decision_type"] == "throttle" for decision in decision_rows
    )
