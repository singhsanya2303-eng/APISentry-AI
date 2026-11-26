"""Dedicated isolated request-time enforcement demonstration (WP9).

This module is demo-only and default OFF. It never registers production
middleware, never uses the configured database, and never handles real traffic.
It reuses :class:`IsolatedEnforcementRuntime` inside a synthetic loopback
FastAPI application with an injected, demo-owned SQLite session factory.

Gate E remains untouched: this is a separate demonstration of the real
request-time middleware rather than a second synthetic evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.mitigation import (
    MitigationAuditEvent,
    MitigationDecision as MitigationDecisionRow,
)
from app.models.traffic import APITrafficLog
from app.schemas.mitigation import MitigationPolicyConfig, MitigationPolicyMode
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services.bot_detection_service import BotScoringConfig
from app.services.mitigation_policy_lifecycle_persistence_service import (
    persist_lifecycle_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)
from app.services.request_enforcement_service import (
    ISOLATED_HARNESS_ENVIRONMENT,
    IsolatedEnforcementRuntime,
    RequestEnforcementMiddleware,
)

logger = logging.getLogger("apisentry.request_enforcement_demo")

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient", "testserver"})
_HARNESS_HOST = "127.0.0.1"
_DEMO_DB_DIRNAME = "apisentry_request_enforcement_demo"
_SCENARIOS = frozenset({"allow", "block", "throttle"})
_ACTOR = LifecycleActor(
    role=LifecycleRole.ADMIN,
    actor_hash="sha256:" + hashlib.sha256(b"wp9-request-demo-admin").hexdigest(),
)


class RequestDemoGuardError(ValueError):
    """Raised when a demo safety guard rejects an operation."""


@dataclass
class RequestDemoState:
    enabled: bool = False
    demo_id: str | None = None
    scenario: str | None = None
    policy_version: str | None = None
    max_requests: int = 12
    max_duration_seconds: int = 300
    started_at: datetime | None = None
    runtime: IsolatedEnforcementRuntime | None = None
    lifecycle: MitigationPolicyLifecycleService | None = None
    session_factory: Callable[[], Session] | None = None
    engine: Any = None
    db_path: str | None = None
    app: FastAPI | None = None
    client: TestClient | None = None


_state = RequestDemoState()
_lock = threading.RLock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.strip().lower()
    if normalized.startswith("[") and "]" in normalized:
        normalized = normalized[1 : normalized.index("]")]
    if ":" in normalized and normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]
    return normalized in _LOOPBACK_HOSTS


def _require_loopback(client_host: str | None, target_host: str | None = None) -> None:
    if not _is_loopback(client_host):
        raise RequestDemoGuardError("demo requests must originate from loopback")
    if target_host is not None and not _is_loopback(target_host):
        raise RequestDemoGuardError("demo target must be loopback")


def _resolve_db_path(demo_id: str) -> Path:
    root = Path(tempfile.gettempdir()).resolve()
    directory = (root / _DEMO_DB_DIRNAME).resolve()
    if directory != root and root not in directory.parents:
        raise RequestDemoGuardError("demo database directory must be under system temp")
    safe_id = "".join(ch for ch in demo_id if ch.isalnum() or ch in "-_")[:48] or "demo"
    candidate = (directory / f"request_enforcement_{safe_id}.sqlite3").resolve()
    if directory not in candidate.parents:
        raise RequestDemoGuardError("demo database path escaped the demo directory")
    return candidate


def _make_factory(db_path: Path) -> tuple[Any, Callable[[], Session]]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=engine)
    return engine, sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _policy_config(*, version: str, scenario: str) -> MitigationPolicyConfig:
    return MitigationPolicyConfig(
        enabled=True,
        mode=MitigationPolicyMode.ENFORCE,
        policy_version=version,
        monitoring_score_threshold=25.0,
        throttling_score_threshold=75.0,
        blocking_score_threshold=90.0,
        minimum_authentication_failures=5,
        require_grouped_brute_force=True,
        throttle_enabled=scenario == "throttle",
        throttle_limit=2,
        throttle_window_seconds=60,
        throttle_duration_seconds=300,
        block_enabled=scenario == "block",
        block_duration_seconds=900,
        max_block_duration_seconds=3600,
    )


def _register_active_policy(
    factory: Callable[[], Session],
    lifecycle: MitigationPolicyLifecycleService,
    config: MitigationPolicyConfig,
    now: datetime,
) -> None:
    proposed = lifecycle.propose_policy(
        actor=_ACTOR, config=config, created_at=now - timedelta(minutes=5)
    )
    if not proposed.ok:
        raise RequestDemoGuardError("demo policy proposal failed")
    validated = lifecycle.validate_policy(
        actor=_ACTOR, version=config.policy_version, at=now - timedelta(minutes=4)
    )
    if not validated.ok:
        raise RequestDemoGuardError("demo policy validation failed")
    activated = lifecycle.activate_policy(
        actor=_ACTOR, version=config.policy_version, at=now - timedelta(minutes=3)
    )
    if not activated.ok:
        raise RequestDemoGuardError("demo policy activation failed")
    with factory() as session:
        persisted = persist_lifecycle_result(session, activated, actor=_ACTOR, at=now)
        session.commit()
    if not persisted.ok:
        raise RequestDemoGuardError("demo policy persistence failed")


def _seed_auth_failures(
    factory: Callable[[], Session], now: datetime, count: int
) -> None:
    if count <= 0:
        return
    with factory() as session:
        for index in range(count):
            session.add(
                APITrafficLog(
                    request_id=f"wp9-demo-auth-{index}-{uuid.uuid4().hex[:8]}",
                    timestamp=now - timedelta(seconds=30 - index),
                    method="POST",
                    path="/login",
                    query_params={},
                    client_ip=_HARNESS_HOST,
                    user_agent="APISentryRequestDemo/1.0",
                    status_code=401,
                    response_time_ms=1.0,
                    actor_id=str(_ACTOR.actor_hash),
                )
            )
        session.commit()


def _build_synthetic_app(runtime: IsolatedEnforcementRuntime) -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.state.handler_calls = 0

    @app.get("/protected")
    async def protected() -> dict[str, str]:
        app.state.handler_calls += 1
        return {"detail": "isolated demo handler reached"}

    app.add_middleware(RequestEnforcementMiddleware, runtime=runtime)
    client = TestClient(app, base_url=f"http://{_HARNESS_HOST}", client=(_HARNESS_HOST, 54321))
    return app, client


def _counts(factory: Callable[[], Session] | None) -> tuple[int, int]:
    if factory is None:
        return 0, 0
    try:
        with factory() as session:
            decisions = int(session.query(MitigationDecisionRow).count())
            audits = int(session.query(MitigationAuditEvent).count())
            return decisions, audits
    except Exception:
        logger.warning("demo evidence counts unavailable", exc_info=True)
        return 0, 0


class _FailingSessionFactory:
    """A demo-only factory that starts healthy and then simulates outage."""

    def __init__(self, factory: Callable[[], Session]) -> None:
        self._factory = factory
        self._fail = False

    def __call__(self) -> Session:
        if self._fail:
            raise RuntimeError("simulated enforcement dependency outage")
        return self._factory()

    def break_dependency(self) -> None:
        self._fail = True


def get_status() -> dict[str, Any]:
    with _lock:
        runtime_status = _state.runtime.status() if _state.runtime is not None else {
            "mode": "disabled",
            "enforcement_enabled": False,
            "kill_switch_active": False,
            "request_count": 0,
        }
        enforcement_enabled = bool(_state.enabled and runtime_status["enforcement_enabled"])
        decisions, audits = _counts(_state.session_factory)
        persistence = "injected-isolated" if _state.db_path is None and _state.enabled else (
            "isolated-temp-sqlite" if _state.db_path else "none"
        )
        if not _state.enabled:
            reason = "disabled"
        elif runtime_status["kill_switch_active"]:
            reason = "kill_switch_active"
        elif enforcement_enabled:
            reason = "active_isolated_enforcement"
        else:
            reason = "advisory_only"
        return {
            "demo_enabled": _state.enabled,
            "enforcement_enabled": enforcement_enabled,
            "advisory_only": not enforcement_enabled,
            "kill_switch_active": bool(runtime_status["kill_switch_active"]),
            "loopback_only": True,
            "synthetic_only": True,
            "production_middleware_registered": False,
            "real_enforcement": False,
            "demo_id": _state.demo_id,
            "scenario": _state.scenario,
            "policy_version": _state.policy_version,
            "max_requests": _state.max_requests,
            "requests_executed": int(runtime_status["request_count"]),
            "started_at": _state.started_at,
            "decision_count": decisions,
            "audit_event_count": audits,
            "persistence_db": persistence,
            "status_reason": reason,
            "guards": {
                "default_off": True,
                "explicit_confirmation_required": True,
                "loopback_required": True,
                "synthetic_required": True,
                "isolated_db_required": True,
                "production_middleware_registered": False,
                "real_enforcement": False,
            },
        }


def enable(
    *,
    demo_id: str,
    policy_version: str,
    scenario: str,
    client_host: str | None,
    target_host: str | None,
    max_requests: int,
    max_duration_seconds: int,
    session_factory: Callable[[], Session] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Enable an isolated demo runtime; never activates production enforcement."""
    _require_loopback(client_host, target_host)
    if scenario not in _SCENARIOS:
        raise RequestDemoGuardError("unsupported demo scenario")
    if max_requests < 1 or max_duration_seconds < 1:
        raise RequestDemoGuardError("invalid demo limits")

    with _lock:
        if _state.enabled:
            raise RequestDemoGuardError("demo is already enabled")
        engine: Any = None
        db_path: str | None = None
        if session_factory is None:
            path = _resolve_db_path(demo_id)
            engine, session_factory = _make_factory(path)
            db_path = str(path)

        now = (clock or _now)()
        lifecycle = MitigationPolicyLifecycleService()
        config = _policy_config(version=policy_version, scenario=scenario)
        client: TestClient | None = None
        app: FastAPI | None = None
        try:
            _register_active_policy(session_factory, lifecycle, config, now)
            _seed_auth_failures(
                session_factory, now, 5 if scenario in {"block", "throttle"} else 0
            )
            runtime = IsolatedEnforcementRuntime()
            runtime.enable(
                environment=ISOLATED_HARNESS_ENVIRONMENT,
                client_host=_HARNESS_HOST,
                target_host=_HARNESS_HOST,
                session_factory=session_factory,
                lifecycle=lifecycle,
                actor=_ACTOR,
                policy_version=policy_version,
                isolated_environment_confirmation=True,
                clock=clock,
                scoring_config=BotScoringConfig(brute_force_weight=95.0),
                max_requests=max_requests,
                max_duration_seconds=max_duration_seconds,
            )
            app, client = _build_synthetic_app(runtime)
        except Exception:
            if client is not None:
                client.close()
            if engine is not None:
                engine.dispose()
            if db_path:
                Path(db_path).unlink(missing_ok=True)
            raise

        _state.enabled = True
        _state.demo_id = demo_id
        _state.scenario = scenario
        _state.policy_version = policy_version
        _state.max_requests = max_requests
        _state.max_duration_seconds = max_duration_seconds
        _state.started_at = now
        _state.runtime = runtime
        _state.lifecycle = lifecycle
        _state.session_factory = session_factory
        _state.engine = engine
        _state.db_path = db_path
        _state.app = app
        _state.client = client
        return get_status()


def run(
    *, demo_id: str, request_count: int, client_host: str | None
) -> dict[str, Any]:
    """Send bounded synthetic requests through the isolated middleware."""
    _require_loopback(client_host)
    with _lock:
        if not _state.enabled or _state.demo_id != demo_id:
            raise RequestDemoGuardError("no matching enabled demo")
        if _state.client is None or _state.app is None or _state.runtime is None:
            raise RequestDemoGuardError("demo harness is unavailable")
        client = _state.client
        app = _state.app
        scenario = str(_state.scenario)
        outcomes: list[dict[str, Any]] = []
        for index in range(request_count):
            before = int(app.state.handler_calls)
            response = client.get(
                "/protected",
                params={"probe": f"wp9-{index}-{uuid.uuid4().hex[:8]}"},
            )
            body: dict[str, Any] = {}
            if response.headers.get("content-type", "").startswith("application/json"):
                body = response.json()
            outcomes.append(
                {
                    "status_code": int(response.status_code),
                    "enforcement_action": response.headers.get("X-Enforcement-Action"),
                    "enforcement_outcome": response.headers.get("X-Enforcement-Outcome"),
                    "handler_reached": int(app.state.handler_calls) > before,
                    "decision_ref": body.get("decision_ref"),
                    "request_ref": body.get("request_ref"),
                }
            )
        return {
            "demo_id": demo_id,
            "scenario": scenario,
            "outcomes": outcomes,
            "status": get_status(),
        }


def kill_switch(*, client_host: str | None) -> dict[str, Any]:
    """Return the isolated runtime to advisory-only mode immediately."""
    _require_loopback(client_host)
    with _lock:
        if not _state.enabled or _state.runtime is None:
            raise RequestDemoGuardError("no enabled demo to stop")
        _state.runtime.kill_switch()
        return get_status()


def fail_closed(*, client_host: str | None) -> dict[str, Any]:
    """Demonstrate a dependency outage with a separate bound runtime."""
    _require_loopback(client_host)
    with _lock:
        if not _state.enabled or _state.runtime is None or _state.session_factory is None:
            raise RequestDemoGuardError("no enabled demo harness")
        if _state.lifecycle is None or _state.policy_version is None:
            raise RequestDemoGuardError("demo policy is unavailable")

        wrapped = _FailingSessionFactory(_state.session_factory)
        outage_runtime = IsolatedEnforcementRuntime()
        outage_runtime.enable(
            environment=ISOLATED_HARNESS_ENVIRONMENT,
            client_host=_HARNESS_HOST,
            target_host=_HARNESS_HOST,
            session_factory=wrapped,
            lifecycle=_state.lifecycle,
            actor=_ACTOR,
            policy_version=_state.policy_version,
            isolated_environment_confirmation=True,
            clock=None,
            max_requests=2,
            max_duration_seconds=60,
        )
        wrapped.break_dependency()
        app, client = _build_synthetic_app(outage_runtime)
        try:
            before = int(app.state.handler_calls)
            response = client.get("/protected")
            body = response.json()
            return {
                "status_code": int(response.status_code),
                "detail": str(body.get("detail", "")),
                "enforcement_outcome": response.headers.get("X-Enforcement-Outcome"),
                "handler_reached": int(app.state.handler_calls) > before,
                "real_enforcement": False,
                "production_middleware_registered": False,
            }
        finally:
            client.close()
            outage_runtime.disable()


def evidence(*, client_host: str | None) -> dict[str, Any]:
    """Return bounded, non-sensitive views of persisted demo decisions/audits."""
    _require_loopback(client_host)
    with _lock:
        factory = _state.session_factory
        if factory is None:
            return {
                "decision_count": 0,
                "audit_event_count": 0,
                "decisions": [],
                "audit_events": [],
            }
        with factory() as session:
            decision_count = int(session.query(MitigationDecisionRow).count())
            audit_event_count = int(session.query(MitigationAuditEvent).count())
            decisions = [
                {
                    "decision_uuid": row.decision_uuid,
                    "decision_type": row.decision_type,
                    "issued_at": row.issued_at,
                    "advisory_only": row.advisory_only,
                }
                for row in session.query(MitigationDecisionRow)
                .order_by(MitigationDecisionRow.id.desc())
                .limit(20)
                .all()
            ]
            audits = [
                {
                    "event_uuid": row.event_uuid,
                    "event_type": row.event_type.value,
                    "created_at": row.created_at,
                    "details": {
                        key: value
                        for key, value in dict(row.details or {}).items()
                        if key
                        in {
                            "decision_ref",
                            "selected_action",
                            "enforcement_outcome",
                            "advisory_only",
                            "risk_score",
                            "risk_severity",
                            "risk_coverage_ratio",
                            "mw1_status",
                            "mw2_signal_count",
                            "mw2_high_severity_count",
                        }
                    },
                }
                for row in session.query(MitigationAuditEvent)
                .order_by(MitigationAuditEvent.id.desc())
                .limit(20)
                .all()
            ]
        return {
            "decision_count": decision_count,
            "audit_event_count": audit_event_count,
            "decisions": decisions,
            "audit_events": audits,
        }


def disable(*, client_host: str | None, reason: str) -> dict[str, Any]:
    """Disable the demo, close its client and dispose its isolated database."""
    del reason  # Accepted for parity with Gate E; not persisted or exposed.
    _require_loopback(client_host)
    with _lock:
        if _state.runtime is not None:
            _state.runtime.disable()
        if _state.client is not None:
            _state.client.close()
        if _state.engine is not None:
            _state.engine.dispose()
        if _state.db_path:
            Path(_state.db_path).unlink(missing_ok=True)

        _state.enabled = False
        _state.demo_id = None
        _state.scenario = None
        _state.policy_version = None
        _state.max_requests = 12
        _state.max_duration_seconds = 300
        _state.started_at = None
        _state.runtime = None
        _state.lifecycle = None
        _state.session_factory = None
        _state.engine = None
        _state.db_path = None
        _state.app = None
        _state.client = None
        return get_status()


def reset_for_tests() -> None:
    """Best-effort cleanup for isolated tests; never touches production state."""
    try:
        disable(client_host=_HARNESS_HOST, reason="test_reset")
    except RequestDemoGuardError:
        pass
