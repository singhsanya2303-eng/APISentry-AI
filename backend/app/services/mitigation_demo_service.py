"""Gate E isolated local enforcement demonstration service.

This module is demo-only. It never enables production enforcement, never touches
preserved PostgreSQL databases, and only operates on loopback synthetic requests.
All state is in-memory and defaults to OFF.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import logging
import tempfile
import threading
import uuid
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.mitigation import (  # noqa: F401 - ensure metadata registration
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
    MitigationPolicyState,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationPolicyConfig,
    MitigationRequestContext,
    MitigationScopeType,
)
from app.schemas.mitigation_policy_lifecycle import (
    LifecycleActor,
    LifecycleRole,
    PolicyEvaluationResult,
    PolicyLifecycleState,
)
from app.schemas.bot_detection import (
    BotAnalysisResult,
    BotClassification,
    BotReason,
    BotReasonCategory,
    BotReasonSeverity,
)
from app.services.mitigation_policy_lifecycle_persistence_service import (
    persist_evaluation_result,
)
from app.core.config import settings
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)

logger = logging.getLogger("apisentry.demo.enforcement")

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}
_DEFAULT_DEMO_DB_DIRNAME = "apisentry_mitigation_demo"
_DEMO_ACTOR = LifecycleActor(
    role=LifecycleRole.ADMIN,
    actor_hash="sha256:" + hashlib.sha256(b"gate-e-demo-admin").hexdigest(),
)


def _allowed_demo_temp_root() -> Path:
    return Path(tempfile.gettempdir()).resolve()


def resolve_demo_db_dir() -> Path:
    """Resolve the demo SQLite directory to a safe temp-contained path.

    Default: <system-temp>/apisentry_mitigation_demo. A configured
    MITIGATION_DEMO_DB_DIR must be absolute or relative-safe and resolves under
    the system temp directory; arbitrary filesystem writes are rejected.
    """
    configured = str(getattr(settings, "MITIGATION_DEMO_DB_DIR", "") or "").strip()
    root = _allowed_demo_temp_root()
    candidate = (root / _DEFAULT_DEMO_DB_DIRNAME) if not configured else Path(configured)
    resolved = candidate.resolve()
    if not (resolved == root or root in resolved.parents):
        raise DemoGuardError("demo database directory must be under the system temp directory")
    return resolved


class DemoGuardError(ValueError):
    """Raised when a demo safety guard rejects an operation."""


@dataclass
class DemoState:
    demo_mode: bool = False
    enforcement_enabled: bool = False
    kill_switch_active: bool = False
    active_demo_id: str | None = None
    policy_version: str | None = None
    max_requests: int = 25
    max_duration_seconds: int = 300
    requests_executed: int = 0
    started_at: datetime | None = None
    expires_at: datetime | None = None
    last_decision_outcome: str | None = None
    last_decision_uuid: str | None = None
    db_path: str | None = None
    engine: Any = None
    session_factory: Any = None


_state = DemoState()
_lock = threading.RLock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.strip().lower()
    # strip port/brackets
    if normalized.startswith("[") and "]" in normalized:
        normalized = normalized[1 : normalized.index("]")]
    if ":" in normalized and normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]
    return normalized in _LOOPBACK_HOSTS


def _require_loopback(client_host: str | None, target_host: str | None = None) -> None:
    if not _is_loopback(client_host):
        raise DemoGuardError("demo requests must originate from loopback")
    if target_host is not None and not _is_loopback(target_host):
        raise DemoGuardError("demo target must be loopback")


def _reset_db_locked() -> None:
    if _state.engine is not None:
        try:
            _state.engine.dispose()
        except Exception:
            logger.warning("failed to dispose demo engine")
    _state.engine = None
    _state.session_factory = None
    _state.db_path = None


def _close_demo_db() -> None:
    with _lock:
        _reset_db_locked()


def _ensure_demo_db_locked(demo_id: str) -> None:
    _reset_db_locked()
    demo_db_dir = resolve_demo_db_dir()
    demo_db_dir.mkdir(parents=True, exist_ok=True)
    safe_id = "".join(ch for ch in demo_id if ch.isalnum() or ch in "-_")[:48] or "demo"
    db_path = (demo_db_dir / f"demo_enforcement_{safe_id}.sqlite3").resolve()
    if demo_db_dir not in db_path.parents:
        raise DemoGuardError("demo database path escaped the demo directory")
    # fresh DB for each demo activation
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    _state.engine = engine
    _state.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    _state.db_path = str(db_path)


def _seed_policy_locked(lifecycle: MitigationPolicyLifecycleService, version: str) -> None:
    record = lifecycle.get_policy(version)
    if record is None:
        raise DemoGuardError("demo policy version not found")
    if record.state != PolicyLifecycleState.ACTIVE:
        raise DemoGuardError("demo policy must be ACTIVE")
    config: MitigationPolicyConfig = record.config
    if _state.session_factory is None:
        raise DemoGuardError("demo database is not initialized")
    session: Session = _state.session_factory()
    try:
        row = MitigationPolicy(
            policy_version=config.policy_version,
            enabled=config.enabled,
            mode=config.mode.value,
            monitoring_score_threshold=config.monitoring_score_threshold,
            throttling_score_threshold=config.throttling_score_threshold,
            blocking_score_threshold=config.blocking_score_threshold,
            minimum_authentication_failures=config.minimum_authentication_failures,
            require_grouped_brute_force=config.require_grouped_brute_force,
            throttle_enabled=config.throttle_enabled,
            throttle_limit=config.throttle_limit,
            throttle_window_seconds=config.throttle_window_seconds,
            throttle_duration_seconds=config.throttle_duration_seconds,
            block_enabled=config.block_enabled,
            block_duration_seconds=config.block_duration_seconds,
            max_block_duration_seconds=config.max_block_duration_seconds,
            admin_protection_enabled=config.admin_protection_enabled,
            max_evidence_references=config.max_evidence_references,
            created_at=record.created_at,
            creator_hash=getattr(record, "owner_actor_hash", None),
        )
        session.add(row)
        session.flush()
        session.add(MitigationPolicyState(id=1, policy_id=row.id, singleton_marker=1))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_status() -> dict[str, Any]:
    with _lock:
        expired = bool(_state.expires_at and _now() >= _state.expires_at)
        enforcement_enabled = bool(
            _state.demo_mode
            and _state.enforcement_enabled
            and not _state.kill_switch_active
            and not expired
        )
        advisory_only = not enforcement_enabled
        if not _state.demo_mode:
            status_reason = "disabled"
        elif _state.kill_switch_active:
            status_reason = "kill_switch_active"
        elif expired:
            status_reason = "expired"
        elif enforcement_enabled:
            status_reason = "active_demo_enforcement"
        else:
            status_reason = "advisory_only"
        return {
            "demo_mode": _state.demo_mode,
            "enforcement_enabled": enforcement_enabled,
            "kill_switch_active": _state.kill_switch_active,
            "advisory_only": advisory_only,
            "loopback_only": True,
            "synthetic_only": True,
            "active_demo_id": _state.active_demo_id,
            "policy_version": _state.policy_version,
            "max_requests": _state.max_requests,
            "max_duration_seconds": _state.max_duration_seconds,
            "requests_executed": _state.requests_executed,
            "started_at": _state.started_at,
            "expires_at": _state.expires_at,
            "last_decision_outcome": _state.last_decision_outcome,
            "last_decision_uuid": _state.last_decision_uuid,
            "persistence_db": "isolated-temp-sqlite" if _state.db_path else "none",
            "expired": expired,
            "status_reason": status_reason,
            "real_enforcement": False,
            "guards": {
                "default_off": True,
                "loopback_required": True,
                "synthetic_required": True,
                "explicit_enable_required": True,
                "kill_switch_available": True,
                "request_limit_active": _state.demo_mode and not expired,
                "duration_limit_active": _state.demo_mode and not expired,
                "expired": expired,
                "real_enforcement": False,
            },
        }


def enable_demo(
    *,
    lifecycle: MitigationPolicyLifecycleService,
    client_host: str | None,
    target_host: str | None,
    policy_version: str,
    max_requests: int,
    max_duration_seconds: int,
) -> dict[str, Any]:
    _require_loopback(client_host, target_host)
    with _lock:
        if _state.demo_mode and _state.enforcement_enabled and not _state.kill_switch_active:
            raise DemoGuardError("demo already active; disable before re-enabling")
        demo_id = f"demo-{uuid.uuid4().hex[:12]}"
        started_at = _now()
        expires_at = started_at + timedelta(seconds=max_duration_seconds)
        _ensure_demo_db_locked(demo_id)
        try:
            _seed_policy_locked(lifecycle, policy_version)
        except Exception:
            _reset_db_locked()
            raise
        _state.demo_mode = True
        _state.enforcement_enabled = True
        _state.kill_switch_active = False
        _state.active_demo_id = demo_id
        _state.policy_version = policy_version
        _state.max_requests = max_requests
        _state.max_duration_seconds = max_duration_seconds
        _state.requests_executed = 0
        _state.started_at = started_at
        _state.expires_at = expires_at
        _state.last_decision_outcome = None
        _state.last_decision_uuid = None
    logger.info("gate-e demo enabled demo_id=%s policy=%s", demo_id, policy_version)
    return get_status()


def disable_demo(*, client_host: str | None, reason: str = "operator_disable") -> dict[str, Any]:
    _require_loopback(client_host, client_host)
    with _lock:
        _state.enforcement_enabled = False
        _state.demo_mode = False
        _state.kill_switch_active = False
        _state.active_demo_id = None
        _state.policy_version = None
        _state.requests_executed = 0
        _state.started_at = None
        _state.expires_at = None
        _state.max_requests = 25
        _state.max_duration_seconds = 300
        _state.last_decision_outcome = f"disabled:{reason}"
        _state.last_decision_uuid = None
        _reset_db_locked()
    logger.info("gate-e demo disabled reason=%s", reason)
    return get_status()


def kill_switch(*, client_host: str | None) -> dict[str, Any]:
    _require_loopback(client_host, client_host)
    with _lock:
        _state.kill_switch_active = True
        _state.enforcement_enabled = False
        _state.last_decision_outcome = "kill_switch_activated"
        _reset_db_locked()
    logger.warning("gate-e demo kill switch activated")
    return get_status()


def _build_synthetic_detection(req: Any) -> BotAnalysisResult:
    score = float(req.bot_risk_score)
    if score >= 75:
        classification = BotClassification.AUTOMATION_SUSPICIOUS
    elif score >= 35:
        classification = BotClassification.AUTOMATION_BENIGN_CANDIDATE
    else:
        classification = BotClassification.HUMAN_LIKE
    reasons: list[BotReason] = []
    if score > 0:
        reasons.append(
            BotReason(
                code="SYNTHETIC_DEMO_SIGNAL",
                category=BotReasonCategory.AUTOMATION_CHARACTERISTIC,
                severity=BotReasonSeverity.MEDIUM if score < 75 else BotReasonSeverity.HIGH,
                description="Deterministic synthetic demo signal; no production traffic used.",
            )
        )
    return BotAnalysisResult(
        client_ip=req.client_ip,
        bot_risk_score=score,
        classification=classification,
        reasons=reasons,
        summary="Synthetic Gate E demo evaluation; no production traffic used.",
    )


def _build_context(req: Any, evaluated_at: datetime) -> MitigationRequestContext:
    # Normalize scope/hash for synthetic demo; no real user identifiers.
    scope_hash = req.principal_hash
    if scope_hash and not scope_hash.startswith("sha256:"):
        scope_hash = "sha256:" + hashlib.sha256(scope_hash.encode("utf-8")).hexdigest()
    if scope_hash is None:
        # Deterministic synthetic fallback; no real identifiers.
        scope_hash = "sha256:" + hashlib.sha256(f"demo:{req.request_id}:{req.scope_type.value}".encode("utf-8")).hexdigest()

    actor_key_hash = None
    network_key_hash = None
    api_key_principal_hash = None
    if req.attribution_status == MitigationAttributionStatus.VERIFIED_USER:
        actor_key_hash = scope_hash
    elif req.attribution_status == MitigationAttributionStatus.NETWORK_IP:
        network_key_hash = scope_hash
    elif req.attribution_status == MitigationAttributionStatus.API_KEY_PRINCIPAL:
        api_key_principal_hash = scope_hash

    return MitigationRequestContext(
        evaluated_at=evaluated_at,
        attribution_status=req.attribution_status,
        scope_type=req.scope_type,
        scope_key_hash=scope_hash,
        actor_key_hash=actor_key_hash,
        network_key_hash=network_key_hash,
        api_key_principal_hash=api_key_principal_hash,
        http_method=req.method,
        request_path=req.path,
        endpoint_category="demo",
        is_authenticated=bool(req.authenticated),
        authentication_failures=req.auth_failures,
    )


def _enforcement_decision(decision_type: str, enforcement_enabled: bool) -> tuple[bool, str, str]:
    # returns (allowed, enforcement_state, actual_outcome)
    if not enforcement_enabled:
        return True, "advisory_only", f"advisory:{decision_type}"
    if decision_type == "block":
        return False, "enforced_block", "blocked"
    if decision_type == "throttle":
        return False, "enforced_block", "throttled"
    return True, "enforced_allow", f"allowed:{decision_type}"


def run_synthetic(
    *,
    lifecycle: MitigationPolicyLifecycleService,
    client_host: str | None,
    target_host: str | None,
    demo_id: str,
    requests: list[Any],
) -> dict[str, Any]:
    _require_loopback(client_host, target_host)
    outcomes = []
    stopped_reason = None
    with _lock:
        status = get_status()
        if not _state.demo_mode or _state.active_demo_id != demo_id:
            raise DemoGuardError("demo is not active for this demo_id")
        if _state.kill_switch_active:
            raise DemoGuardError("kill switch is active; demo enforcement disabled")
        if _state.expires_at and _now() >= _state.expires_at:
            _state.enforcement_enabled = False
            raise DemoGuardError("demo duration limit reached")
        if _state.session_factory is None or _state.policy_version is None:
            raise DemoGuardError("demo persistence is not initialized")
        if len(requests) + _state.requests_executed > _state.max_requests:
            raise DemoGuardError("request limit exceeded")

        for req in requests:
            if _state.expires_at and _now() >= _state.expires_at:
                stopped_reason = "duration_limit"
                _state.enforcement_enabled = False
                break
            if _state.requests_executed >= _state.max_requests:
                stopped_reason = "request_limit"
                _state.enforcement_enabled = False
                break
            if not _is_loopback(req.client_ip):
                outcomes.append({
                    "request_id": req.request_id,
                    "scenario": req.scenario,
                    "allowed": True,
                    "enforcement_state": "advisory_only",
                    "intended_action": None,
                    "actual_outcome": "rejected_by_scope_guard",
                    "reason": "non-loopback synthetic target rejected",
                    "decision_uuid": None,
                    "policy_version": _state.policy_version,
                    "audit_event_uuid": None,
                    "evidence_references": [],
                    "advisory_only": True,
                })
                _state.requests_executed += 1
                continue

            evaluated_at = _now()
            session: Session = _state.session_factory()
            try:
                detection = _build_synthetic_detection(req)
                context = _build_context(req, evaluated_at)
                eval_result: PolicyEvaluationResult = lifecycle.evaluate_policy(
                    actor=_DEMO_ACTOR,
                    version=_state.policy_version,
                    at=evaluated_at,
                    detection_result=detection,
                    context=context,
                    risk_assessment=None,
                    advanced_envelope=None,
                    dry_run=False,
                    idempotency_token=f"demo:{demo_id}:{req.request_id}",
                )
                if not eval_result.ok or eval_result.decision is None:
                    session.rollback()
                    outcomes.append({
                        "request_id": req.request_id,
                        "scenario": req.scenario,
                        "allowed": True,
                        "enforcement_state": "advisory_only",
                        "intended_action": None,
                        "actual_outcome": "advisory_only:evaluation_error",
                        "reason": (eval_result.error.code.value if eval_result.error else "evaluation_error"),
                        "decision_uuid": None,
                        "policy_version": _state.policy_version,
                        "audit_event_uuid": None,
                        "evidence_references": [],
                        "advisory_only": True,
                    })
                    _state.requests_executed += 1
                    continue

                persisted = persist_evaluation_result(session, eval_result)
                if not persisted.ok or persisted.decision is None:
                    session.rollback()
                    outcomes.append({
                        "request_id": req.request_id,
                        "scenario": req.scenario,
                        "allowed": True,
                        "enforcement_state": "advisory_only",
                        "intended_action": getattr(eval_result.decision.decision, "decision", None).value if getattr(eval_result.decision.decision, "decision", None) else None,
                        "actual_outcome": "advisory_only:persistence_error",
                        "reason": persisted.error or "persistence_error",
                        "decision_uuid": None,
                        "policy_version": _state.policy_version,
                        "audit_event_uuid": None,
                        "evidence_references": list(eval_result.decision.decision.evidence_references),
                        "advisory_only": True,
                    })
                    _state.requests_executed += 1
                    continue

                session.commit()
                intended = eval_result.decision.decision.decision.value
                enforcement_enabled = _state.enforcement_enabled and not _state.kill_switch_active
                if _state.expires_at and _now() >= _state.expires_at:
                    enforcement_enabled = False
                allowed, enf_state, actual = _enforcement_decision(intended, enforcement_enabled)
                decision_uuid = eval_result.decision.decision_ref
                audit_uuid = eval_result.audit_event.event_uuid if eval_result.audit_event else None
                outcomes.append({
                    "request_id": req.request_id,
                    "scenario": req.scenario,
                    "allowed": allowed,
                    "enforcement_state": enf_state,
                    "intended_action": intended,
                    "actual_outcome": actual,
                    "reason": "demo_evaluation",
                    "decision_uuid": decision_uuid,
                    "policy_version": _state.policy_version,
                    "audit_event_uuid": audit_uuid,
                    "evidence_references": list(eval_result.decision.decision.evidence_references),
                    "advisory_only": enf_state == "advisory_only",
                })
                _state.last_decision_outcome = actual
                _state.last_decision_uuid = decision_uuid
                _state.requests_executed += 1
            except Exception as exc:
                session.rollback()
                logger.exception("demo request failed safely")
                outcomes.append({
                    "request_id": getattr(req, "request_id", "unknown"),
                    "scenario": getattr(req, "scenario", "unknown"),
                    "allowed": True,
                    "enforcement_state": "advisory_only",
                    "intended_action": None,
                    "actual_outcome": "advisory_only:internal_error",
                    "reason": "internal_error",
                    "decision_uuid": None,
                    "policy_version": _state.policy_version,
                    "audit_event_uuid": None,
                    "evidence_references": [],
                    "advisory_only": True,
                })
                _state.requests_executed += 1
            finally:
                session.close()

        if stopped_reason is None and _state.requests_executed >= _state.max_requests:
            stopped_reason = "request_limit"
            _state.enforcement_enabled = False
        if stopped_reason is None and _state.expires_at and _now() >= _state.expires_at:
            stopped_reason = "duration_limit"
            _state.enforcement_enabled = False

    status = get_status()
    return {
        "demo_id": demo_id,
        "demo_mode": status["demo_mode"],
        "enforcement_enabled": status["enforcement_enabled"],
        "kill_switch_active": status["kill_switch_active"],
        "advisory_only": status["advisory_only"],
        "policy_version": status["policy_version"],
        "executed_requests": status["requests_executed"],
        "max_requests": status["max_requests"],
        "max_duration_seconds": status["max_duration_seconds"],
        "started_at": status["started_at"],
        "expires_at": status["expires_at"],
        "outcomes": outcomes,
        "stopped_reason": stopped_reason,
    }


def reset_for_tests() -> None:
    with _lock:
        _reset_db_locked()
        _state.demo_mode = False
        _state.enforcement_enabled = False
        _state.kill_switch_active = False
        _state.active_demo_id = None
        _state.policy_version = None
        _state.max_requests = 25
        _state.max_duration_seconds = 300
        _state.requests_executed = 0
        _state.started_at = None
        _state.expires_at = None
        _state.last_decision_outcome = None
        _state.last_decision_uuid = None
