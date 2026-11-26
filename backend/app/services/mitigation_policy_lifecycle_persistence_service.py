"""MW3 Gate B persistence boundary for the Gate A policy lifecycle.

This module deliberately reuses the five mitigation tables introduced by the
existing migrations. It adds no HTTP route, no auth/RBAC change, no frontend
change, no dependency, and no enforcement behaviour. The caller owns the
SQLAlchemy transaction; this boundary only validates, flushes, and reads.

Lossy mapping contract
----------------------
Gate A carries more lifecycle metadata than the existing schema can represent.
The following mappings are explicit and intentionally lossy:

* ``ImmutablePolicyVersion.config`` maps field-for-field to one immutable
  ``mitigation_policies`` row. Lifecycle state, validity windows, approval
  metadata, predecessor version, and config digest are **not** columns.
* ``ACTIVE`` is represented by the singleton ``mitigation_policy_state`` row.
  ``INACTIVE``, ``RETIRED``, and ``ROLLED_BACK`` are distinguishable only by the
  Gate A result; after persistence they are represented by the absence of an
  active pointer plus the corresponding activation/audit history. This module
  never invents an audit event that Gate A did not produce.
* Activation plans map directly to ``mitigation_policy_activation_events``.
  Gate A detail keys outside the model allowlist are dropped; a small,
  documented subset is remapped to allowlisted keys.
* Audit plans map to ``mitigation_audit_events``. The Gate A ``content_digest``
  is stored as ``event_hash`` data only and is **not** represented as a
  tamper-proof chain. ``correlation_ref`` is stored as ``chain_id`` and
  ``sequence_no`` is a deterministic placeholder. Gate A ``action``,
  ``outcome``, ``reason``, and non-allowlisted detail keys are not persisted.
* Decisions map to ``mitigation_decisions`` with ``decision_ref`` used as both
  ``decision_uuid`` and ``dedupe_key``.

No row is committed here. Failed writes raise a boundary-specific exception and
leave the session transaction for the caller to roll back.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.mitigation import (
    ALLOWED_ACTIVATION_DETAIL_KEYS,
    ALLOWED_AUDIT_DETAIL_KEYS,
    MitigationAuditEvent as AuditEventRow,
    MitigationDecision as DecisionRow,
    MitigationPolicy as PolicyRow,
    MitigationPolicyActivationEvent as ActivationEventRow,
    MitigationPolicyState as PolicyStateRow,
)
from app.schemas.mitigation import MitigationPolicyConfig
from app.schemas.mitigation_policy_lifecycle import (
    ActivationEventPlan,
    ImmutablePolicyVersion,
    LifecycleAuditEventPlan,
    LifecycleDecision,
    PolicyEvaluationResult,
    PolicyLifecycleResult,
    PolicyLifecycleState,
)


class LifecyclePersistenceError(Exception):
    """Base class for all Gate B persistence-boundary failures."""


class LifecyclePersistenceValidationError(LifecyclePersistenceError):
    """A plan cannot be mapped safely to the existing schema."""


class LifecyclePersistenceConflictError(LifecyclePersistenceError):
    """A deterministic identifier already exists with different content."""


class LifecyclePersistenceDatabaseError(LifecyclePersistenceError):
    """The disposable database operation failed. No DSN is included."""


@dataclass(frozen=True)
class PersistedPolicySnapshot:
    policy_version: str
    config: MitigationPolicyConfig
    creator_hash: Optional[str]
    created_at: datetime
    active: bool
    activation_event_count: int
    latest_activation_event_type: Optional[str]
    created: bool


@dataclass(frozen=True)
class PersistedActivationSnapshot:
    event_uuid: str
    event_type: str
    policy_version: str
    created: bool


@dataclass(frozen=True)
class PersistedAuditSnapshot:
    event_uuid: str
    event_hash: str
    chain_id: str
    sequence_no: int
    created: bool


@dataclass(frozen=True)
class LifecyclePersistenceResult:
    ok: bool
    policy: PersistedPolicySnapshot | None
    activation_events: tuple[PersistedActivationSnapshot, ...]
    audit_events: tuple[PersistedAuditSnapshot, ...]
    error: Optional[str]
    created: bool


@dataclass(frozen=True)
class PersistedDecisionSnapshot:
    decision_uuid: str
    dedupe_key: str
    policy_version: str
    decision_type: str
    created: bool


@dataclass(frozen=True)
class LifecycleEvaluationPersistenceResult:
    ok: bool
    decision: PersistedDecisionSnapshot | None
    audit_event: PersistedAuditSnapshot | None
    error: Optional[str]


_POLICY_FIELDS = (
    "enabled",
    "mode",
    "monitoring_score_threshold",
    "throttling_score_threshold",
    "blocking_score_threshold",
    "minimum_authentication_failures",
    "require_grouped_brute_force",
    "throttle_enabled",
    "throttle_limit",
    "throttle_window_seconds",
    "throttle_duration_seconds",
    "block_enabled",
    "block_duration_seconds",
    "max_block_duration_seconds",
    "admin_protection_enabled",
    "max_evidence_references",
)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise LifecyclePersistenceValidationError("timestamp must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _config_from_row(row: PolicyRow) -> MitigationPolicyConfig:
    values: dict[str, Any] = {"policy_version": row.policy_version}
    for name in _POLICY_FIELDS:
        value = getattr(row, name)
        values[name] = value.value if hasattr(value, "value") else value
    try:
        return MitigationPolicyConfig(**values)
    except (TypeError, ValueError, ValidationError) as exc:
        raise LifecyclePersistenceValidationError(
            "stored policy configuration is not valid"
        ) from exc


def _config_values(config: MitigationPolicyConfig) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in _POLICY_FIELDS:
        value = getattr(config, name)
        values[name] = value.value if hasattr(value, "value") else value
    return values


def _policy_fingerprint(row: PolicyRow) -> tuple[Any, ...]:
    return (
        row.policy_version,
        row.creator_hash,
        _utc(row.created_at),
        tuple(
            (value.value if hasattr(value, "value") else value)
            for value in (getattr(row, name) for name in _POLICY_FIELDS)
        ),
    )


def _activation_fingerprint(row: ActivationEventRow) -> tuple[Any, ...]:
    return (
        row.event_uuid,
        row.event_type,
        row.policy_id,
        row.actor_hash,
        row.reason_code,
        _utc(row.occurred_at),
        dict(row.details or {}),
    )


def _audit_fingerprint(row: AuditEventRow) -> tuple[Any, ...]:
    return (
        row.event_uuid,
        row.event_type,
        row.entity_type,
        row.entity_identifier,
        row.policy_id,
        row.decision_id,
        row.actor_hash,
        row.actor_role,
        dict(row.details or {}),
        row.previous_event_hash,
        row.event_hash,
        row.sequence_no,
        row.chain_id,
        _utc(row.created_at),
    )


def _decision_fingerprint(row: DecisionRow) -> tuple[Any, ...]:
    return (
        row.decision_uuid,
        row.dedupe_key,
        row.policy_id,
        row.decision_type,
        row.scope_type,
        row.scope_key_hash,
        row.attribution_status,
        row.verified_attribution,
        list(row.reason_codes or []),
        row.explanation,
        list(row.evidence_references or []),
        _utc(row.issued_at),
        _utc(row.expires_at) if row.expires_at is not None else None,
        row.rate_limit,
        row.rate_limit_window_seconds,
    )


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, str):
        if isinstance(value, str) and len(value) > 128:
            return value[:128]
        return value
    return str(value)[:128]


def _map_activation_details(
    plan: ActivationEventPlan, config: MitigationPolicyConfig
) -> dict[str, Any]:
    """Map Gate A details to the model's narrow activation allowlist."""
    details: dict[str, Any] = {
        "policy_version": plan.policy_version,
        "policy_mode": config.mode.value,
    }
    previous = plan.details.get("previous_active_version")
    rollback_from = plan.details.get("rolled_back_from")
    if isinstance(previous, str) and previous != "none":
        details["previous_policy_version"] = previous
    elif isinstance(rollback_from, str) and rollback_from != "none":
        details["previous_policy_version"] = rollback_from
    return {
        key: _safe_scalar(value)
        for key, value in details.items()
        if key in ALLOWED_ACTIVATION_DETAIL_KEYS
    }


def _map_audit_details(plan: LifecycleAuditEventPlan) -> dict[str, Any]:
    """Drop every audit detail key not accepted by the existing model."""
    return {
        key: _safe_scalar(value)
        for key, value in plan.details.items()
        if key in ALLOWED_AUDIT_DETAIL_KEYS
    }


def _get_policy_row(db: Session, version: str) -> PolicyRow | None:
    return db.query(PolicyRow).filter(PolicyRow.policy_version == version).one_or_none()


def _get_state_row(db: Session) -> PolicyStateRow:
    row = db.query(PolicyStateRow).filter(PolicyStateRow.id == 1).one_or_none()
    if row is None:
        row = PolicyStateRow(id=1, policy_id=None, singleton_marker=1)
        db.add(row)
        db.flush()
    return row


def _persist_policy(
    db: Session, snapshot: ImmutablePolicyVersion
) -> tuple[PolicyRow, bool]:
    existing = _get_policy_row(db, snapshot.policy_version)
    if existing is not None:
        expected_config = snapshot.config.model_dump(mode="json")
        stored_config = _config_from_row(existing).model_dump(mode="json")
        expected = (
            snapshot.policy_version,
            snapshot.owner_actor_hash,
            _utc(snapshot.created_at),
            tuple(expected_config[name] for name in _POLICY_FIELDS),
        )
        stored = _policy_fingerprint(existing)[:2] + (_utc(existing.created_at), stored_config_tuple(stored_config))
        if expected != stored:
            raise LifecyclePersistenceConflictError(
                "policy version already exists with different content"
            )
        return existing, False

    row = PolicyRow(
        policy_version=snapshot.policy_version,
        creator_hash=snapshot.owner_actor_hash,
        created_at=_utc(snapshot.created_at),
        **_config_values(snapshot.config),
    )
    db.add(row)
    db.flush()
    return row, True


def stored_config_tuple(config: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(config[name] for name in _POLICY_FIELDS)


def _persist_activation_event(
    db: Session, plan: ActivationEventPlan, result_config: MitigationPolicyConfig
) -> PersistedActivationSnapshot:
    """Persist one activation plan against the policy version that owns it.

    A rollback result contains events for both the outgoing and incoming policy
    versions. The event's own ``policy_version`` therefore determines the FK,
    not the policy snapshot attached to the overall lifecycle result.
    """
    policy_row = _get_policy_row(db, plan.policy_version)
    if policy_row is None:
        raise LifecyclePersistenceValidationError(
            "activation event references a policy that was not persisted"
        )
    config = (
        result_config
        if policy_row.policy_version == result_config.policy_version
        else _config_from_row(policy_row)
    )
    expected_details = _map_activation_details(plan, config)
    existing = (
        db.query(ActivationEventRow)
        .filter(ActivationEventRow.event_uuid == plan.event_uuid)
        .one_or_none()
    )
    if existing is not None:
        expected = (
            plan.event_uuid,
            plan.event_type.value,
            policy_row.id,
            plan.actor_hash,
            plan.reason_code.value,
            _utc(plan.occurred_at),
            expected_details,
        )
        if _activation_fingerprint(existing) != expected:
            raise LifecyclePersistenceConflictError(
                "activation event UUID already exists with different content"
            )
        return PersistedActivationSnapshot(
            plan.event_uuid, plan.event_type.value, policy_row.policy_version, False
        )

    row = ActivationEventRow(
        event_uuid=plan.event_uuid,
        event_type=plan.event_type.value,
        policy_id=policy_row.id,
        actor_hash=plan.actor_hash,
        reason_code=plan.reason_code.value,
        occurred_at=_utc(plan.occurred_at),
        details=expected_details,
    )
    db.add(row)
    db.flush()
    return PersistedActivationSnapshot(
        plan.event_uuid, plan.event_type.value, policy_row.policy_version, True
    )


def _resolve_audit_links(
    db: Session, plan: LifecycleAuditEventPlan
) -> tuple[int | None, int | None]:
    policy_row = _get_policy_row(db, plan.policy_version)
    if policy_row is None:
        raise LifecyclePersistenceValidationError("audit event references an unknown policy")
    decision_row = None
    if plan.decision_ref is not None:
        decision_row = (
            db.query(DecisionRow)
            .filter(DecisionRow.decision_uuid == plan.decision_ref)
            .one_or_none()
        )
        if decision_row is None:
            raise LifecyclePersistenceValidationError(
                "decision audit event references an unknown decision"
            )
    return policy_row.id, decision_row.id if decision_row is not None else None


def _persist_audit_event(
    db: Session, plan: LifecycleAuditEventPlan
) -> PersistedAuditSnapshot:
    policy_id, decision_id = _resolve_audit_links(db, plan)
    expected_details = _map_audit_details(plan)
    chain_id = plan.correlation_ref
    sequence_no = 1
    existing = (
        db.query(AuditEventRow)
        .filter(AuditEventRow.event_uuid == plan.event_uuid)
        .one_or_none()
    )
    if existing is not None:
        expected = (
            plan.event_uuid,
            plan.event_type.value,
            plan.entity_type.value,
            plan.entity_identifier,
            policy_id,
            decision_id,
            plan.actor_hash,
            plan.actor_role if plan.actor_role is not None else None,
            expected_details,
            None,
            plan.content_digest,
            sequence_no,
            chain_id,
            _utc(plan.occurred_at),
        )
        if _audit_fingerprint(existing) != expected:
            raise LifecyclePersistenceConflictError(
                "audit event UUID already exists with different content"
            )
        return PersistedAuditSnapshot(
            plan.event_uuid, plan.content_digest, chain_id, sequence_no, False
        )

    conflicting_chain = (
        db.query(AuditEventRow)
        .filter(
            AuditEventRow.chain_id == chain_id,
            AuditEventRow.sequence_no == sequence_no,
        )
        .one_or_none()
    )
    if conflicting_chain is not None:
        raise LifecyclePersistenceConflictError(
            "audit chain slot already belongs to another event"
        )

    row = AuditEventRow(
        event_uuid=plan.event_uuid,
        event_type=plan.event_type.value,
        entity_type=plan.entity_type.value,
        entity_identifier=plan.entity_identifier,
        policy_id=policy_id,
        decision_id=decision_id,
        actor_hash=plan.actor_hash,
        actor_role=plan.actor_role if plan.actor_role is not None else None,
        details=expected_details,
        previous_event_hash=None,
        event_hash=plan.content_digest,
        sequence_no=sequence_no,
        chain_id=chain_id,
        created_at=_utc(plan.occurred_at),
    )
    db.add(row)
    db.flush()
    return PersistedAuditSnapshot(
        plan.event_uuid, plan.content_digest, chain_id, sequence_no, True
    )


def _sync_active_pointer(db: Session, policy_row: PolicyRow, state: PolicyLifecycleState) -> None:
    state_row = db.query(PolicyStateRow).filter(PolicyStateRow.id == 1).one_or_none()
    if state is PolicyLifecycleState.ACTIVE:
        if state_row is None:
            db.add(PolicyStateRow(id=1, policy_id=policy_row.id, singleton_marker=1))
        else:
            state_row.policy_id = policy_row.id
        db.flush()
        return
    if (
        state in {
            PolicyLifecycleState.INACTIVE,
            PolicyLifecycleState.RETIRED,
            PolicyLifecycleState.ROLLED_BACK,
        }
        and state_row is not None
        and state_row.policy_id == policy_row.id
    ):
        state_row.policy_id = None
        db.flush()


def _policy_snapshot(db: Session, row: PolicyRow, created: bool) -> PersistedPolicySnapshot:
    state_row = db.query(PolicyStateRow).filter(PolicyStateRow.id == 1).one_or_none()
    activation_rows = (
        db.query(ActivationEventRow)
        .filter(ActivationEventRow.policy_id == row.id)
        .order_by(ActivationEventRow.occurred_at.desc(), ActivationEventRow.id.desc())
        .all()
    )
    latest = str(activation_rows[0].event_type) if activation_rows else None
    return PersistedPolicySnapshot(
        policy_version=row.policy_version,
        config=_config_from_row(row),
        creator_hash=row.creator_hash,
        created_at=_utc(row.created_at),
        active=(state_row is not None and state_row.policy_id == row.id),
        activation_event_count=len(activation_rows),
        latest_activation_event_type=latest,
        created=created,
    )


def persist_lifecycle_result(
    db: Session,
    result: PolicyLifecycleResult,
    *,
    actor: Any = None,
    at: Optional[datetime] = None,
) -> LifecyclePersistenceResult:
    """Flush a successful Gate A lifecycle result into the existing tables."""
    if not result.ok:
        return LifecyclePersistenceResult(
            ok=False,
            policy=None,
            activation_events=(),
            audit_events=(),
            error=result.error.code.value if result.error is not None else "unknown_error",
            created=False,
        )
    snapshot = result.policy
    if snapshot is None:
        raise LifecyclePersistenceValidationError("successful lifecycle result has no policy")
    if actor is not None and getattr(actor, "actor_hash", None) != snapshot.owner_actor_hash:
        raise LifecyclePersistenceValidationError("actor does not own the policy snapshot")
    try:
        policy_row, created = _persist_policy(db, snapshot)
        _sync_active_pointer(db, policy_row, snapshot.state)
        activation_events = tuple(
            _persist_activation_event(db, plan, snapshot.config)
            for plan in result.activation_events
        )
        audit_events = tuple(_persist_audit_event(db, plan) for plan in result.audit_events)
        return LifecyclePersistenceResult(
            ok=True,
            policy=_policy_snapshot(db, policy_row, created),
            activation_events=activation_events,
            audit_events=audit_events,
            error=None,
            created=created,
        )
    except LifecyclePersistenceError:
        raise
    except IntegrityError:
        raise LifecyclePersistenceConflictError(
            "a deterministic database identifier conflicts with existing data"
        ) from None
    except SQLAlchemyError:
        raise LifecyclePersistenceDatabaseError(
            "disposable database write failed"
        ) from None


def _decision_values(decision: LifecycleDecision, policy_row: PolicyRow) -> dict[str, Any]:
    core = decision.decision
    return {
        "decision_uuid": decision.decision_ref,
        "dedupe_key": decision.decision_ref,
        "decision_type": core.decision.value,
        "scope_type": core.scope_type.value,
        "scope_key_hash": core.scope_key_hash,
        "attribution_status": core.attribution_status.value,
        "verified_attribution": bool(core.verified_attribution),
        "reason_codes": [code.value for code in core.reason_codes],
        "explanation": core.explanation,
        "policy_id": policy_row.id,
        "evidence_references": list(core.evidence_references),
        "issued_at": _utc(core.issued_at),
        "expires_at": _utc(core.expires_at) if core.expires_at is not None else None,
        "rate_limit": core.rate_limit,
        "rate_limit_window_seconds": core.rate_limit_window_seconds,
        "advisory_only": True,
        "created_at": _utc(decision.evaluated_at),
    }


def persist_evaluation_result(
    db: Session, result: PolicyEvaluationResult
) -> LifecycleEvaluationPersistenceResult:
    """Flush a successful Gate A advisory decision and its audit plan."""
    if not result.ok:
        return LifecycleEvaluationPersistenceResult(
            ok=False,
            decision=None,
            audit_event=None,
            error=result.error.code.value if result.error is not None else "unknown_error",
        )
    decision = result.decision
    audit_plan = result.audit_event
    if decision is None or audit_plan is None:
        raise LifecyclePersistenceValidationError(
            "successful evaluation result has no decision or audit plan"
        )
    policy_row = _get_policy_row(db, decision.policy_version)
    if policy_row is None:
        raise LifecyclePersistenceValidationError(
            "decision references a policy that was not persisted"
        )
    if decision.decision.advisory_only is not True:
        raise LifecyclePersistenceValidationError("only advisory-only decisions are persisted")
    values = _decision_values(decision, policy_row)
    try:
        existing = (
            db.query(DecisionRow)
            .filter(DecisionRow.decision_uuid == decision.decision_ref)
            .one_or_none()
        )
        if existing is not None:
            if _decision_fingerprint(existing) != _decision_fingerprint_values(values):
                raise LifecyclePersistenceConflictError(
                    "decision UUID already exists with different content"
                )
            created = False
            decision_row = existing
        else:
            decision_row = DecisionRow(**values)
            db.add(decision_row)
            db.flush()
            created = True
        audit_event = _persist_audit_event(db, audit_plan)
        return LifecycleEvaluationPersistenceResult(
            ok=True,
            decision=PersistedDecisionSnapshot(
                decision.decision_ref,
                decision.decision_ref,
                decision.policy_version,
                decision.decision.decision.value,
                created,
            ),
            audit_event=audit_event,
            error=None,
        )
    except LifecyclePersistenceError:
        raise
    except IntegrityError:
        raise LifecyclePersistenceConflictError(
            "a deterministic decision identifier conflicts with existing data"
        ) from None
    except SQLAlchemyError:
        raise LifecyclePersistenceDatabaseError(
            "disposable database decision write failed"
        ) from None


def _decision_fingerprint_values(values: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        values["decision_uuid"],
        values["dedupe_key"],
        values["policy_id"],
        values["decision_type"],
        values["scope_type"],
        values["scope_key_hash"],
        values["attribution_status"],
        values["verified_attribution"],
        list(values["reason_codes"]),
        values["explanation"],
        list(values["evidence_references"]),
        _utc(values["issued_at"]),
        _utc(values["expires_at"]) if values["expires_at"] is not None else None,
        values["rate_limit"],
        values["rate_limit_window_seconds"],
    )


def load_persisted_policy(db: Session, version: str) -> PersistedPolicySnapshot | None:
    row = _get_policy_row(db, version)
    if row is None:
        return None
    return _policy_snapshot(db, row, created=False)


def load_active_policy_version(db: Session) -> str | None:
    row = db.query(PolicyStateRow).filter(PolicyStateRow.id == 1).one_or_none()
    if row is None or row.policy_id is None:
        return None
    policy_row = db.query(PolicyRow).filter(PolicyRow.id == row.policy_id).one_or_none()
    return policy_row.policy_version if policy_row is not None else None


def load_all_persisted_policies(db: Session) -> tuple[PersistedPolicySnapshot, ...]:
    """Load all persisted policy snapshots in deterministic version order."""
    rows = db.query(PolicyRow).order_by(PolicyRow.policy_version.asc(), PolicyRow.id.asc()).all()
    return tuple(_policy_snapshot(db, row, created=False) for row in rows)


def load_persisted_decision(db: Session, decision_ref: str) -> DecisionRow | None:
    return (
        db.query(DecisionRow)
        .filter(DecisionRow.decision_uuid == decision_ref)
        .one_or_none()
    )


def load_persisted_audit_event(db: Session, event_uuid: str) -> AuditEventRow | None:
    return (
        db.query(AuditEventRow)
        .filter(AuditEventRow.event_uuid == event_uuid)
        .one_or_none()
    )


__all__ = [
    "LifecycleEvaluationPersistenceResult",
    "LifecyclePersistenceConflictError",
    "LifecyclePersistenceDatabaseError",
    "LifecyclePersistenceError",
    "LifecyclePersistenceResult",
    "LifecyclePersistenceValidationError",
    "PersistedActivationSnapshot",
    "PersistedAuditSnapshot",
    "PersistedDecisionSnapshot",
    "PersistedPolicySnapshot",
    "load_active_policy_version",
    "load_all_persisted_policies",
    "load_persisted_audit_event",
    "load_persisted_decision",
    "load_persisted_policy",
    "persist_evaluation_result",
    "persist_lifecycle_result",
]
