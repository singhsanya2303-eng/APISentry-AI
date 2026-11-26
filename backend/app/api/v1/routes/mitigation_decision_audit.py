"""Read-only decision, audit-history, and status endpoints (Gate C).

These routes project existing Gate B rows into explicit privacy-safe response
models. They add query glue only; no policy evaluation, hashing, chain logic,
enforcement, or write operation is performed here.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.routes.mitigation_policy_admin import get_lifecycle_service
from app.core.security import require_analyst
from app.db.session import get_db
from app.models.mitigation import (
    MitigationAuditEntityType,
    MitigationAuditEvent as AuditEventRow,
    MitigationAuditEventType,
    MitigationDecision as DecisionRow,
    MitigationDecisionType,
    MitigationPolicy as PolicyRow,
    MitigationScopeType,
)
from app.schemas.mitigation_admin import (
    AuditEventListResponse,
    AuditEventRecord,
    DecisionListResponse,
    DecisionRecord,
    EnforcementStatusResponse,
)
from app.services.mitigation_policy_lifecycle_persistence_service import (
    load_active_policy_version,
    load_persisted_policy,
)

router = APIRouter(
    prefix="/security/mitigation",
    tags=["Mitigation Decision and Audit History"],
)
logger = logging.getLogger("apisentry.api.mitigation_decision_audit")


def _decision_record(
    row: DecisionRow, policy_version: str
) -> DecisionRecord:
    return DecisionRecord(
        decision_uuid=row.decision_uuid,
        dedupe_key=row.dedupe_key,
        policy_version=policy_version,
        decision_type=row.decision_type,
        scope_type=row.scope_type,
        scope_key_hash=row.scope_key_hash,
        attribution_status=row.attribution_status,
        verified_attribution=row.verified_attribution,
        reason_codes=list(row.reason_codes or []),
        explanation=row.explanation,
        evidence_references=list(row.evidence_references or []),
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        created_at=row.created_at,
        rate_limit=row.rate_limit,
        rate_limit_window_seconds=row.rate_limit_window_seconds,
        advisory_only=row.advisory_only,
    )


def _audit_record(
    row: AuditEventRow,
    policy_version: str | None,
    decision_uuid: str | None,
) -> AuditEventRecord:
    return AuditEventRecord(
        event_uuid=row.event_uuid,
        event_type=row.event_type,
        entity_type=row.entity_type,
        entity_identifier=row.entity_identifier,
        policy_version=policy_version,
        decision_uuid=decision_uuid,
        actor_hash=row.actor_hash,
        actor_role=row.actor_role,
        chain_id=row.chain_id,
        sequence_no=row.sequence_no,
        event_hash=row.event_hash,
        previous_event_hash=row.previous_event_hash,
        details=dict(row.details or {}),
        created_at=row.created_at,
    )


def _check_time_range(from_time: datetime | None, to_time: datetime | None) -> None:
    if from_time is not None and to_time is not None and from_time > to_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="from_time must be earlier than or equal to to_time",
        )


def _read_failure() -> None:
    logger.exception("mitigation history read failed")
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal server error.",
    ) from None


@router.get("/decisions", response_model=DecisionListResponse)
def list_decisions(
    policy_version: str | None = Query(default=None, max_length=64),
    decision_ref: str | None = Query(default=None, max_length=128),
    decision_type: MitigationDecisionType | None = Query(default=None),
    scope_type: MitigationScopeType | None = Query(default=None),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> DecisionListResponse:
    """List persisted advisory decisions with bounded, allowlisted filters."""
    _check_time_range(from_time, to_time)
    try:
        query = db.query(DecisionRow, PolicyRow.policy_version).join(
            PolicyRow, DecisionRow.policy_id == PolicyRow.id
        )
        if policy_version is not None:
            query = query.filter(PolicyRow.policy_version == policy_version)
        if decision_ref is not None:
            query = query.filter(DecisionRow.decision_uuid == decision_ref)
        if decision_type is not None:
            query = query.filter(DecisionRow.decision_type == decision_type.value)
        if scope_type is not None:
            query = query.filter(DecisionRow.scope_type == scope_type.value)
        if from_time is not None:
            query = query.filter(DecisionRow.issued_at >= from_time)
        if to_time is not None:
            query = query.filter(DecisionRow.issued_at <= to_time)

        total = query.count()
        rows = (
            query.order_by(DecisionRow.issued_at.desc(), DecisionRow.id.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return DecisionListResponse(
            items=[_decision_record(row, version) for row, version in rows],
            total=total,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except SQLAlchemyError:
        _read_failure()
    except Exception:
        _read_failure()


@router.get("/decisions/{decision_ref}", response_model=DecisionRecord)
def get_decision(
    decision_ref: str,
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> DecisionRecord:
    """Retrieve one persisted advisory decision by its opaque UUID5 reference."""
    try:
        row = (
            db.query(DecisionRow, PolicyRow.policy_version)
            .join(PolicyRow, DecisionRow.policy_id == PolicyRow.id)
            .filter(DecisionRow.decision_uuid == decision_ref)
            .one_or_none()
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Decision not found.",
            )
        decision_row, version = row
        return _decision_record(decision_row, version)
    except HTTPException:
        raise
    except SQLAlchemyError:
        _read_failure()
    except Exception:
        _read_failure()


@router.get("/audit-events", response_model=AuditEventListResponse)
def list_audit_events(
    policy_version: str | None = Query(default=None, max_length=64),
    decision_ref: str | None = Query(default=None, max_length=128),
    event_type: MitigationAuditEventType | None = Query(default=None),
    entity_type: MitigationAuditEntityType | None = Query(default=None),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> AuditEventListResponse:
    """List persisted audit events. Hashes are content digests stored as data."""
    _check_time_range(from_time, to_time)
    try:
        query = (
            db.query(
                AuditEventRow,
                PolicyRow.policy_version,
                DecisionRow.decision_uuid,
            )
            .outerjoin(PolicyRow, AuditEventRow.policy_id == PolicyRow.id)
            .outerjoin(DecisionRow, AuditEventRow.decision_id == DecisionRow.id)
        )
        if policy_version is not None:
            query = query.filter(PolicyRow.policy_version == policy_version)
        if decision_ref is not None:
            query = query.filter(DecisionRow.decision_uuid == decision_ref)
        if event_type is not None:
            query = query.filter(AuditEventRow.event_type == event_type.value)
        if entity_type is not None:
            query = query.filter(AuditEventRow.entity_type == entity_type.value)
        if from_time is not None:
            query = query.filter(AuditEventRow.created_at >= from_time)
        if to_time is not None:
            query = query.filter(AuditEventRow.created_at <= to_time)

        total = query.count()
        rows = (
            query.order_by(AuditEventRow.created_at.desc(), AuditEventRow.id.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return AuditEventListResponse(
            items=[
                _audit_record(row, version, decision_uuid)
                for row, version, decision_uuid in rows
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except SQLAlchemyError:
        _read_failure()
    except Exception:
        _read_failure()


@router.get("/audit-events/{event_uuid}", response_model=AuditEventRecord)
def get_audit_event(
    event_uuid: str,
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> AuditEventRecord:
    """Retrieve one persisted audit event by its opaque UUID5 reference."""
    try:
        row = (
            db.query(
                AuditEventRow,
                PolicyRow.policy_version,
                DecisionRow.decision_uuid,
            )
            .outerjoin(PolicyRow, AuditEventRow.policy_id == PolicyRow.id)
            .outerjoin(DecisionRow, AuditEventRow.decision_id == DecisionRow.id)
            .filter(AuditEventRow.event_uuid == event_uuid)
            .one_or_none()
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Audit event not found.",
            )
        audit_row, version, decision_uuid = row
        return _audit_record(audit_row, version, decision_uuid)
    except HTTPException:
        raise
    except SQLAlchemyError:
        _read_failure()
    except Exception:
        _read_failure()


@router.get("/enforcement/status", response_model=EnforcementStatusResponse)
def enforcement_status(
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> EnforcementStatusResponse:
    """Return read-only lifecycle status; no enforcement layer is enabled."""
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    active_version = service.active_version
    policy = service.get_policy(active_version) if active_version else None
    try:
        persisted_active_version = load_active_policy_version(db)
        persisted = (
            load_persisted_policy(db, active_version) if active_version else None
        )
    except Exception:
        _read_failure()

    latest_activation: str | None = None
    if persisted is not None and persisted.latest_activation_event_type:
        latest_activation = persisted.latest_activation_event_type.rsplit(".", 1)[-1]

    diverged = bool(hydration.get("diverged")) or (active_version != persisted_active_version)
    consistency_note = None
    if diverged:
        consistency_note = str(hydration.get("error") or "in_memory_persisted_divergence")
    elif hydration.get("hydrated"):
        consistency_note = "hydrated_from_persistence"

    return EnforcementStatusResponse(
        active_version=active_version,
        policy_available=policy is not None,
        policy_mode=policy.config.mode.value if policy is not None else None,
        persisted_active_version=persisted_active_version,
        activation_event_count=(
            persisted.activation_event_count if persisted is not None else None
        ),
        latest_activation_event_type=latest_activation,
        registry_consistent=not diverged,
        consistency_note=consistency_note,
    )
