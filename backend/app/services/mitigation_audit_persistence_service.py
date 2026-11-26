"""Persistence for privacy-safe mitigation audit events.

Scope boundary: this module does **not** implement hash-chain append. Callers must
supply already-computed ``event_hash``, ``chain_id``, ``sequence_no``, and optional
``previous_event_hash`` values. The service stores them as data; it does not claim
chain continuity, tamper evidence, or concurrency-safe sequence allocation.

Transaction boundary: the caller owns the SQLAlchemy session. Writes are flushed
inside a nested savepoint and are never committed by this module.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
from typing import Any, NamedTuple, Optional, Union

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.mitigation import (
    MitigationAuditEntityType,
    MitigationAuditEvent,
    MitigationAuditEventType,
)
from app.services.mitigation_persistence_common import (
    AuditEventPersistenceError,
    AuditEventValidationError,
    PrivacySensitiveDataError,
    ensure_outer_transaction_safely,
    reject_raw_privacy_text,
    reject_sensitive_fields,
)

logger = logging.getLogger("apisentry.persistence.mitigation.audit")

_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class AuditEventPersistenceResult(NamedTuple):
    """The persisted or idempotently reused audit event and whether it was created."""

    event: MitigationAuditEvent
    created: bool


def _enum_value(value: Any, enum_type: Any, field_name: str) -> str:
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise AuditEventValidationError(f"{field_name} is not an allowed value") from None


def _validate_event_uuid(event_uuid: Any) -> str:
    if not isinstance(event_uuid, str) or not _UUID5_RE.fullmatch(event_uuid):
        raise AuditEventValidationError("event_uuid must be a lowercase UUID5")
    return event_uuid


def _validate_details(details: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if details is None:
        return None
    reject_sensitive_fields(details, context="audit details")
    try:
        return MitigationAuditEvent(details=details).details
    except (ValueError, TypeError) as exc:
        raise AuditEventValidationError("audit details failed allowlist validation") from None


def _find_existing(db: Session, event_uuid: str) -> Optional[MitigationAuditEvent]:
    try:
        return (
            db.query(MitigationAuditEvent)
            .filter(MitigationAuditEvent.event_uuid == event_uuid)
            .first()
        )
    except SQLAlchemyError as exc:
        logger.error("Existing audit event lookup failed (%s)", type(exc).__name__)
        raise AuditEventPersistenceError("Existing audit event could not be read") from None


def _build_record(
    *,
    event_uuid: str,
    event_type: Union[MitigationAuditEventType, str],
    entity_type: Union[MitigationAuditEntityType, str],
    entity_identifier: str,
    event_hash: str,
    chain_id: str,
    sequence_no: int,
    policy_id: Optional[int],
    decision_id: Optional[int],
    actor_hash: Optional[str],
    actor_role: Optional[str],
    details: Optional[dict[str, Any]],
    previous_event_hash: Optional[str],
    created_at: Optional[datetime],
) -> MitigationAuditEvent:
    clean_details = _validate_details(details)
    if clean_details is not None:
        for value in clean_details.values():
            if isinstance(value, str):
                reject_raw_privacy_text(
                    value,
                    field_name="audit detail value",
                    error_type=AuditEventValidationError,
                )

    for field_name, value in (
        ("entity_identifier", entity_identifier),
        ("chain_id", chain_id),
        ("actor_hash", actor_hash),
        ("previous_event_hash", previous_event_hash),
        ("event_hash", event_hash),
    ):
        if value is not None:
            reject_raw_privacy_text(
                str(value),
                field_name=field_name,
                error_type=AuditEventValidationError,
            )

    try:
        return MitigationAuditEvent(
            event_uuid=event_uuid,
            event_type=_enum_value(event_type, MitigationAuditEventType, "event_type"),
            entity_type=_enum_value(entity_type, MitigationAuditEntityType, "entity_type"),
            entity_identifier=entity_identifier,
            policy_id=policy_id,
            decision_id=decision_id,
            actor_hash=actor_hash,
            actor_role=actor_role,
            details=clean_details,
            previous_event_hash=previous_event_hash,
            event_hash=event_hash,
            sequence_no=sequence_no,
            chain_id=chain_id,
            created_at=created_at or datetime.now(timezone.utc),
        )
    except PrivacySensitiveDataError:
        raise
    except (ValueError, TypeError) as exc:
        logger.error("Audit event failed ORM validation")
        raise AuditEventValidationError("Audit event is not persistable") from None


def persist_audit_event(
    db: Session,
    *,
    event_uuid: str,
    event_type: Union[MitigationAuditEventType, str],
    entity_type: Union[MitigationAuditEntityType, str],
    entity_identifier: str,
    event_hash: str,
    chain_id: str,
    sequence_no: int,
    policy_id: Optional[int] = None,
    decision_id: Optional[int] = None,
    actor_hash: Optional[str] = None,
    actor_role: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    previous_event_hash: Optional[str] = None,
    created_at: Optional[datetime] = None,
) -> AuditEventPersistenceResult:
    """Persist one caller-validated audit event idempotently by ``event_uuid``.

    All caller input is validated before the session transaction is touched. A
    repeated ``event_uuid`` returns the existing row with ``created=False`` and
    never mutates it. A duplicate ``(chain_id, sequence_no)`` belonging to another
    event is rejected; the service does not allocate sequence numbers or compute
    hashes.
    """
    if not isinstance(db, Session):
        raise AuditEventPersistenceError("A SQLAlchemy Session is required")

    clean_uuid = _validate_event_uuid(event_uuid)
    # Building the transient ORM record runs every ORM validator and privacy check
    # before any database operation is attempted.
    record = _build_record(
        event_uuid=clean_uuid,
        event_type=event_type,
        entity_type=entity_type,
        entity_identifier=entity_identifier,
        event_hash=event_hash,
        chain_id=chain_id,
        sequence_no=sequence_no,
        policy_id=policy_id,
        decision_id=decision_id,
        actor_hash=actor_hash,
        actor_role=actor_role,
        details=details,
        previous_event_hash=previous_event_hash,
        created_at=created_at,
    )

    ensure_outer_transaction_safely(
        db,
        error_type=AuditEventPersistenceError,
        operation="Audit transaction setup",
    )

    try:
        existing = _find_existing(db, clean_uuid)
    except SQLAlchemyError as exc:
        logger.error("Existing audit event lookup failed (%s)", type(exc).__name__)
        raise AuditEventPersistenceError("Existing audit event could not be read") from None
    if existing is not None:
        return AuditEventPersistenceResult(event=existing, created=False)

    try:
        with db.begin_nested():
            db.add(record)
            db.flush()
    except IntegrityError:
        existing = _find_existing(db, clean_uuid)
        if existing is not None:
            return AuditEventPersistenceResult(event=existing, created=False)
        logger.error("Audit event insert violated a database constraint")
        raise AuditEventPersistenceError(
            "Audit event insert violated a database constraint"
        ) from None
    except SQLAlchemyError as exc:
        logger.error("Audit event insert failed (%s)", type(exc).__name__)
        raise AuditEventPersistenceError("Audit event could not be persisted") from None

    return AuditEventPersistenceResult(event=record, created=True)
