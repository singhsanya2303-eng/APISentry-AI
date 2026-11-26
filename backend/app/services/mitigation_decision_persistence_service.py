"""Persistence for already-evaluated Stage 2B advisory decisions.

Transaction boundary: the caller owns the SQLAlchemy session. This module only
flushes inside a nested savepoint and never commits or rolls back the outer
transaction. An equivalent retry resolves deterministically to the existing row;
a conflicting UUID or material payload is rejected and an existing row is never
overwritten. No evaluation, enforcement, or blocking behaviour lives here.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import logging
import re
from typing import Any, NamedTuple, Optional, Union
import uuid

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.mitigation import MitigationDecision
from app.schemas.mitigation import MitigationDecision as EvaluatedDecision
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    DecisionPolicyNotFoundError,
    DecisionPersistenceError,
    DecisionValidationError,
    DuplicateDecisionConflictError,
    PrivacySensitiveDataError,
    ensure_outer_transaction_safely,
    reject_raw_privacy_text,
    reject_sensitive_fields,
)
from app.services.mitigation_policy_persistence_service import load_policy_by_version

logger = logging.getLogger("apisentry.persistence.mitigation.decision")

_DEDUPE_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DECISION_UUID_NAMESPACE = uuid.NAMESPACE_URL
# Preflight ORM construction uses a neutral placeholder. No row is added to the
# session until the real policy id has been resolved from the database.
_PREFLIGHT_POLICY_ID = 1


class DecisionPersistenceResult(NamedTuple):
    """The persisted or idempotently reused decision and whether it was created."""

    decision: MitigationDecision
    created: bool


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _validate_dedupe_key(dedupe_key: Any) -> str:
    if not isinstance(dedupe_key, str) or not _DEDUPE_KEY_RE.fullmatch(dedupe_key):
        raise DecisionValidationError("dedupe_key must be an opaque token")
    reject_raw_privacy_text(
        dedupe_key,
        field_name="dedupe_key",
        error_type=DecisionValidationError,
    )
    return dedupe_key


def _validate_decision_uuid(decision_uuid: Any) -> str:
    if not isinstance(decision_uuid, str) or not _UUID5_RE.fullmatch(decision_uuid):
        raise DecisionValidationError("decision_uuid must be a lowercase UUID5")
    return decision_uuid


def _validate_created_at(created_at: Any) -> Optional[datetime]:
    """Validate caller-supplied creation time before touching the session."""
    if created_at is not None and not isinstance(created_at, datetime):
        raise DecisionValidationError("created_at must be a datetime")
    return created_at


def _validate_policy_version(policy_version: Any) -> str:
    """Validate the accepted Stage 2B policy-version format before any DB access.

    The stored-policy service repeats this check during lookup; doing it here too
    ensures an invalid caller value is rejected before a transaction is opened.
    """
    if not isinstance(policy_version, str) or not 1 <= len(policy_version) <= 64:
        raise DecisionValidationError("policy_version must be a string of 1 to 64 characters")
    reject_raw_privacy_text(
        policy_version,
        field_name="policy_version",
        error_type=DecisionValidationError,
    )
    return policy_version


def _derive_decision_uuid(policy_version: str, dedupe_key: str) -> str:
    """Derive a stable opaque UUID5 so retries cannot create duplicate rows."""
    identity = f"apisentry:mitigation-decision:v1:{policy_version}:{dedupe_key}"
    return str(uuid.uuid5(_DECISION_UUID_NAMESPACE, identity))


def _as_utc_compare(value: Optional[datetime]) -> Optional[datetime]:
    """Normalize timestamps for identity comparison without mutating inputs."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _identity_tuple(
    decision: EvaluatedDecision, dedupe_key: str, policy_id: int
) -> tuple[Any, ...]:
    """Material fields that define decision identity for idempotency.

    ``decision_uuid`` is compared separately so an explicit UUID conflict is
    never hidden by a matching dedupe key. The ORM row stores the immutable
    policy primary key rather than a version string; that key is the persisted
    representation of the policy version identity.
    """
    return (
        _enum_value(decision.decision),
        _enum_value(decision.scope_type),
        decision.scope_key_hash,
        _enum_value(decision.attribution_status),
        bool(decision.verified_attribution),
        tuple(_enum_value(code) for code in decision.reason_codes),
        decision.explanation,
        policy_id,
        tuple(str(ref) for ref in decision.evidence_references),
        _as_utc_compare(decision.issued_at),
        _as_utc_compare(decision.expires_at),
        decision.rate_limit,
        decision.rate_limit_window_seconds,
        bool(decision.advisory_only),
        dedupe_key,
    )


def _stored_identity_tuple(record: MitigationDecision) -> tuple[Any, ...]:
    """Read the same identity fields back from a persisted ORM row."""
    return (
        _enum_value(record.decision_type),
        _enum_value(record.scope_type),
        record.scope_key_hash,
        _enum_value(record.attribution_status),
        bool(record.verified_attribution),
        tuple(_enum_value(code) for code in record.reason_codes),
        record.explanation,
        record.policy_id,
        tuple(str(ref) for ref in record.evidence_references),
        _as_utc_compare(record.issued_at),
        _as_utc_compare(record.expires_at),
        record.rate_limit,
        record.rate_limit_window_seconds,
        bool(record.advisory_only),
        record.dedupe_key,
    )


def _resolve_existing(
    *,
    by_dedupe: Optional[MitigationDecision],
    by_uuid: Optional[MitigationDecision],
    decision: EvaluatedDecision,
    dedupe_key: str,
    expected_uuid: str,
    policy_id: int,
) -> Optional[DecisionPersistenceResult]:
    """Resolve existing rows without hiding UUID or payload conflicts."""
    if by_uuid is not None and (by_dedupe is None or by_uuid.id != by_dedupe.id):
        raise DuplicateDecisionConflictError(
            "decision_uuid is already associated with another decision"
        )
    if by_dedupe is None:
        return None
    if by_dedupe.decision_uuid != expected_uuid:
        raise DuplicateDecisionConflictError(
            "decision_uuid conflicts with the existing dedupe key"
        )
    if _stored_identity_tuple(by_dedupe) != _identity_tuple(
        decision, dedupe_key, policy_id
    ):
        raise DuplicateDecisionConflictError(
            "dedupe_key is already associated with a different decision identity"
        )
    return DecisionPersistenceResult(decision=by_dedupe, created=False)


def _validate_evaluated_decision(
    decision: Union[EvaluatedDecision, Mapping[str, Any]],
) -> EvaluatedDecision:
    reject_sensitive_fields(decision, context="decision input")
    try:
        validated = EvaluatedDecision.model_validate(decision)
    except ValidationError as exc:
        logger.error("Stage 2B decision input failed schema validation")
        raise DecisionValidationError("Evaluated decision is not schema-valid") from None

    if validated.advisory_only is not True:
        raise DecisionValidationError("advisory_only must remain True")
    reject_raw_privacy_text(
        validated.explanation,
        field_name="explanation",
        error_type=DecisionValidationError,
    )
    for reference in validated.evidence_references:
        reject_raw_privacy_text(
            str(reference),
            field_name="evidence_reference",
            error_type=DecisionValidationError,
        )
    return validated


def _find_existing(
    db: Session, *, dedupe_key: str, decision_uuid: str
) -> tuple[Optional[MitigationDecision], Optional[MitigationDecision]]:
    """Bounded lookups of both unique decision keys."""
    try:
        by_dedupe = (
            db.query(MitigationDecision)
            .filter(MitigationDecision.dedupe_key == dedupe_key)
            .first()
        )
        by_uuid = (
            db.query(MitigationDecision)
            .filter(MitigationDecision.decision_uuid == decision_uuid)
            .first()
        )
    except SQLAlchemyError as exc:
        logger.error("Existing decision lookup failed (%s)", type(exc).__name__)
        raise DecisionPersistenceError("Existing decision could not be read") from None
    return by_dedupe, by_uuid


def _find_existing_safely(
    db: Session, *, dedupe_key: str, decision_uuid: str
) -> tuple[Optional[MitigationDecision], Optional[MitigationDecision]]:
    """Guard external/fault-injected lookup failures with safe diagnostics."""
    try:
        return _find_existing(
            db, dedupe_key=dedupe_key, decision_uuid=decision_uuid
        )
    except SQLAlchemyError as exc:
        logger.error("Existing decision lookup failed (%s)", type(exc).__name__)
        raise DecisionPersistenceError("Existing decision could not be read") from None


def _build_record(
    *,
    decision: EvaluatedDecision,
    policy_id: int,
    decision_uuid: str,
    dedupe_key: str,
    created_at: Optional[datetime],
) -> MitigationDecision:
    try:
        return MitigationDecision(
            decision_uuid=decision_uuid,
            decision_type=_enum_value(decision.decision),
            scope_type=_enum_value(decision.scope_type),
            scope_key_hash=decision.scope_key_hash,
            attribution_status=_enum_value(decision.attribution_status),
            verified_attribution=decision.verified_attribution,
            reason_codes=[_enum_value(code) for code in decision.reason_codes],
            explanation=decision.explanation,
            policy_id=policy_id,
            evidence_references=[str(ref) for ref in decision.evidence_references],
            issued_at=decision.issued_at,
            expires_at=decision.expires_at,
            rate_limit=decision.rate_limit,
            rate_limit_window_seconds=decision.rate_limit_window_seconds,
            advisory_only=True,
            dedupe_key=dedupe_key,
            created_at=created_at or datetime.now(timezone.utc),
        )
    except (ValueError, TypeError) as exc:
        logger.error("Evaluated decision failed ORM validation")
        raise DecisionValidationError("Evaluated decision is not persistable") from None


def persist_evaluated_decision(
    db: Session,
    decision: Union[EvaluatedDecision, Mapping[str, Any]],
    *,
    dedupe_key: str,
    decision_uuid: Optional[str] = None,
    created_at: Optional[datetime] = None,
) -> DecisionPersistenceResult:
    """Persist an already-evaluated advisory decision idempotently.

    Identity contract: a decision is identified by ``dedupe_key`` plus
    ``decision_uuid`` (explicit or derived from policy version and dedupe key).
    An existing row is returned only when the UUID and all material decision
    fields are equivalent. A conflicting UUID or different policy version/payload
    raises :class:`DuplicateDecisionConflictError`; no existing row is overwritten.
    Unique database indexes remain the final race guard.
    """
    if not isinstance(db, Session):
        raise DecisionPersistenceError("A SQLAlchemy Session is required")

    # Pure caller-input validation: everything in this block runs before the
    # session is touched, including all ORM field validators below.
    validated = _validate_evaluated_decision(decision)
    policy_version = _validate_policy_version(validated.policy_version)
    key = _validate_dedupe_key(dedupe_key)
    requested_uuid = (
        _validate_decision_uuid(decision_uuid) if decision_uuid is not None else None
    )
    clean_created_at = _validate_created_at(created_at)
    final_uuid = requested_uuid or _derive_decision_uuid(policy_version, key)

    # Construct the transient row before transaction setup so every ORM validator
    # can reject bad caller input first. The neutral policy id is replaced with
    # the stored value only after the database-dependent checks below succeed.
    record = _build_record(
        decision=validated,
        policy_id=_PREFLIGHT_POLICY_ID,
        decision_uuid=final_uuid,
        dedupe_key=key,
        created_at=clean_created_at,
    )

    ensure_outer_transaction_safely(
        db,
        error_type=DecisionPersistenceError,
        operation="Decision transaction setup",
    )

    # Database-dependent validation starts here: exact stored policy identity,
    # unique-key lookup, and database constraints enforced at flush time.
    try:
        policy = load_policy_by_version(db, policy_version)
    except ActivePolicyNotFoundError as exc:
        raise DecisionPolicyNotFoundError(
            "Decision policy version could not be resolved"
        ) from None
    except PrivacySensitiveDataError:
        raise
    except Exception as exc:
        logger.error("Decision policy resolution failed (%s)", type(exc).__name__)
        raise DecisionValidationError("Decision policy version could not be resolved") from None

    # The preflight record already passed every ORM validator; only the real
    # persisted policy identity remains to be attached before any write.
    record.policy_id = policy.id

    by_dedupe, by_uuid = _find_existing_safely(
        db, dedupe_key=key, decision_uuid=final_uuid
    )
    existing = _resolve_existing(
        by_dedupe=by_dedupe,
        by_uuid=by_uuid,
        decision=validated,
        dedupe_key=key,
        expected_uuid=final_uuid,
        policy_id=policy.id,
    )
    if existing is not None:
        return existing

    try:
        with db.begin_nested():
            db.add(record)
            db.flush()
    except IntegrityError:
        by_dedupe, by_uuid = _find_existing_safely(
            db, dedupe_key=key, decision_uuid=final_uuid
        )
        existing = _resolve_existing(
            by_dedupe=by_dedupe,
            by_uuid=by_uuid,
            decision=validated,
            dedupe_key=key,
            expected_uuid=final_uuid,
            policy_id=policy.id,
        )
        if existing is not None:
            return existing
        logger.error("Decision insert violated a database constraint")
        raise DecisionPersistenceError("Decision insert violated a database constraint") from None
    except SQLAlchemyError as exc:
        logger.error("Decision insert failed (%s)", type(exc).__name__)
        raise DecisionPersistenceError("Decision could not be persisted") from None

    return DecisionPersistenceResult(decision=record, created=True)
