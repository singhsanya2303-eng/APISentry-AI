"""Pure C1 integration from persisted mitigation decisions to audit events.

This module plans and persists exactly one ``DECISION_ISSUED`` audit event for each
eligible Stage A outcome. It uses only the persisted decision row, its policy row,
and an optional already-validated verified principal. No request data is read and
no route is wired in this phase.

Transaction boundary: the caller owns the SQLAlchemy session. This module adds no
``commit()`` or ``rollback()`` call; accepted persistence code flushes inside a
nested savepoint only.

Integrity boundary: ``event_hash`` is a deterministic *content digest* over an
explicit allowlist. It is not a tamper-evident or tamper-proof hash chain value.
``chain_id``, ``sequence_no``, and ``previous_event_hash`` are fixed metadata and
are deliberately excluded from the digest; no chain continuity is verified.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import re
from typing import Any, Optional
import uuid

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.mitigation import (
    MitigationAuditEntityType,
    MitigationAuditEventType,
    MitigationDecision as PersistedDecision,
    MitigationPolicy as PersistedPolicy,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision as EvaluatedDecision,
    MitigationDecisionType,
    MitigationReasonCode,
    MitigationScopeType,
)
from app.schemas.mitigation_audit_integration import (
    DecisionAuditEventPlan,
    MitigationAuditEventOutcome,
    MitigationAuditEventStatus,
    MitigationAuditIntegrationResult,
)
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationIntegrationResult,
    MitigationOutcomeStatus,
    VerifiedMitigationPrincipal,
)
from app.services.mitigation_audit_persistence_service import (
    AuditEventPersistenceResult,
    persist_audit_event,
)
from app.services.mitigation_persistence_common import (
    AuditEventPersistenceError,
    AuditEventValidationError,
    MitigationPersistenceError,
    PrivacySensitiveDataError,
    reject_raw_privacy_text,
    reject_sensitive_fields,
)

logger = logging.getLogger("apisentry.services.mitigation.audit_integration")

_EVENT_TYPE = MitigationAuditEventType.DECISION_ISSUED.value
_ENTITY_TYPE = MitigationAuditEntityType.DECISION.value
_DIGEST_DOMAIN = "apisentry.mitigation.audit.decision_issued.v1"
_UUID_DOMAIN = "apisentry:mitigation-audit-event:v1"
_UUID_NAMESPACE = uuid.NAMESPACE_URL
_HASH_PREFIX = "sha256:"
_UUID5_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
_ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ELIGIBLE_OUTCOMES = frozenset(
    {MitigationOutcomeStatus.PERSISTED, MitigationOutcomeStatus.IDEMPOTENT_REUSE}
)
_VERIFIED_AUDIT_ROLES = frozenset({"admin", "analyst"})

# The only detail keys this integration may ever construct. This is a strict
# subset of the accepted model allowlist; no caller-supplied detail is accepted.
_DETAIL_KEYS = frozenset(
    {
        "policy_version",
        "decision_type",
        "scope_type",
        "attribution_status",
        "evidence_reference_count",
        "advisory_only",
    }
)

# Every key that contributes to the content digest, in a documented versioned
# schema. ``MitigationAuditEvent.id``, ``chain_id``, ``sequence_no``, and
# ``previous_event_hash`` are intentionally absent. ``decision_id`` and
# ``policy_id`` are stable persisted entity identifiers, not audit row IDs.
_CONTENT_KEYS = (
    "domain",
    "event_type",
    "entity_type",
    "entity_identifier",
    "decision_id",
    "policy_id",
    "policy_version",
    "decision_type",
    "scope_type",
    "scope_key_hash",
    "attribution_status",
    "verified_attribution",
    "actor_hash",
    "actor_role",
    "reason_codes",
    "evidence_references",
    "issued_at",
    "created_at",
    "advisory_only",
    "details",
)


class MitigationAuditIntegrationError(MitigationPersistenceError):
    """Base class for safe C1 audit-integration failures."""


class MitigationAuditValidationError(MitigationAuditIntegrationError):
    """Input or persisted state is incomplete or not safely allowlisted."""


class MitigationAuditConflictError(MitigationAuditIntegrationError):
    """An existing audit event UUID is associated with different content."""


class MitigationAuditPersistenceFailure(MitigationAuditIntegrationError):
    """Accepted persistence code could not complete an audit write."""


def _ensure_utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise MitigationAuditValidationError("timestamp must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _enum_value(value: Any, enum_type: type[Enum], field_name: str) -> str:
    raw = value.value if isinstance(value, Enum) else value
    try:
        return enum_type(raw).value  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise MitigationAuditValidationError(
            f"{field_name} is not an allowed value"
        ) from None


def _validate_uuid5(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _UUID5_PATTERN.fullmatch(value):
        raise MitigationAuditValidationError(f"{field_name} must be a lowercase UUID5")
    return value


def _validate_sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise MitigationAuditValidationError(f"{field_name} must be a validated hash")
    return value


def _validate_opaque_token(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_TOKEN_PATTERN.fullmatch(value):
        raise MitigationAuditValidationError(f"{field_name} must be an opaque token")
    reject_raw_privacy_text(
        value,
        field_name=field_name,
        error_type=MitigationAuditValidationError,
    )
    return value


def _validate_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise MitigationAuditValidationError(f"{field_name} must be a positive integer")
    return value


def _validate_reason_codes(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise MitigationAuditValidationError("reason_codes must be a sequence")
    codes: set[str] = set()
    for item in value:
        code = _enum_value(item, MitigationReasonCode, "reason_code")
        codes.add(code)
    return sorted(codes)


def _validate_evidence_references(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise MitigationAuditValidationError("evidence_references must be a sequence")
    references: set[str] = set()
    for item in value:
        references.add(_validate_uuid5(item, "evidence_reference"))
    return sorted(references)


def _validate_details(value: Mapping[str, Any]) -> dict[str, str | int | bool]:
    """Validate a locally constructed, short-scalar, allowlisted details object."""
    reject_sensitive_fields(value, context="audit detail fields")
    cleaned: dict[str, str | int | bool] = {}
    for name, item in value.items():
        if name not in _DETAIL_KEYS:
            raise MitigationAuditValidationError(
                "audit details contain a key that is not allowlisted"
            )
        if isinstance(item, str):
            if len(item) > 128:
                raise MitigationAuditValidationError(
                    "audit detail values must be short scalars"
                )
            reject_raw_privacy_text(
                item,
                field_name="audit detail value",
                error_type=MitigationAuditValidationError,
            )
            cleaned[name] = item
        elif isinstance(item, bool):
            cleaned[name] = item
        elif isinstance(item, int):
            cleaned[name] = item
        else:
            raise MitigationAuditValidationError(
                "audit detail values must be short scalars"
            )
    return dict(sorted(cleaned.items()))


def _canonical_content(content: Mapping[str, Any]) -> dict[str, Any]:
    """Return only versioned allowlisted content keys in deterministic form.

    Unknown keys are deliberately ignored. In particular, chain metadata passed
    by a caller can never become part of the content digest.
    """
    clean: dict[str, Any] = {}
    for key in _CONTENT_KEYS:
        if key not in content:
            raise MitigationAuditValidationError(
                "audit content is missing a required field"
            )
        clean[key] = content[key]
    return clean


def _content_digest(content: Mapping[str, Any]) -> str:
    """Return a SHA-256 content descriptor over canonical UTF-8 JSON."""
    payload = json.dumps(
        _canonical_content(content),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _event_uuid(digest_hex: str) -> str:
    """Derive a lowercase UUID5 from the content digest and a dedicated domain."""
    return str(uuid.uuid5(_UUID_NAMESPACE, f"{_UUID_DOMAIN}:{digest_hex}"))


def _validate_authentication_context(
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal],
) -> None:
    if not isinstance(authentication_mode, MitigationAuthenticationMode):
        raise MitigationAuditValidationError("authentication_mode is invalid")
    if _is_api_key(authentication_mode):
        if verified_principal is not None:
            raise MitigationAuditValidationError(
                "API-key audit events cannot carry a verified principal"
            )
        return
    if verified_principal is None:
        raise MitigationAuditValidationError(
            "verified JWT audit events require a verified principal"
        )
    if not isinstance(verified_principal, VerifiedMitigationPrincipal):
        raise MitigationAuditValidationError("verified_principal is invalid")
    if verified_principal.role not in _VERIFIED_AUDIT_ROLES:
        raise MitigationAuditValidationError(
            "verified principal role is not eligible for audit attribution"
        )


def _is_api_key(authentication_mode: MitigationAuthenticationMode) -> bool:
    """Return whether the trusted caller supplied API-key authentication."""
    return authentication_mode == MitigationAuthenticationMode.API_KEY


def _resolve_actor(
    *,
    decision: PersistedDecision,
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal],
) -> tuple[Optional[str], Optional[str]]:
    """Resolve actor attribution only from a verified principal object."""
    attribution_status = _enum_value(
        decision.attribution_status,
        MitigationAttributionStatus,
        "attribution_status",
    )

    if _is_api_key(authentication_mode):
        if attribution_status != MitigationAttributionStatus.MISSING.value:
            raise MitigationAuditValidationError(
                "API-key audit event has unexpected attribution status"
            )
        if decision.verified_attribution is not False or decision.scope_key_hash is not None:
            raise MitigationAuditValidationError(
                "API-key audit event has unexpected identity data"
            )
        return None, None

    if attribution_status != MitigationAttributionStatus.VERIFIED_USER.value:
        raise MitigationAuditValidationError(
            "verified principal audit event has unexpected attribution status"
        )
    if decision.verified_attribution is not True:
        raise MitigationAuditValidationError(
            "verified principal audit event is not verified"
        )
    actor_hash = _validate_sha256(
        verified_principal.actor_key_hash, "actor_key_hash"
    ) if verified_principal is not None else None
    if actor_hash is None or decision.scope_key_hash != actor_hash:
        raise MitigationAuditValidationError(
            "verified principal does not match the persisted scope hash"
        )
    role = verified_principal.role if verified_principal is not None else None
    if role not in _VERIFIED_AUDIT_ROLES:
        raise MitigationAuditValidationError("actor_role is not eligible")
    return actor_hash, role


def build_decision_audit_event_plan(
    *,
    decision: PersistedDecision,
    policy: PersistedPolicy,
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal] = None,
) -> DecisionAuditEventPlan:
    """Build one fully allowlisted audit event plan from persisted rows only.

    This builder performs no database access and uses no wall-clock time or random
    identifiers. Adding chain metadata to a content dictionary cannot change the
    resulting digest.
    """
    _validate_authentication_context(authentication_mode, verified_principal)

    decision_uuid = _validate_uuid5(decision.decision_uuid, "decision_uuid")
    decision_id = _validate_positive_int(decision.id, "decision_id")
    policy_id = _validate_positive_int(policy.id, "policy_id")
    policy_version = _validate_opaque_token(policy.policy_version, "policy_version")
    decision_type = _enum_value(decision.decision_type, MitigationDecisionType, "decision_type")
    scope_type = _enum_value(decision.scope_type, MitigationScopeType, "scope_type")
    attribution_status = _enum_value(
        decision.attribution_status,
        MitigationAttributionStatus,
        "attribution_status",
    )
    verified_attribution = decision.verified_attribution
    if not isinstance(verified_attribution, bool):
        raise MitigationAuditValidationError(
            "verified_attribution must be a boolean"
        )
    reason_codes = _validate_reason_codes(decision.reason_codes)
    evidence_references = _validate_evidence_references(decision.evidence_references)
    if decision.advisory_only is not True:
        raise MitigationAuditValidationError("decision is not advisory-only")
    issued_at = _ensure_utc(decision.issued_at)
    created_at = issued_at

    scope_key_hash = (
        _validate_sha256(decision.scope_key_hash, "scope_key_hash")
        if decision.scope_key_hash is not None
        else None
    )
    actor_hash, actor_role = _resolve_actor(
        decision=decision,
        authentication_mode=authentication_mode,
        verified_principal=verified_principal,
    )

    details = _validate_details(
        {
            "policy_version": policy_version,
            "decision_type": decision_type,
            "scope_type": scope_type,
            "attribution_status": attribution_status,
            "evidence_reference_count": len(evidence_references),
            "advisory_only": True,
        }
    )

    content = {
        "domain": _DIGEST_DOMAIN,
        "event_type": _EVENT_TYPE,
        "entity_type": _ENTITY_TYPE,
        "entity_identifier": decision_uuid,
        "decision_id": decision_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "decision_type": decision_type,
        "scope_type": scope_type,
        "scope_key_hash": scope_key_hash,
        "attribution_status": attribution_status,
        "verified_attribution": verified_attribution,
        "actor_hash": actor_hash,
        "actor_role": actor_role,
        "reason_codes": reason_codes,
        "evidence_references": evidence_references,
        "issued_at": issued_at.isoformat(),
        "created_at": created_at.isoformat(),
        "advisory_only": True,
        "details": details,
    }
    digest_hex = _content_digest(content)
    chain_id = _validate_opaque_token(f"decision-{decision_uuid}", "chain_id")

    try:
        return DecisionAuditEventPlan(
            event_uuid=_event_uuid(digest_hex),
            event_type=_EVENT_TYPE,  # type: ignore[arg-type]
            entity_type=_ENTITY_TYPE,  # type: ignore[arg-type]
            entity_identifier=decision_uuid,
            event_hash=f"{_HASH_PREFIX}{digest_hex}",
            chain_id=chain_id,
            sequence_no=1,
            previous_event_hash=None,
            policy_id=policy_id,
            decision_id=decision_id,
            actor_hash=actor_hash,
            actor_role=actor_role,
            details=details,
            created_at=created_at,
        )
    except ValidationError:
        logger.error("Decision audit event plan failed schema validation")
        raise MitigationAuditValidationError(
            "Decision audit event plan is not valid"
        ) from None


def _load_decision_and_policy(
    db: Session, decision_uuid: str
) -> tuple[PersistedDecision, PersistedPolicy]:
    """Resolve the persisted decision and its policy using read-only lookups."""
    try:
        decision = (
            db.query(PersistedDecision)
            .filter(PersistedDecision.decision_uuid == decision_uuid)
            .one_or_none()
        )
        if decision is None:
            raise MitigationAuditValidationError(
                "Outcomes reference an unknown persisted decision"
            )
        policy = (
            db.query(PersistedPolicy)
            .filter(PersistedPolicy.id == decision.policy_id)
            .one_or_none()
        )
        if policy is None:
            raise MitigationAuditValidationError(
                "Persisted decision policy could not be resolved"
            )
    except SQLAlchemyError as exc:
        logger.error("Persisted decision lookup failed (%s)", type(exc).__name__)
        raise MitigationAuditPersistenceFailure(
            "Persisted decision could not be read safely"
        ) from None
    return decision, policy


def _validate_outcome_decision(
    outcome: Any,
    *,
    decision: PersistedDecision,
    policy: PersistedPolicy,
    decision_uuid: str,
) -> None:
    """Check that the Stage A outcome agrees with the persisted row."""
    if not isinstance(outcome.decision, EvaluatedDecision):
        raise MitigationAuditValidationError(
            "Eligible outcome has no evaluated decision"
        )
    if outcome.advisory_only is not True or outcome.decision.advisory_only is not True:
        raise MitigationAuditValidationError("Outcome is not advisory-only")

    reject_raw_privacy_text(
        outcome.decision.explanation,
        field_name="decision explanation",
        error_type=MitigationAuditValidationError,
    )

    if _enum_value(decision.decision_type, MitigationDecisionType, "decision_type") != _enum_value(
        outcome.decision.decision, MitigationDecisionType, "decision_type"
    ):
        raise MitigationAuditValidationError(
            "Outcome decision type does not match persisted decision"
        )
    if _enum_value(decision.scope_type, MitigationScopeType, "scope_type") != _enum_value(
        outcome.decision.scope_type, MitigationScopeType, "scope_type"
    ):
        raise MitigationAuditValidationError(
            "Outcome scope type does not match persisted decision"
        )
    if _enum_value(
        decision.attribution_status, MitigationAttributionStatus, "attribution_status"
    ) != _enum_value(
        outcome.decision.attribution_status,
        MitigationAttributionStatus,
        "attribution_status",
    ):
        raise MitigationAuditValidationError(
            "Outcome attribution status does not match persisted decision"
        )
    if decision.verified_attribution is not outcome.decision.verified_attribution:
        raise MitigationAuditValidationError(
            "Outcome attribution verification does not match persisted decision"
        )
    if decision.scope_key_hash != outcome.decision.scope_key_hash:
        raise MitigationAuditValidationError(
            "Outcome scope hash does not match persisted decision"
        )
    if _validate_reason_codes(decision.reason_codes) != _validate_reason_codes(
        outcome.decision.reason_codes
    ):
        raise MitigationAuditValidationError(
            "Outcome reason codes do not match persisted decision"
        )
    if _validate_evidence_references(decision.evidence_references) != _validate_evidence_references(
        outcome.decision.evidence_references
    ):
        raise MitigationAuditValidationError(
            "Outcome evidence references do not match persisted decision"
        )
    if _ensure_utc(decision.issued_at) != _ensure_utc(outcome.decision.issued_at):
        raise MitigationAuditValidationError(
            "Outcome timestamp does not match persisted decision"
        )
    if policy.policy_version != _validate_opaque_token(
        outcome.decision.policy_version, "policy_version"
    ):
        raise MitigationAuditValidationError(
            "Outcome policy version does not match persisted policy"
        )
    if decision.decision_uuid != decision_uuid:
        raise MitigationAuditValidationError(
            "Persisted decision UUID does not match outcome"
        )


def _persist_plan(db: Session, plan: DecisionAuditEventPlan) -> AuditEventPersistenceResult:
    """Delegate persistence to the accepted service without owning the transaction."""
    try:
        return persist_audit_event(db, **plan.to_persistence_kwargs())
    except (
        AuditEventValidationError,
        AuditEventPersistenceError,
        PrivacySensitiveDataError,
    ) as exc:
        logger.error("Decision audit event persistence failed (%s)", type(exc).__name__)
        raise MitigationAuditPersistenceFailure(
            "Decision audit event could not be persisted safely"
        ) from None


def persist_decision_audit_events(
    db: Session,
    integration_result: MitigationIntegrationResult,
    *,
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal] = None,
) -> MitigationAuditIntegrationResult:
    """Plan and persist one audit event per eligible Stage A decision outcome.

    Non-persisted outcomes are skipped. Reused event UUIDs with an identical
    content digest are safe idempotent reuse; a different stored digest raises a
    safe conflict and never overwrites the existing row. This function never
    commits or rolls back the caller-owned transaction and never changes the
    Stage B response contract because it is not wired into any route in C1.
    """
    if not isinstance(db, Session):
        raise MitigationAuditValidationError("A SQLAlchemy Session is required")
    if not isinstance(integration_result, MitigationIntegrationResult):
        raise MitigationAuditValidationError("Stage A integration result is invalid")
    _validate_authentication_context(authentication_mode, verified_principal)

    outcomes: list[MitigationAuditEventOutcome] = []
    for outcome in integration_result.outcomes:
        if outcome.status not in _ELIGIBLE_OUTCOMES:
            outcomes.append(
                MitigationAuditEventOutcome(
                    result_index=outcome.result_index,
                    decision_uuid=None,
                    event_uuid=None,
                    status=MitigationAuditEventStatus.SKIPPED,
                    created=False,
                )
            )
            continue

        decision_uuid = _validate_uuid5(outcome.decision_uuid, "decision_uuid")
        decision, policy = _load_decision_and_policy(db, decision_uuid)
        _validate_outcome_decision(
            outcome,
            decision=decision,
            policy=policy,
            decision_uuid=decision_uuid,
        )
        plan = build_decision_audit_event_plan(
            decision=decision,
            policy=policy,
            authentication_mode=authentication_mode,
            verified_principal=verified_principal,
        )
        persisted = _persist_plan(db, plan)
        if not persisted.created and persisted.event.event_hash != plan.event_hash:
            logger.error("Decision audit event UUID conflicts with stored content")
            raise MitigationAuditConflictError(
                "Audit event UUID is already associated with different content"
            )

        outcomes.append(
            MitigationAuditEventOutcome(
                result_index=outcome.result_index,
                decision_uuid=decision_uuid,
                event_uuid=plan.event_uuid,
                status=(
                    MitigationAuditEventStatus.CREATED
                    if persisted.created
                    else MitigationAuditEventStatus.IDEMPOTENT_REUSE
                ),
                created=bool(persisted.created),
            )
        )

    event_count = sum(
        1
        for item in outcomes
        if item.status
        in {MitigationAuditEventStatus.CREATED, MitigationAuditEventStatus.IDEMPOTENT_REUSE}
    )
    skipped_count = sum(
        1 for item in outcomes if item.status == MitigationAuditEventStatus.SKIPPED
    )
    return MitigationAuditIntegrationResult(
        outcomes=outcomes,
        event_count=event_count,
        skipped_count=skipped_count,
    )


__all__ = [
    "MitigationAuditConflictError",
    "MitigationAuditIntegrationError",
    "MitigationAuditPersistenceFailure",
    "MitigationAuditValidationError",
    "build_decision_audit_event_plan",
    "persist_decision_audit_events",
]
