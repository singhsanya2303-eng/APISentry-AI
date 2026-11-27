"""Pure Stage A mitigation orchestration.

This module loads the accepted active policy, builds privacy-safe Stage 2B
context from verified server-side information, evaluates each Stage 1 result with
the accepted policy engine, and persists advisory decisions with the accepted
persistence service.

Boundaries:
  - No default or fallback policy is ever substituted.
  - The caller owns the outer SQLAlchemy transaction; this module never commits
    or rolls it back.
  - No audit events, hashes, chain metadata, routes, or enforcement are present.
  - Expected failures become explicit safe statuses; unexpected programming
    errors propagate.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Optional

from sqlalchemy.orm import Session

from app.schemas.bot_detection import BotAnalysisResult, BotDetectionResponse
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision,
    MitigationRequestContext,
    MitigationScopeType,
)
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationDecisionOutcome,
    MitigationIntegrationResult,
    MitigationOutcomeStatus,
    VerifiedMitigationPrincipal,
)
from app.services.mitigation_decision_persistence_service import (
    persist_evaluated_decision,
)
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    DecisionPersistenceError,
    DecisionValidationError,
    DuplicateDecisionConflictError,
    PolicyConfigurationError,
    PolicyVersionMismatchError,
    PrivacySensitiveDataError,
    reject_raw_privacy_text,
)
from app.services.mitigation_policy_persistence_service import load_active_policy
from app.services.mitigation_policy_service import evaluate_mitigation_decision

logger = logging.getLogger("apisentry.services.mitigation.integration")

_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_OPAQUE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_ROUTE_CLASS_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,99}")
_MAX_DEDUPE_REFERENCES = 25
_DEDUPE_DOMAIN = "apisentry.mitigation.stage-a.v1"


class MitigationIntegrationValidationError(RuntimeError):
    """A caller or upstream value cannot be used safely by this module."""


def _ensure_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise MitigationIntegrationValidationError("timestamp must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _evaluation_timestamp(
    detection: BotDetectionResponse, result: BotAnalysisResult
) -> datetime:
    """Return a deterministic UTC timestamp derived from Stage 1 data."""
    for candidate in (result.last_seen, detection.analysis_window_end):
        if candidate is not None:
            return _ensure_utc(candidate)
    raise MitigationIntegrationValidationError(
        "no server-derived evaluation timestamp is available"
    )


def _validate_route_class(route_class: str) -> str:
    if not isinstance(route_class, str) or not _ROUTE_CLASS_RE.fullmatch(route_class):
        raise MitigationIntegrationValidationError("route_class is not an opaque token")
    reject_raw_privacy_text(
        route_class,
        field_name="route_class",
        error_type=MitigationIntegrationValidationError,
    )
    return route_class


def _validate_idempotency_key(idempotency_key: Optional[str]) -> str:
    if idempotency_key is None:
        return "auto"
    if not isinstance(idempotency_key, str) or not _OPAQUE_TOKEN_RE.fullmatch(
        idempotency_key
    ):
        raise MitigationIntegrationValidationError(
            "idempotency_key must be an opaque token"
        )
    reject_raw_privacy_text(
        idempotency_key,
        field_name="idempotency_key",
        error_type=MitigationIntegrationValidationError,
    )
    return idempotency_key


def _validate_policy_version(policy_version: str) -> str:
    if not isinstance(policy_version, str) or not 1 <= len(policy_version) <= 64:
        raise MitigationIntegrationValidationError("policy_version is invalid")
    reject_raw_privacy_text(
        policy_version,
        field_name="policy_version",
        error_type=MitigationIntegrationValidationError,
    )
    return policy_version


def _opaque_evidence_references(result: BotAnalysisResult) -> tuple[str, ...]:
    references: list[str] = []
    for reference in result.evidence_references:
        value = str(getattr(reference, "request_id", reference))
        if not _UUID5_RE.fullmatch(value):
            raise MitigationIntegrationValidationError(
                "evidence reference is not a lowercase UUID5"
            )
        if value not in references:
            references.append(value)
    return tuple(sorted(references)[:_MAX_DEDUPE_REFERENCES])


def _scope_identity(context: MitigationRequestContext) -> tuple[str, str]:
    status = context.attribution_status
    if status is MitigationAttributionStatus.VERIFIED_USER:
        return MitigationScopeType.VERIFIED_USER.value, str(context.actor_key_hash)
    if status is MitigationAttributionStatus.API_KEY_PRINCIPAL:
        return (
            MitigationScopeType.API_KEY_PRINCIPAL.value,
            str(context.api_key_principal_hash),
        )
    if status is MitigationAttributionStatus.NETWORK_IP:
        return MitigationScopeType.NETWORK_IP.value, str(context.network_key_hash)
    return MitigationScopeType.UNATTRIBUTED.value, "none"


def build_dedupe_key(
    *,
    policy_version: str,
    detection: BotDetectionResponse,
    result: BotAnalysisResult,
    context: MitigationRequestContext,
    idempotency_key: Optional[str] = None,
) -> str:
    """Build an opaque, privacy-safe, stable deduplication token.

    The token uses only a validated policy version, verified scope identity,
    opaque Stage 1 evidence references, a server-derived timestamp, and an
    optional opaque idempotency token. Material decision fields are deliberately
    excluded so a reused identity with changed payloads is detected as a
    conflict rather than silently creating a second decision.
    """
    version = _validate_policy_version(policy_version)
    key_seed = _validate_idempotency_key(idempotency_key)
    evaluated_at = _evaluation_timestamp(detection, result)
    scope_type, scope_hash = _scope_identity(context)
    references = _opaque_evidence_references(result)

    material = "\x1f".join(
        (
            _DEDUPE_DOMAIN,
            version,
            scope_type,
            scope_hash,
            evaluated_at.isoformat(),
            key_seed,
            ",".join(references),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"mitigation-{digest}"


def build_mitigation_context(
    *,
    detection: BotDetectionResponse,
    result: BotAnalysisResult,
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal] = None,
    route_class: str = "security_bot_analysis",
) -> MitigationRequestContext:
    """Build Stage 2B context from verified server-side information only.

    API-key authentication is always unattributed. A verified user principal is
    accepted only as a pre-hashed object produced by trusted authentication code;
    raw actor IDs are never inspected here.
    """
    clean_route_class = _validate_route_class(route_class)
    evaluated_at = _evaluation_timestamp(detection, result)
    evidence_complete = not detection.limits.truncated

    if authentication_mode is MitigationAuthenticationMode.API_KEY:
        if verified_principal is not None:
            raise MitigationIntegrationValidationError(
                "API-key authentication cannot supply a verified user principal"
            )
        return MitigationRequestContext(
            evaluated_at=evaluated_at,
            route_class=clean_route_class,
            is_control_plane=False,
            is_admin=False,
            attribution_status=MitigationAttributionStatus.MISSING,
            actor_key_hash=None,
            api_key_principal_hash=None,
            network_key_hash=None,
            inferred_actor_key_hash=None,
            detection_available=True,
            evidence_complete=evidence_complete,
        )

    if verified_principal is not None:
        return MitigationRequestContext(
            evaluated_at=evaluated_at,
            route_class=clean_route_class,
            is_control_plane=False,
            is_admin=verified_principal.role == "admin",
            attribution_status=MitigationAttributionStatus.VERIFIED_USER,
            actor_key_hash=verified_principal.actor_key_hash,
            api_key_principal_hash=None,
            network_key_hash=None,
            inferred_actor_key_hash=None,
            detection_available=True,
            evidence_complete=evidence_complete,
        )

    return MitigationRequestContext(
        evaluated_at=evaluated_at,
        route_class=clean_route_class,
        is_control_plane=False,
        is_admin=False,
        attribution_status=MitigationAttributionStatus.MISSING,
        actor_key_hash=None,
        api_key_principal_hash=None,
        network_key_hash=None,
        inferred_actor_key_hash=None,
        detection_available=True,
        evidence_complete=evidence_complete,
    )


def _unavailable_outcomes(detection: BotDetectionResponse) -> list[MitigationDecisionOutcome]:
    return [
        MitigationDecisionOutcome(
            result_index=index,
            status=MitigationOutcomeStatus.POLICY_UNAVAILABLE,
        )
        for index in range(len(detection.results))
    ]


def evaluate_and_persist_bot_detection(
    db: Session,
    detection: BotDetectionResponse,
    *,
    authentication_mode: MitigationAuthenticationMode,
    verified_principal: Optional[VerifiedMitigationPrincipal] = None,
    expected_policy_version: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> MitigationIntegrationResult:
    """Load policy, evaluate each Stage 1 result, and persist advisory decisions.

    Expected policy and persistence failures are converted into explicit safe
    statuses. This function never commits or rolls back the caller's transaction
    and never persists audit events.
    """
    try:
        loaded_policy = load_active_policy(
            db, expected_policy_version=expected_policy_version
        )
    except (
        ActivePolicyNotFoundError,
        PolicyConfigurationError,
        PolicyVersionMismatchError,
        PrivacySensitiveDataError,
    ) as exc:
        logger.error(
            "Mitigation active policy could not be loaded (%s)", type(exc).__name__
        )
        return MitigationIntegrationResult(
            policy_version=None,
            outcomes=_unavailable_outcomes(detection),
        )

    outcomes: list[MitigationDecisionOutcome] = []
    for index, result in enumerate(detection.results):
        try:
            context = build_mitigation_context(
                detection=detection,
                result=result,
                authentication_mode=authentication_mode,
                verified_principal=verified_principal,
            )
            dedupe_key = build_dedupe_key(
                policy_version=loaded_policy.config.policy_version,
                detection=detection,
                result=result,
                context=context,
                idempotency_key=idempotency_key,
            )
            decision = evaluate_mitigation_decision(
                result, context, loaded_policy.config
            )
            persisted = persist_evaluated_decision(
                db,
                decision,
                dedupe_key=dedupe_key,
                created_at=context.evaluated_at,
            )
        except DuplicateDecisionConflictError:
            logger.error("Mitigation decision identity conflict")
            outcomes.append(
                MitigationDecisionOutcome(
                    result_index=index,
                    status=MitigationOutcomeStatus.CONFLICT,
                )
            )
            continue
        except (
            DecisionValidationError,
            DecisionPersistenceError,
            PrivacySensitiveDataError,
        ) as exc:
            logger.error(
                "Mitigation decision could not be persisted (%s)", type(exc).__name__
            )
            outcomes.append(
                MitigationDecisionOutcome(
                    result_index=index,
                    status=MitigationOutcomeStatus.DECISION_NOT_PERSISTED,
                )
            )
            continue

        outcomes.append(
            MitigationDecisionOutcome(
                result_index=index,
                status=(
                    MitigationOutcomeStatus.PERSISTED
                    if persisted.created
                    else MitigationOutcomeStatus.IDEMPOTENT_REUSE
                ),
                decision=decision,
                decision_uuid=persisted.decision.decision_uuid,
            )
        )

    return MitigationIntegrationResult(
        policy_version=loaded_policy.config.policy_version,
        outcomes=outcomes,
    )


__all__ = [
    "MitigationIntegrationValidationError",
    "build_dedupe_key",
    "build_mitigation_context",
    "evaluate_and_persist_bot_detection",
]
