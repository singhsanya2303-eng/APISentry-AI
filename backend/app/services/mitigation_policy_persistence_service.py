"""Active mitigation policy loading for Stage 2C Phase 3.

Read-only boundary: this module never commits, rolls back, activates, or mutates
policy state. The caller owns the SQLAlchemy session transaction. A stored policy
is returned only after it passes the accepted Stage 2B ``MitigationPolicyConfig``
schema; no default or fallback policy is ever substituted.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.mitigation import MitigationPolicy, MitigationPolicyState
from app.schemas.mitigation import MitigationPolicyConfig
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    PolicyConfigurationError,
    PolicyVersionMismatchError,
    PrivacySensitiveDataError,
    reject_sensitive_fields,
)

logger = logging.getLogger("apisentry.persistence.mitigation.policy")

_ACTIVE_POLICY_STATE_ID = 1


@dataclass(frozen=True)
class LoadedPolicy:
    """Validated policy configuration plus its persistent identity."""

    record: MitigationPolicy
    config: MitigationPolicyConfig


def _safe_validation_locations(exc: ValidationError) -> tuple[str, ...]:
    """Return field locations only; Pydantic error values are never emitted."""
    locations: list[str] = []
    for error in exc.errors()[:5]:
        path = tuple(str(part) for part in error.get("loc", ()))
        locations.append(".".join(path) if path else "root")
    return tuple(locations)


def _config_mapping(record: MitigationPolicy) -> dict[str, Any]:
    """Build a minimal attribute mapping for Stage 2B schema validation."""
    mapping: dict[str, Any] = {}
    for field_name in MitigationPolicyConfig.model_fields:
        value = getattr(record, field_name)
        mapping[field_name] = value.value if hasattr(value, "value") else value
    return mapping


def _validate_policy_version(policy_version: Any) -> str:
    if not isinstance(policy_version, str) or not 1 <= len(policy_version) <= 64:
        raise PolicyConfigurationError("Policy version is invalid")
    return policy_version


def load_policy_by_version(db: Session, policy_version: Any) -> MitigationPolicy:
    """Load a stored immutable policy by its exact version identity.

    This is a bounded indexed lookup. It does not commit or roll back the caller's
    transaction.
    """
    version = _validate_policy_version(policy_version)
    try:
        record = (
            db.query(MitigationPolicy)
            .filter(MitigationPolicy.policy_version == version)
            .first()
        )
    except SQLAlchemyError as exc:
        logger.error("Mitigation policy version lookup failed (%s)", type(exc).__name__)
        raise PolicyConfigurationError("Stored mitigation policy could not be read") from None

    if record is None:
        raise ActivePolicyNotFoundError("Requested policy version is not stored")
    if record.policy_version != version:
        raise PolicyVersionMismatchError("Stored policy version identity differs")
    return record


def load_active_policy(
    db: Session, *, expected_policy_version: Optional[str] = None
) -> LoadedPolicy:
    """Load and validate the currently active mitigation policy.

    Raises:
        ActivePolicyNotFoundError: no active marker, no policy reference, or no
            matching policy row.
        PolicyConfigurationError: stored values fail Stage 2B validation or the
            database read fails.
        PolicyVersionMismatchError: ``expected_policy_version`` was supplied and
            does not match the stored version.
        PrivacySensitiveDataError: a caller supplied raw privacy-shaped input.
    """
    if expected_policy_version is not None:
        reject_sensitive_fields(
            {"policy_version": expected_policy_version}, context="expected policy input"
        )
        _validate_policy_version(expected_policy_version)

    try:
        state = db.get(MitigationPolicyState, _ACTIVE_POLICY_STATE_ID)
        if state is None or state.policy_id is None:
            raise ActivePolicyNotFoundError("No active mitigation policy is configured")
        record = db.get(MitigationPolicy, state.policy_id)
    except (ActivePolicyNotFoundError, PrivacySensitiveDataError):
        raise
    except SQLAlchemyError as exc:
        logger.error("Active mitigation policy read failed (%s)", type(exc).__name__)
        raise PolicyConfigurationError("Active mitigation policy could not be read") from None

    if record is None:
        raise ActivePolicyNotFoundError("Active policy reference has no policy row")

    try:
        config = MitigationPolicyConfig.model_validate(_config_mapping(record))
    except ValidationError as exc:
        logger.error(
            "Stored mitigation policy failed Stage 2B validation at %s",
            ",".join(_safe_validation_locations(exc)) or "root",
        )
        raise PolicyConfigurationError("Stored mitigation policy configuration is invalid") from None

    if config.policy_version != record.policy_version:
        raise PolicyVersionMismatchError("Validated policy version identity differs")

    if expected_policy_version is not None and config.policy_version != expected_policy_version:
        raise PolicyVersionMismatchError("Expected policy version does not match active policy")

    return LoadedPolicy(record=record, config=config)
