"""Mitigation persistence models - Stage 2C Phases 1 and 2.

This module stores versioned mitigation policy configuration, the singleton
active-policy marker, activation history, advisory decisions, and decision/audit
history. It deliberately does not provide repositories, policy loading, audit
hash-chain writing, concurrent append logic, routes, middleware, or any
request-enforcement behaviour.

Security contract:
    - No raw user IDs, usernames, emails, IP addresses, API keys, tokens,
      credentials, request IDs, cookies, User-Agent values, query values, or
      request bodies are stored.
    - Actor/creator/scope hashes are accepted only as validated
      ``sha256:<64 lowercase hex>`` values.
    - Stage 1 evidence references are stored only as opaque UUID5 values.
    - Configuration and decision fields mirror the accepted Stage 2B schemas.
    - Enum-like values use portable VARCHAR storage with SQLAlchemy-level
      validation and named portable CHECK constraints rather than PostgreSQL
      native enums.
    - Audit hash chaining is represented as data only; this module makes no
      tamper-proof claim and implements no append algorithm.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Sequence

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.base import Base

_ATTRIBUTE_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

# Allowlisted keys for optional activation details. Values are restricted to
# short scalars so that free-form text, credentials, and nested records cannot
# be persisted through this interface.
ALLOWED_ACTIVATION_DETAIL_KEYS = frozenset(
    {
        "previous_policy_version",
        "policy_version",
        "policy_mode",
        "review_reference",
    }
)

# Mirror of the accepted Stage 1 opaque UUID5 correlation reference format.
_OPAQUE_UUID5_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Allowlisted keys for optional audit details. Values are short scalars only so
# raw identities, credentials, and nested records cannot be persisted here.
ALLOWED_AUDIT_DETAIL_KEYS = frozenset(
    {
        "policy_version",
        "previous_policy_version",
        "decision_type",
        "scope_type",
        "attribution_status",
        "reason_code",
        "evidence_reference_count",
        "explanation_summary",
        "advisory_only",
        "request_ref",
        "risk_assessment_ref",
        "decision_ref",
        "selected_action",
        "enforcement_outcome",
        "enforced_at",
        "risk_score",
        "risk_severity",
        "risk_coverage_ratio",
        "mw1_status",
        "mw2_signal_count",
        "mw2_high_severity_count",
    }
)


class MitigationPolicyMode(str, Enum):
    """Portable mirror of the Stage 2B policy mode values."""

    SHADOW = "shadow"
    MONITOR = "monitor"
    ENFORCE = "enforce"


class MitigationActivationEventType(str, Enum):
    """The only two supported activation history event types."""

    ACTIVATE = "ACTIVATE"
    DEACTIVATE = "DEACTIVATE"


class MitigationActivationReasonCode(str, Enum):
    """Safe, machine-readable reasons for an activation history event."""

    INITIAL_ACTIVATION = "initial_activation"
    POLICY_VERSION_CHANGE = "policy_version_change"
    OPERATOR_REVIEW = "operator_review"
    CONFIGURATION_REVIEW = "configuration_review"
    POLICY_DEACTIVATION = "policy_deactivation"


class MitigationDecisionType(str, Enum):
    """Portable mirror of the accepted Stage 2B advisory decision values."""

    ALLOW = "allow"
    MONITOR = "monitor"
    THROTTLE = "throttle"
    BLOCK = "block"


class MitigationScopeType(str, Enum):
    """Portable mirror of the accepted Stage 2B scope classes."""

    VERIFIED_USER = "verified_user"
    API_KEY_PRINCIPAL = "api_key_principal"
    NETWORK_IP = "network_ip"
    UNATTRIBUTED = "unattributed"


class MitigationAttributionStatus(str, Enum):
    """Portable mirror of the accepted Stage 2B attribution trust levels."""

    VERIFIED_USER = "verified_user"
    API_KEY_PRINCIPAL = "api_key_principal"
    NETWORK_IP = "network_ip"
    INFERRED = "inferred"
    MISSING = "missing"


class MitigationAuditEventType(str, Enum):
    """Recordable policy/decision lifecycle events.

    The ``*_reserved`` members reserve vocabulary for a future enforcement
    implementation. This phase only stores values; it performs no enforcement.
    """

    POLICY_ACTIVATED = "policy_activated"
    POLICY_DEACTIVATED = "policy_deactivated"
    POLICY_VERSION_CHANGED = "policy_version_changed"
    DECISION_ISSUED = "decision_issued"
    DECISION_EXPIRED = "decision_expired"
    ENFORCEMENT_APPLIED_RESERVED = "enforcement_applied_reserved"
    ENFORCEMENT_REMOVED_RESERVED = "enforcement_removed_reserved"


class MitigationAuditEntityType(str, Enum):
    """Entity classes referenced by an audit event."""

    POLICY = "policy"
    DECISION = "decision"


def _enum_values(enum_class: type[Enum]) -> list[str]:
    """Return stable stored values for a SQLAlchemy portable Enum."""
    return [member.value for member in enum_class]  # type: ignore[attr-defined]


def _in_clause(column: str, values: Sequence[str]) -> str:
    """Build a portable CHECK expression from an accepted enum's values."""
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


_ACTIVATION_EVENT_TYPE_CHECK = _in_clause(
    "event_type", tuple(_enum_values(MitigationActivationEventType))
)
_ACTIVATION_REASON_CODE_CHECK = _in_clause(
    "reason_code", tuple(_enum_values(MitigationActivationReasonCode))
)

_HEX_DIGITS = "0123456789abcdef"


def _sha256_check(column: str, *, nullable: bool) -> str:
    """Build a portable CHECK for ``sha256:<64 lowercase hex>`` values.

    ``REPLACE``, ``SUBSTR``, ``LENGTH`` and ``LOWER`` are available on both
    SQLite and PostgreSQL, so no dialect-specific regex is required.
    """
    body = f"substr({column}, 8)"
    stripped = body
    for digit in _HEX_DIGITS:
        stripped = f"replace({stripped}, '{digit}', '')"
    value_check = (
        f"length({column}) = 71 "
        f"AND substr({column}, 1, 7) = 'sha256:' "
        f"AND lower({column}) = {column} "
        f"AND length({stripped}) = 0"
    )
    return f"{column} IS NULL OR ({value_check})" if nullable else value_check


def _uuid5_check(column: str) -> str:
    """Build a portable CHECK for a lowercase UUID5 string."""
    compact = f"replace({column}, '-', '')"
    stripped = compact
    for digit in _HEX_DIGITS:
        stripped = f"replace({stripped}, '{digit}', '')"
    return (
        f"length({column}) = 36 "
        f"AND lower({column}) = {column} "
        f"AND substr({column}, 9, 1) = '-' "
        f"AND substr({column}, 14, 1) = '-' "
        f"AND substr({column}, 19, 1) = '-' "
        f"AND substr({column}, 24, 1) = '-' "
        f"AND substr({compact}, 13, 1) = '5' "
        f"AND substr({compact}, 17, 1) IN ('8', '9', 'a', 'b') "
        f"AND length({stripped}) = 0"
    )


_DECISION_TYPE_CHECK = _in_clause(
    "decision_type", tuple(_enum_values(MitigationDecisionType))
)
_SCOPE_TYPE_CHECK = _in_clause("scope_type", tuple(_enum_values(MitigationScopeType)))
_ATTRIBUTION_STATUS_CHECK = _in_clause(
    "attribution_status", tuple(_enum_values(MitigationAttributionStatus))
)
_AUDIT_EVENT_TYPE_CHECK = _in_clause(
    "event_type", tuple(_enum_values(MitigationAuditEventType))
)
_AUDIT_ENTITY_TYPE_CHECK = _in_clause(
    "entity_type", tuple(_enum_values(MitigationAuditEntityType))
)


def _validated_hash(value: Optional[str], field_name: str) -> Optional[str]:
    """Validate and return an opaque attribution hash, or ``None``."""
    if value is None:
        return None
    if not isinstance(value, str) or not _ATTRIBUTE_HASH_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be sha256:<64 lowercase hex>")
    return value


def _as_utc(value: Optional[datetime], field_name: str) -> Optional[datetime]:
    """Normalize a timestamp to an aware UTC value without mutating the input."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validated_uuid5(value: Optional[str], field_name: str) -> Optional[str]:
    """Validate the same lowercase UUID5 form enforced by the database CHECK."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        value = str(value)
    if not isinstance(value, str) or not _OPAQUE_UUID5_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase opaque UUID5 string")
    return value


def _validated_code_list(
    value: Optional[list[Any]], field_name: str, max_items: int
) -> list[str]:
    """Validate a short, deduplicated list of machine-readable codes."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON list")
    if len(value) > max_items:
        raise ValueError(f"{field_name} has too many values")

    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", item):
            raise ValueError(f"{field_name} contains an invalid code")
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _validated_evidence_refs(value: Optional[list[Any]]) -> list[str]:
    """Validate bounded opaque UUID5 references from Stage 1 evidence."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("evidence_references must be a JSON list")
    if len(value) > 200:
        raise ValueError("evidence_references has too many values")

    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not _OPAQUE_UUID5_PATTERN.fullmatch(item):
            raise ValueError("evidence_references contains a non-opaque reference")
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _require_value(value: Optional[str], field_name: str) -> str:
    """Reject ``None`` for fields that are required at the application layer."""
    if value is None:
        raise ValueError(f"{field_name} is required")
    return value


def _validated_audit_details(value: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Validate allowlisted, short scalar audit detail values."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("details must be a JSON object")
    cleaned: dict[str, Any] = {}
    for name, item in value.items():
        if name not in ALLOWED_AUDIT_DETAIL_KEYS:
            raise ValueError("details contains a key that is not allowlisted")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError("details values must be short scalars")
        if isinstance(item, str) and len(item) > 128:
            raise ValueError("details string values must be at most 128 characters")
        cleaned[name] = item
    return cleaned


class MitigationPolicy(Base):
    """Immutable, versioned mitigation policy configuration.

    The fields mirror ``app.schemas.mitigation.MitigationPolicyConfig``. Once
    assigned, ``policy_version`` cannot be changed through the application
    interface; corrections must be a new version rather than an in-place edit.
    """

    __tablename__ = "mitigation_policies"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    policy_version: Mapped[str] = mapped_column(
        sa.String(length=64), nullable=False, unique=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    mode: Mapped[MitigationPolicyMode] = mapped_column(
        sa.Enum(
            MitigationPolicyMode,
            name="mitigation_policy_mode",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
        default=MitigationPolicyMode.MONITOR,
    )

    monitoring_score_threshold: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=25.0
    )
    throttling_score_threshold: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=75.0
    )
    blocking_score_threshold: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=90.0
    )

    minimum_authentication_failures: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=5
    )
    require_grouped_brute_force: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )

    throttle_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False
    )
    throttle_limit: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=60)
    throttle_window_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=60
    )
    throttle_duration_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=300
    )

    block_enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    block_duration_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=900
    )
    max_block_duration_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=3600
    )

    admin_protection_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )
    max_evidence_references: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=25
    )

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    creator_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(length=71), nullable=True
    )

    @validates("policy_version")
    def _validate_policy_version(self, key: str, value: Any) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 64:
            raise ValueError("policy_version must be a string of 1 to 64 characters")
        # ``getattr`` deliberately loads an expired persisted value so a committed
        # policy cannot be silently reversioned after an expire-on-commit refresh.
        current = getattr(self, key, None)
        if current is not None and current != value:
            raise ValueError("policy_version is immutable")
        return value

    @validates("creator_hash")
    def _validate_creator_hash(self, key: str, value: Any) -> Optional[str]:
        return _validated_hash(value, "creator_hash")

    @validates("created_at")
    def _validate_created_at(self, key: str, value: Any) -> datetime:
        normalized = _as_utc(value, "created_at")
        if normalized is None:
            raise ValueError("created_at is required")
        return normalized


class MitigationPolicyState(Base):
    """Singleton marker identifying the currently active policy version."""

    __tablename__ = "mitigation_policy_state"
    __table_args__ = (
        sa.CheckConstraint("id = 1", name="ck_mitigation_policy_state_id"),
        sa.CheckConstraint(
            "singleton_marker = 1", name="ck_mitigation_policy_state_singleton_marker"
        ),
    )

    id: Mapped[int] = mapped_column(
        sa.Integer, primary_key=True, default=1, server_default=sa.text("1")
    )
    policy_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey(
            "mitigation_policies.id",
            ondelete="RESTRICT",
            name="fk_mitigation_policy_state_policy",
        ),
        nullable=True,
        unique=True,
        index=True,
    )
    # A unique, fixed marker plus CHECK constraints enforces singleton semantics
    # at the database layer. The application validators preserve the same rule
    # before a flush.
    singleton_marker: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        default=1,
        server_default=sa.text("1"),
        unique=True,
        index=True,
    )

    policy: Mapped[Optional[MitigationPolicy]] = relationship(
        "MitigationPolicy",
        foreign_keys=[policy_id],
        lazy="select",
        passive_deletes=False,
    )

    @validates("id")
    def _validate_singleton_id(self, key: str, value: Any) -> int:
        if value != 1:
            raise ValueError("MitigationPolicyState is a singleton with id=1")
        return int(value)

    @validates("singleton_marker")
    def _validate_singleton_marker(self, key: str, value: Any) -> int:
        if value != 1:
            raise ValueError("singleton_marker must be 1")
        return int(value)


class MitigationPolicyActivationEvent(Base):
    """Append-only history of policy activation and deactivation events."""

    __tablename__ = "mitigation_policy_activation_events"
    __table_args__ = (
        sa.CheckConstraint(
            _ACTIVATION_EVENT_TYPE_CHECK,
            name="ck_mitigation_policy_activation_event_type",
        ),
        sa.CheckConstraint(
            _ACTIVATION_REASON_CODE_CHECK,
            name="ck_mitigation_policy_activation_reason_code",
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(
        sa.String(length=36), nullable=False, unique=True, index=True
    )
    event_type: Mapped[MitigationActivationEventType] = mapped_column(
        sa.Enum(
            MitigationActivationEventType,
            name="mitigation_activation_event_type",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
        index=True,
    )
    policy_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey(
            "mitigation_policies.id",
            ondelete="RESTRICT",
            name="fk_mitigation_activation_event_policy",
        ),
        nullable=False,
        index=True,
    )
    actor_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(length=71), nullable=True
    )
    reason_code: Mapped[MitigationActivationReasonCode] = mapped_column(
        sa.Enum(
            MitigationActivationReasonCode,
            name="mitigation_activation_reason_code",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)

    policy: Mapped[MitigationPolicy] = relationship(
        "MitigationPolicy",
        foreign_keys=[policy_id],
        lazy="select",
        passive_deletes=False,
    )

    @validates("event_uuid")
    def _validate_event_uuid(self, key: str, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("event_uuid must be a UUID string")
        try:
            return str(uuid.UUID(value))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("event_uuid must be a valid UUID") from exc

    @validates("event_type")
    def _validate_event_type(self, key: str, value: Any) -> str:
        try:
            return MitigationActivationEventType(value).value
        except ValueError as exc:
            raise ValueError("event_type must be ACTIVATE or DEACTIVATE") from exc

    @validates("reason_code")
    def _validate_reason_code(self, key: str, value: Any) -> str:
        try:
            return MitigationActivationReasonCode(value).value
        except ValueError as exc:
            raise ValueError("reason_code is not an allowed activation reason") from exc

    @validates("actor_hash")
    def _validate_actor_hash(self, key: str, value: Any) -> Optional[str]:
        return _validated_hash(value, "actor_hash")

    @validates("occurred_at")
    def _validate_occurred_at(self, key: str, value: Any) -> datetime:
        normalized = _as_utc(value, "occurred_at")
        if normalized is None:
            raise ValueError("occurred_at is required")
        return normalized

    @validates("details")
    def _validate_details(self, key: str, value: Any) -> Optional[dict[str, Any]]:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("details must be a JSON object")
        cleaned: dict[str, Any] = {}
        for name, item in value.items():
            if name not in ALLOWED_ACTIVATION_DETAIL_KEYS:
                raise ValueError("details contains a key that is not allowlisted")
            if item is not None and not isinstance(item, (str, int, float, bool)):
                raise ValueError("details values must be short scalars")
            if isinstance(item, str) and len(item) > 128:
                raise ValueError("details string values must be at most 128 characters")
            cleaned[name] = item
        return cleaned


class MitigationDecision(Base):
    """Advisory-only decision record. No request enforcement is represented."""

    __tablename__ = "mitigation_decisions"
    __table_args__ = (
        sa.Index(
            "ix_mitigation_decisions_decision_uuid", "decision_uuid", unique=True
        ),
        sa.Index("ix_mitigation_decisions_dedupe_key", "dedupe_key", unique=True),
        sa.Index("ix_mitigation_decisions_policy_id", "policy_id"),
        sa.Index("ix_mitigation_decisions_decision_type", "decision_type"),
        sa.Index("ix_mitigation_decisions_scope_type", "scope_type"),
        sa.Index("ix_mitigation_decisions_scope_key_hash", "scope_key_hash"),
        sa.Index("ix_mitigation_decisions_issued_at", "issued_at"),
        sa.Index("ix_mitigation_decisions_expires_at", "expires_at"),
        sa.Index("ix_mitigation_decisions_created_at", "created_at"),
        sa.CheckConstraint(
            _DECISION_TYPE_CHECK, name="ck_mitigation_decision_decision_type"
        ),
        sa.CheckConstraint(_SCOPE_TYPE_CHECK, name="ck_mitigation_decision_scope_type"),
        sa.CheckConstraint(
            _ATTRIBUTION_STATUS_CHECK,
            name="ck_mitigation_decision_attribution_status",
        ),
        sa.CheckConstraint(
            "advisory_only", name="ck_mitigation_decision_advisory_only"
        ),
        sa.CheckConstraint(
            _sha256_check("scope_key_hash", nullable=True),
            name="ck_mitigation_decision_scope_key_hash",
        ),
        sa.CheckConstraint(
            _uuid5_check("decision_uuid"),
            name="ck_mitigation_decision_decision_uuid_format",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > issued_at",
            name="ck_mitigation_decision_expiry_after_issue",
        ),
        sa.CheckConstraint(
            "rate_limit IS NULL OR rate_limit > 0",
            name="ck_mitigation_decision_rate_limit_positive",
        ),
        sa.CheckConstraint(
            "rate_limit_window_seconds IS NULL OR rate_limit_window_seconds > 0",
            name="ck_mitigation_decision_rate_window_positive",
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    decision_uuid: Mapped[str] = mapped_column(sa.String(length=36), nullable=False)
    decision_type: Mapped[MitigationDecisionType] = mapped_column(
        sa.Enum(
            MitigationDecisionType,
            name="mitigation_decision_type",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    scope_type: Mapped[MitigationScopeType] = mapped_column(
        sa.Enum(
            MitigationScopeType,
            name="mitigation_scope_type",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    scope_key_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(length=71), nullable=True
    )
    attribution_status: Mapped[MitigationAttributionStatus] = mapped_column(
        sa.Enum(
            MitigationAttributionStatus,
            name="mitigation_attribution_status",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    verified_attribution: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    explanation: Mapped[str] = mapped_column(sa.String(length=2000), nullable=False)
    policy_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey(
            "mitigation_policies.id",
            ondelete="RESTRICT",
            name="fk_mitigation_decision_policy",
        ),
        nullable=False,
    )
    evidence_references: Mapped[list[str]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    issued_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    rate_limit: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    rate_limit_window_seconds: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True
    )
    advisory_only: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True, server_default=sa.true()
    )
    dedupe_key: Mapped[str] = mapped_column(sa.String(length=128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    policy: Mapped[MitigationPolicy] = relationship(
        "MitigationPolicy",
        foreign_keys=[policy_id],
        lazy="select",
        passive_deletes=False,
    )

    @validates("decision_uuid")
    def _validate_decision_uuid(self, key: str, value: Any) -> str:
        return _require_value(_validated_uuid5(value, key), key)

    @validates("decision_type")
    def _validate_decision_type(self, key: str, value: Any) -> str:
        try:
            return MitigationDecisionType(value).value
        except ValueError as exc:
            raise ValueError("decision_type is not an allowed advisory decision") from exc

    @validates("scope_type")
    def _validate_scope_type(self, key: str, value: Any) -> str:
        try:
            return MitigationScopeType(value).value
        except ValueError as exc:
            raise ValueError("scope_type is not an allowed scope class") from exc

    @validates("scope_key_hash")
    def _validate_scope_key_hash(self, key: str, value: Any) -> Optional[str]:
        return _validated_hash(value, key)

    @validates("attribution_status")
    def _validate_attribution_status(self, key: str, value: Any) -> str:
        try:
            return MitigationAttributionStatus(value).value
        except ValueError as exc:
            raise ValueError("attribution_status is not an allowed trust level") from exc

    @validates("reason_codes")
    def _validate_reason_codes(self, key: str, value: Any) -> list[str]:
        return _validated_code_list(value, key, 64)

    @validates("explanation")
    def _validate_explanation(self, key: str, value: Any) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 2000:
            raise ValueError("explanation must be a string of 1 to 2000 characters")
        return value

    @validates("evidence_references")
    def _validate_evidence_references(self, key: str, value: Any) -> list[str]:
        return _validated_evidence_refs(value)

    @validates("issued_at")
    def _validate_issued_at(self, key: str, value: Any) -> datetime:
        normalized = _as_utc(value, key)
        if normalized is None:
            raise ValueError("issued_at is required")
        return normalized

    @validates("expires_at")
    def _validate_expires_at(self, key: str, value: Any) -> Optional[datetime]:
        return _as_utc(value, key)

    @validates("advisory_only")
    def _validate_advisory_only(self, key: str, value: Any) -> bool:
        if value is not True:
            raise ValueError("advisory_only must be True in this phase")
        return True

    @validates("dedupe_key")
    def _validate_dedupe_key(self, key: str, value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value
        ):
            raise ValueError("dedupe_key must be an opaque 1 to 128 character token")
        return value

    @validates("created_at")
    def _validate_created_at(self, key: str, value: Any) -> datetime:
        normalized = _as_utc(value, key)
        if normalized is None:
            raise ValueError("created_at is required")
        return normalized


class MitigationAuditEvent(Base):
    """Privacy-safe audit data for policy and decision lifecycle events.

    Hash-chain fields are stored as data only. This class does not claim that
    the chain is tamper-proof and does not implement a concurrent append
    algorithm; those belong to a separately approved service.
    """

    __tablename__ = "mitigation_audit_events"
    __table_args__ = (
        sa.Index(
            "ix_mitigation_audit_events_event_uuid", "event_uuid", unique=True
        ),
        sa.Index(
            "uq_mitigation_audit_events_chain_id_sequence_no",
            "chain_id",
            "sequence_no",
            unique=True,
        ),
        sa.Index("ix_mitigation_audit_events_event_type", "event_type"),
        sa.Index("ix_mitigation_audit_events_entity_type", "entity_type"),
        sa.Index("ix_mitigation_audit_events_policy_id", "policy_id"),
        sa.Index("ix_mitigation_audit_events_decision_id", "decision_id"),
        sa.Index("ix_mitigation_audit_events_actor_hash", "actor_hash"),
        sa.Index("ix_mitigation_audit_events_chain_id", "chain_id"),
        sa.Index("ix_mitigation_audit_events_created_at", "created_at"),
        sa.CheckConstraint(
            _AUDIT_EVENT_TYPE_CHECK, name="ck_mitigation_audit_event_type"
        ),
        sa.CheckConstraint(
            _AUDIT_ENTITY_TYPE_CHECK, name="ck_mitigation_audit_entity_type"
        ),
        sa.CheckConstraint(
            _uuid5_check("event_uuid"),
            name="ck_mitigation_audit_event_uuid_format",
        ),
        sa.CheckConstraint(
            _sha256_check("actor_hash", nullable=True),
            name="ck_mitigation_audit_actor_hash",
        ),
        sa.CheckConstraint(
            _sha256_check("previous_event_hash", nullable=True),
            name="ck_mitigation_audit_previous_event_hash",
        ),
        sa.CheckConstraint(
            _sha256_check("event_hash", nullable=False),
            name="ck_mitigation_audit_event_hash",
        ),
        sa.CheckConstraint(
            "sequence_no > 0", name="ck_mitigation_audit_sequence_no_positive"
        ),
        sa.CheckConstraint(
            "length(chain_id) BETWEEN 1 AND 64",
            name="ck_mitigation_audit_chain_id_length",
        ),
        sa.CheckConstraint(
            "length(entity_identifier) BETWEEN 1 AND 64",
            name="ck_mitigation_audit_entity_identifier_length",
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(sa.String(length=36), nullable=False)
    event_type: Mapped[MitigationAuditEventType] = mapped_column(
        sa.Enum(
            MitigationAuditEventType,
            name="mitigation_audit_event_type",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    entity_type: Mapped[MitigationAuditEntityType] = mapped_column(
        sa.Enum(
            MitigationAuditEntityType,
            name="mitigation_audit_entity_type",
            native_enum=False,
            create_constraint=False,
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    entity_identifier: Mapped[str] = mapped_column(sa.String(length=64), nullable=False)
    policy_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey(
            "mitigation_policies.id",
            ondelete="RESTRICT",
            name="fk_mitigation_audit_event_policy",
        ),
        nullable=True,
    )
    decision_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey(
            "mitigation_decisions.id",
            ondelete="RESTRICT",
            name="fk_mitigation_audit_event_decision",
        ),
        nullable=True,
    )
    actor_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(length=71), nullable=True
    )
    actor_role: Mapped[Optional[str]] = mapped_column(sa.String(length=64), nullable=True)
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)
    previous_event_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(length=71), nullable=True
    )
    event_hash: Mapped[str] = mapped_column(sa.String(length=71), nullable=False)
    sequence_no: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    chain_id: Mapped[str] = mapped_column(sa.String(length=64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    policy: Mapped[Optional[MitigationPolicy]] = relationship(
        "MitigationPolicy",
        foreign_keys=[policy_id],
        lazy="select",
        passive_deletes=False,
    )
    decision: Mapped[Optional[MitigationDecision]] = relationship(
        "MitigationDecision",
        foreign_keys=[decision_id],
        lazy="select",
        passive_deletes=False,
    )

    @validates("event_uuid")
    def _validate_event_uuid(self, key: str, value: Any) -> str:
        return _require_value(_validated_uuid5(value, key), key)

    @validates("event_type")
    def _validate_event_type(self, key: str, value: Any) -> str:
        try:
            return MitigationAuditEventType(value).value
        except ValueError as exc:
            raise ValueError("event_type is not an allowed audit event type") from exc

    @validates("entity_type")
    def _validate_entity_type(self, key: str, value: Any) -> str:
        try:
            return MitigationAuditEntityType(value).value
        except ValueError as exc:
            raise ValueError("entity_type is not an allowed audit entity type") from exc

    @validates("entity_identifier")
    def _validate_entity_identifier(self, key: str, value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", value
        ):
            raise ValueError("entity_identifier must be an opaque 1 to 64 character token")
        return value

    @validates("actor_hash")
    def _validate_actor_hash(self, key: str, value: Any) -> Optional[str]:
        return _validated_hash(value, key)

    @validates("actor_role")
    def _validate_actor_role(self, key: str, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
            raise ValueError("actor_role must be a short lowercase role token")
        return value

    @validates("details")
    def _validate_details(self, key: str, value: Any) -> Optional[dict[str, Any]]:
        return _validated_audit_details(value)

    @validates("previous_event_hash")
    def _validate_previous_event_hash(self, key: str, value: Any) -> Optional[str]:
        return _validated_hash(value, key)

    @validates("event_hash")
    def _validate_event_hash(self, key: str, value: Any) -> str:
        return _require_value(_validated_hash(value, key), key)

    @validates("sequence_no")
    def _validate_sequence_no(self, key: str, value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError("sequence_no must be a positive integer")
        return value

    @validates("chain_id")
    def _validate_chain_id(self, key: str, value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", value
        ):
            raise ValueError("chain_id must be an opaque 1 to 64 character token")
        return value

    @validates("created_at")
    def _validate_created_at(self, key: str, value: Any) -> datetime:
        normalized = _as_utc(value, key)
        if normalized is None:
            raise ValueError("created_at is required")
        return normalized


__all__ = [
    "ALLOWED_ACTIVATION_DETAIL_KEYS",
    "ALLOWED_AUDIT_DETAIL_KEYS",
    "MitigationActivationEventType",
    "MitigationActivationReasonCode",
    "MitigationAttributionStatus",
    "MitigationAuditEntityType",
    "MitigationAuditEvent",
    "MitigationAuditEventType",
    "MitigationDecision",
    "MitigationDecisionType",
    "MitigationPolicy",
    "MitigationPolicyActivationEvent",
    "MitigationPolicyMode",
    "MitigationPolicyState",
    "MitigationScopeType",
]
