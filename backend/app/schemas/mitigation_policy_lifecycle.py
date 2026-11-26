"""
MW3 Gate A — in-memory mitigation policy lifecycle schemas.

These contracts model the approved policy/decision workflow without persistence,
HTTP exposure, or enforcement. All timestamps are caller-supplied and normalized
to UTC by the service; no wall-clock value or random identifier is generated here.

SECURITY CONTRACT:
  - No raw request IDs, actor IDs, credentials, headers, cookies, payloads, or
    classifier margins are represented.
  - Actor references are pre-hashed ``sha256:<64 lowercase hex>`` values supplied
    by trusted code. API-key callers are unattributed.
  - Correlation references are lowercase UUID5 values derived from allowlisted
    inputs only.
  - ``content_digest`` is a deterministic content descriptor. It is NOT a
    tamper-evident or tamper-proof audit chain value.
  - No field claims that a policy, decision, or audit event was persisted.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.mitigation import (
    MitigationActivationEventType,
    MitigationActivationReasonCode,
    MitigationAuditEntityType,
    MitigationAuditEventType,
)
from app.schemas.mitigation import (
    MitigationDecision,
    MitigationDecisionType,
    MitigationPolicyConfig,
)
from app.schemas.mitigation_audit_integration import (
    AuditOpaqueToken,
    AuditRole,
    OpaqueUuid5,
    Sha256Hash,
)
from app.services.mitigation_persistence_common import (
    PrivacySensitiveDataError,
    reject_raw_privacy_text,
    reject_sensitive_fields,
)

_POLICY_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"
_SCHEMA_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$"

PolicyVersion = Annotated[
    str,
    Field(
        pattern=_POLICY_VERSION_PATTERN,
        min_length=1,
        max_length=64,
        description="Opaque immutable policy version token",
    ),
]

SchemaVersion = Annotated[
    str,
    Field(
        pattern=_SCHEMA_VERSION_PATTERN,
        min_length=1,
        max_length=64,
        description="Versioned advisory schema identifier",
    ),
]

ActorHash = Annotated[
    str,
    Field(
        pattern=r"^sha256:[0-9a-f]{64}$",
        min_length=71,
        max_length=71,
        description="Pre-hashed actor reference; never a raw user identifier",
    ),
]


def _reject_sensitive(value: Any, *, field_name: str) -> None:
    """Translate the shared privacy validator into a Pydantic-safe error."""
    try:
        reject_raw_privacy_text(value, field_name=field_name)
    except PrivacySensitiveDataError as exc:
        raise ValueError(str(exc)) from None


def _reject_sensitive_mapping(value: Any, *, context: str) -> None:
    try:
        reject_sensitive_fields(value, context=context)
    except PrivacySensitiveDataError as exc:
        raise ValueError(str(exc)) from None


class PolicyLifecycleState(str, Enum):
    """Approved in-memory policy lifecycle states."""

    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    RETIRED = "RETIRED"
    ROLLED_BACK = "ROLLED_BACK"


class LifecycleRole(str, Enum):
    """Internal role context modelled after the proposed RBAC matrix.

    These values are supplied by a trusted internal caller. This module does not
    modify or bypass the live authentication/RBAC implementation.
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_KEY = "api_key"


class LifecycleErrorCode(str, Enum):
    """Stable, structured failure codes for lifecycle and evaluation operations."""

    VALIDATION_ERROR = "validation_error"
    UNSUPPORTED_ACTION = "unsupported_action"
    UNAUTHORIZED = "unauthorized"
    POLICY_NOT_FOUND = "policy_not_found"
    VERSION_CONFLICT = "version_conflict"
    POLICY_ALREADY_ACTIVE = "policy_already_active"
    POLICY_NOT_ACTIVE = "policy_not_active"
    POLICY_DISABLED = "policy_disabled"
    POLICY_CONFIGURATION_INVALID = "policy_configuration_invalid"
    POLICY_EXPIRED = "policy_expired"
    POLICY_NOT_YET_VALID = "policy_not_yet_valid"
    INVALID_TRANSITION = "invalid_transition"
    EVALUATION_FAILED = "evaluation_failed"


class LifecycleWorkflowReasonCode(str, Enum):
    """Workflow-level provenance reasons, separate from Stage 2B reason codes."""

    POLICY_PROPOSED = "policy_proposed"
    POLICY_VALIDATED = "policy_validated"
    POLICY_ACTIVATED = "policy_activated"
    POLICY_DEACTIVATED = "policy_deactivated"
    POLICY_RETIRED = "policy_retired"
    POLICY_VERSION_REPLACED = "policy_version_replaced"
    POLICY_ROLLED_BACK = "policy_rolled_back"
    MW1_OUTPUT_MISSING = "mw1_output_missing"
    MW1_COVERAGE_INCOMPLETE = "mw1_coverage_incomplete"
    MW1_HIGH_SEVERITY_ADVISORY = "mw1_high_severity_advisory"
    MW1_LOW_SEVERITY_ADVISORY = "mw1_low_severity_advisory"
    MW2_ENVELOPE_MISSING = "mw2_envelope_missing"
    MW2_SIGNAL_UNCERTAIN = "mw2_signal_uncertain"
    MW2_HIGH_SEVERITY_ADVISORY = "mw2_high_severity_advisory"
    ADVISORY_SIGNAL_CONFLICT_MONITOR_ONLY = "advisory_signal_conflict_monitor_only"
    DECISION_ISSUED = "decision_issued"


class LifecycleDecisionStatus(str, Enum):
    """Status of an advisory decision produced by this internal workflow."""

    ADVISORY_ISSUED = "advisory_issued"


class LifecycleActor(BaseModel):
    """Trusted internal actor context; no raw identity is accepted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: LifecycleRole
    actor_hash: ActorHash | None = None

    @model_validator(mode="after")
    def validate_actor_attribution(self) -> "LifecycleActor":
        if self.role is LifecycleRole.API_KEY:
            if self.actor_hash is not None:
                raise ValueError("API-key actors must remain unattributed")
            return self
        if self.actor_hash is None:
            raise ValueError("authenticated actors require a pre-hashed actor reference")
        return self


class LifecycleError(BaseModel):
    """Structured error with safe, fixed text and optional field names only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: LifecycleErrorCode
    message: str = Field(..., min_length=1, max_length=200)
    fields: tuple[AuditOpaqueToken, ...] = ()


class ActivationEventPlan(BaseModel):
    """Deterministic activation-history plan; never persisted by Gate A."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_uuid: OpaqueUuid5
    event_type: MitigationActivationEventType
    policy_version: PolicyVersion
    actor_hash: ActorHash | None = None
    reason_code: MitigationActivationReasonCode
    occurred_at: datetime
    details: dict[str, str | int | bool]
    content_digest: Sha256Hash

    @model_validator(mode="after")
    def validate_activation_plan(self) -> "ActivationEventPlan":
        _reject_sensitive(self.policy_version, field_name="policy_version")
        _reject_sensitive_mapping(self.details, context="activation event details")
        if self.event_type is MitigationActivationEventType.ACTIVATE and self.actor_hash is None:
            raise ValueError("activation events require an authenticated actor hash")
        return self


class LifecycleAuditEventPlan(BaseModel):
    """Allowlisted audit-event plan with a content digest, not a chain claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_uuid: OpaqueUuid5
    event_type: MitigationAuditEventType
    entity_type: MitigationAuditEntityType
    entity_identifier: AuditOpaqueToken
    policy_version: PolicyVersion
    decision_ref: OpaqueUuid5 | None = None
    actor_hash: ActorHash | None = None
    actor_role: AuditRole | None = None
    occurred_at: datetime
    action: AuditOpaqueToken
    outcome: AuditOpaqueToken
    reason: AuditOpaqueToken
    correlation_ref: OpaqueUuid5
    details: dict[str, str | int | bool]
    content_digest: Sha256Hash

    @model_validator(mode="after")
    def validate_audit_plan(self) -> "LifecycleAuditEventPlan":
        _reject_sensitive(self.policy_version, field_name="policy_version")
        _reject_sensitive(self.entity_identifier, field_name="entity_identifier")
        _reject_sensitive_mapping(self.details, context="audit event details")
        if self.event_type is MitigationAuditEventType.DECISION_ISSUED:
            if self.decision_ref is None:
                raise ValueError("decision_issued audit events require a decision reference")
            if self.entity_type is not MitigationAuditEntityType.DECISION:
                raise ValueError("decision_issued audit events require a decision entity")
        else:
            if self.decision_ref is not None:
                raise ValueError("policy audit events cannot carry a decision reference")
            if self.entity_type is not MitigationAuditEntityType.POLICY:
                raise ValueError("policy audit events require a policy entity")
        return self


class ImmutablePolicyVersion(BaseModel):
    """Frozen internal policy version with explicit lifecycle metadata.

    The nested Stage 2B config is deep-copied by the service on input and output.
    This record is an in-memory contract only; it is not a database row.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_version: PolicyVersion
    config: MitigationPolicyConfig
    state: PolicyLifecycleState
    created_at: datetime
    valid_from: datetime
    valid_until: datetime | None = None
    owner_actor_hash: ActorHash
    owner_role: Literal["admin", "analyst"]
    approved_by_hash: ActorHash | None = None
    approved_role: Literal["admin"] | None = None
    predecessor_version: PolicyVersion | None = None
    config_digest: Sha256Hash

    @model_validator(mode="after")
    def validate_policy_version(self) -> "ImmutablePolicyVersion":
        _reject_sensitive(self.policy_version, field_name="policy_version")
        if self.config.policy_version != self.policy_version:
            raise ValueError("record version must match the policy configuration version")
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        if (self.approved_by_hash is None) != (self.approved_role is None):
            raise ValueError("approval hash and role must be supplied together")
        if self.approved_role is not None and self.approved_role != LifecycleRole.ADMIN.value:
            raise ValueError("only an admin may approve a policy version")
        if self.predecessor_version is not None:
            _reject_sensitive(self.predecessor_version, field_name="predecessor_version")
        return self

    def snapshot(self) -> "ImmutablePolicyVersion":
        """Return a deep copy so callers cannot mutate registry state."""
        return self.model_copy(deep=True)


class AdvisorySignalSummary(BaseModel):
    """Privacy-safe provenance summary of an MW1 or MW2 advisory output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: Literal["mw1_risk_assessment", "mw2_advanced_signals"]
    reference: OpaqueUuid5
    schema_version: SchemaVersion
    status: AuditOpaqueToken
    severity: AuditOpaqueToken | None = None
    score: float | None = Field(default=None, ge=0.0, le=100.0)
    points: float | None = Field(default=None, ge=0.0, le=100.0)
    coverage_ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_reference_count: int = Field(..., ge=0, le=200)
    uncertain: bool

    @model_validator(mode="after")
    def validate_summary_shape(self) -> "AdvisorySignalSummary":
        if self.source == "mw1_risk_assessment" and self.points is not None:
            raise ValueError("MW1 summaries cannot carry MW2 points")
        if self.source == "mw2_advanced_signals" and self.score is not None:
            raise ValueError("MW2 summaries cannot carry an MW1 score")
        return self


class LifecycleDecision(BaseModel):
    """Advisory decision envelope produced by the internal workflow.

    The nested Stage 2B decision remains advisory-only and is never an
    enforcement instruction. No persistence state is represented.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_ref: OpaqueUuid5
    policy_ref: OpaqueUuid5
    policy_version: PolicyVersion
    policy_state: PolicyLifecycleState
    risk_assessment_ref: OpaqueUuid5 | None = None
    advisory_detection_refs: tuple[OpaqueUuid5, ...] = ()
    decision: MitigationDecision
    intended_action: MitigationDecisionType
    decision_status: LifecycleDecisionStatus
    workflow_reason_codes: tuple[LifecycleWorkflowReasonCode, ...]
    missing_signals: tuple[AuditOpaqueToken, ...] = ()
    uncertain_signals: bool
    advisory_only: Literal[True] = True
    evaluated_at: datetime
    config_digest: Sha256Hash
    correlation_ref: OpaqueUuid5

    @model_validator(mode="after")
    def validate_decision_envelope(self) -> "LifecycleDecision":
        if self.decision.advisory_only is not True:
            raise ValueError("Stage 2B decision must be advisory-only")
        if self.decision.policy_version != self.policy_version:
            raise ValueError("decision policy version does not match the workflow version")
        if self.decision.decision is not self.intended_action:
            raise ValueError("intended action must match the advisory decision")
        if not self.workflow_reason_codes:
            raise ValueError("every workflow decision requires explainable reason codes")
        return self


class PolicyLifecycleResult(BaseModel):
    """Structured result for one policy lifecycle mutation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    policy: ImmutablePolicyVersion | None = None
    error: LifecycleError | None = None
    activation_events: tuple[ActivationEventPlan, ...] = ()
    audit_events: tuple[LifecycleAuditEventPlan, ...] = ()

    @model_validator(mode="after")
    def validate_result_shape(self) -> "PolicyLifecycleResult":
        if self.ok:
            if self.error is not None:
                raise ValueError("successful results cannot carry an error")
            if self.policy is None:
                raise ValueError("successful results require a policy snapshot")
        elif self.error is None:
            raise ValueError("failed results require a structured error")
        return self


class PolicyEvaluationResult(BaseModel):
    """Structured result for one internal advisory evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    decision: LifecycleDecision | None = None
    error: LifecycleError | None = None
    audit_event: LifecycleAuditEventPlan | None = None

    @model_validator(mode="after")
    def validate_evaluation_result_shape(self) -> "PolicyEvaluationResult":
        if self.ok:
            if self.error is not None or self.decision is None or self.audit_event is None:
                raise ValueError(
                    "successful evaluation requires a decision and audit event without an error"
                )
        elif self.error is None:
            raise ValueError("failed evaluation requires a structured error")
        return self


__all__ = [
    "ActivationEventPlan",
    "ActorHash",
    "AdvisorySignalSummary",
    "ImmutablePolicyVersion",
    "LifecycleActor",
    "LifecycleAuditEventPlan",
    "LifecycleDecision",
    "LifecycleDecisionStatus",
    "LifecycleErrorCode",
    "LifecycleError",
    "LifecycleRole",
    "LifecycleWorkflowReasonCode",
    "PolicyEvaluationResult",
    "PolicyLifecycleResult",
    "PolicyLifecycleState",
    "PolicyVersion",
    "SchemaVersion",
]
