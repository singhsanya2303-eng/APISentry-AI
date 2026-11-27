"""Request and response contracts for the authenticated mitigation admin APIs.

These models are thin wrappers over the exact Gate A lifecycle schemas and the
existing Gate B mitigation tables. They add no business rules: timestamps,
opaque tokens, policy configuration, and advisory detection inputs are all
validated by the already-approved schema/service layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.mitigation import (
    MitigationActivationReasonCode,
    MitigationAttributionStatus,
    MitigationAuditEntityType,
    MitigationAuditEventType,
    MitigationDecisionType,
    MitigationScopeType,
)
from app.schemas.advanced_detection_signals import AdvancedDetectionEnvelope
from app.schemas.bot_detection import BotAnalysisResult
from app.schemas.mitigation import MitigationPolicyConfig, MitigationRequestContext
from app.schemas.mitigation_policy_lifecycle import ImmutablePolicyVersion
from app.schemas.unified_risk_assessment import UnifiedRiskAssessment


class PolicyProposalRequest(BaseModel):
    """Propose a new immutable policy version. No activation is implied."""

    model_config = ConfigDict(extra="forbid")

    config: MitigationPolicyConfig
    created_at: datetime
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    predecessor_version: str | None = Field(
        default=None,
        max_length=64,
        description="Optional prior immutable version, when this is a replacement.",
    )


class PolicyActionRequest(BaseModel):
    """Common fields for administrative lifecycle transitions."""

    model_config = ConfigDict(extra="forbid")

    at: datetime
    expected_active_version: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Expected currently active version. Omit for no expectation; send "
            "null to assert that no policy is active."
        ),
    )

    def expected_active_kwargs(self) -> dict[str, str | None]:
        """Return the keyword only when the caller actually supplied it."""
        if "expected_active_version" in self.model_fields_set:
            return {"expected_active_version": self.expected_active_version}
        return {}


class PolicyValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at: datetime


class PolicyActivateRequest(PolicyActionRequest):
    reason_code: MitigationActivationReasonCode = (
        MitigationActivationReasonCode.INITIAL_ACTIVATION
    )


class PolicyDeactivateRequest(PolicyActionRequest):
    version: str = Field(..., min_length=1, max_length=64)
    reason_code: MitigationActivationReasonCode = (
        MitigationActivationReasonCode.POLICY_DEACTIVATION
    )


class PolicyRetireRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at: datetime


class PolicyRollbackRequest(PolicyActionRequest):
    pass


class PolicyListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    active_version: str | None
    versions: list[str]
    policies: list[ImmutablePolicyVersion]


class ActivePolicyResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    active_version: str | None
    policy: ImmutablePolicyVersion | None


class EnforcementStatusResponse(BaseModel):
    """Read-only lifecycle status. Enforcement itself is not implemented."""

    model_config = ConfigDict(frozen=True)

    enforcement_active: Literal[False] = False
    advisory_only: Literal[True] = True
    active_version: str | None
    policy_available: bool
    policy_mode: str | None
    persisted_active_version: str | None
    activation_event_count: int | None
    latest_activation_event_type: str | None
    registry_consistent: bool | None = None
    consistency_note: str | None = None


class DryRunEvaluationRequest(BaseModel):
    """Advisory-only evaluation inputs; no state or traffic writes are allowed."""

    model_config = ConfigDict(extra="forbid")

    version: str = Field(..., min_length=1, max_length=64)
    at: datetime
    detection_result: BotAnalysisResult | None = None
    context: MitigationRequestContext
    risk_assessment: UnifiedRiskAssessment | None = None
    advanced_envelope: AdvancedDetectionEnvelope | None = None
    dry_run: bool = Field(
        default=True,
        description=(
            "Lifecycle review mode only. Every returned decision remains advisory."
        ),
    )
    idempotency_token: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Opaque token affecting deterministic decision references only.",
    )


class DecisionRecord(BaseModel):
    """Privacy-safe projection of one persisted advisory decision row."""

    model_config = ConfigDict(frozen=True)

    decision_uuid: str
    dedupe_key: str
    policy_version: str
    decision_type: MitigationDecisionType
    scope_type: MitigationScopeType
    scope_key_hash: str | None
    attribution_status: MitigationAttributionStatus
    verified_attribution: bool
    reason_codes: list[str]
    explanation: str
    evidence_references: list[str]
    issued_at: datetime
    expires_at: datetime | None
    created_at: datetime
    rate_limit: int | None
    rate_limit_window_seconds: int | None
    advisory_only: bool


class DecisionListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[DecisionRecord]
    total: int
    limit: int
    offset: int


class AuditEventRecord(BaseModel):
    """Privacy-safe projection of one persisted audit event row.

    ``event_hash`` is a content digest stored as data. It is not a tamper-evident
    chain value.
    """

    model_config = ConfigDict(frozen=True)

    event_uuid: str
    event_type: MitigationAuditEventType
    entity_type: MitigationAuditEntityType
    entity_identifier: str
    policy_version: str | None
    decision_uuid: str | None
    actor_hash: str | None
    actor_role: str | None
    chain_id: str
    sequence_no: int
    event_hash: str
    previous_event_hash: str | None
    details: dict[str, Any]
    created_at: datetime


class AuditEventListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[AuditEventRecord]
    total: int
    limit: int
    offset: int


__all__ = [
    "ActivePolicyResponse",
    "AuditEventListResponse",
    "AuditEventRecord",
    "DecisionListResponse",
    "DecisionRecord",
    "DryRunEvaluationRequest",
    "EnforcementStatusResponse",
    "PolicyActivateRequest",
    "PolicyActionRequest",
    "PolicyDeactivateRequest",
    "PolicyListResponse",
    "PolicyProposalRequest",
    "PolicyRetireRequest",
    "PolicyRollbackRequest",
    "PolicyValidateRequest",
]
