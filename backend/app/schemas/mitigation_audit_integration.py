"""Stage 2C Phase 4 C1 audit-integration schemas.

These models describe only the planner/builder output and the safe status of an
audit-integration attempt. They contain no request data, raw identity material,
credentials, explanations, evidence payloads, or enforcement data.

The ``event_hash`` produced here is a deterministic *content digest*. It is not a
tamper-evident or tamper-proof hash chain value; no chain continuity is verified.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

_UUID5_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_OPAQUE_TOKEN_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"

OpaqueUuid5 = Annotated[
    str,
    Field(
        pattern=_UUID5_PATTERN,
        min_length=36,
        max_length=36,
        description="Lowercase opaque UUID5 identifier",
    ),
]
Sha256Hash = Annotated[
    str,
    Field(
        pattern=_SHA256_PATTERN,
        min_length=71,
        max_length=71,
        description="SHA-256 digest encoded as sha256:<64 lowercase hex characters>",
    ),
]
AuditOpaqueToken = Annotated[
    str,
    Field(
        pattern=_OPAQUE_TOKEN_PATTERN,
        min_length=1,
        max_length=64,
        description="Short opaque audit token",
    ),
]
AuditRole = Annotated[
    str,
    Field(
        pattern=_ROLE_PATTERN,
        min_length=1,
        max_length=64,
        description="Lowercase validated role token",
    ),
]


class MitigationAuditEventStatus(str, Enum):
    """Safe status for one decision-to-audit attempt."""

    CREATED = "created"
    IDEMPOTENT_REUSE = "idempotent_reuse"
    SKIPPED = "skipped"


class DecisionAuditEventPlan(BaseModel):
    """Fully validated, allowlisted input for ``persist_audit_event()``.

    The plan is derived only from a persisted decision row, its policy row, and an
    optional verified principal. It contains no request-derived data.
    """

    event_uuid: OpaqueUuid5
    event_type: Literal["decision_issued"]
    entity_type: Literal["decision"]
    entity_identifier: AuditOpaqueToken
    event_hash: Sha256Hash
    chain_id: AuditOpaqueToken
    sequence_no: int = Field(default=1, ge=1, le=1)
    previous_event_hash: None = None
    policy_id: int = Field(..., gt=0)
    decision_id: int = Field(..., gt=0)
    actor_hash: Optional[Sha256Hash] = None
    actor_role: Optional[AuditRole] = None
    details: dict[str, str | int | bool]
    created_at: datetime

    model_config = ConfigDict(frozen=True, extra="forbid")

    def to_persistence_kwargs(self) -> dict[str, Any]:
        """Return only the accepted keyword arguments for ``persist_audit_event``."""
        return {
            "event_uuid": self.event_uuid,
            "event_type": self.event_type,
            "entity_type": self.entity_type,
            "entity_identifier": self.entity_identifier,
            "event_hash": self.event_hash,
            "chain_id": self.chain_id,
            "sequence_no": self.sequence_no,
            "policy_id": self.policy_id,
            "decision_id": self.decision_id,
            "actor_hash": self.actor_hash,
            "actor_role": self.actor_role,
            "details": self.details,
            "previous_event_hash": self.previous_event_hash,
            "created_at": self.created_at,
        }


class MitigationAuditEventOutcome(BaseModel):
    """Safe per-outcome result. Sensitive row content is deliberately absent."""

    result_index: int = Field(..., ge=0)
    decision_uuid: Optional[OpaqueUuid5] = None
    event_uuid: Optional[OpaqueUuid5] = None
    status: MitigationAuditEventStatus
    created: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")


class MitigationAuditIntegrationResult(BaseModel):
    """Summary of one audit-integration attempt over Stage A outcomes."""

    outcomes: list[MitigationAuditEventOutcome] = Field(default_factory=list)
    event_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


__all__ = [
    "AuditOpaqueToken",
    "AuditRole",
    "DecisionAuditEventPlan",
    "MitigationAuditEventOutcome",
    "MitigationAuditEventStatus",
    "MitigationAuditIntegrationResult",
    "OpaqueUuid5",
    "Sha256Hash",
]
