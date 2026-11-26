"""Stage 2C Phase 4 Stage A orchestration schemas.

These models describe only advisory mitigation orchestration outputs. No request
enforcement, audit hashing, or chain metadata is represented here.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.mitigation import MitigationDecision, ScopeKeyHash


class MitigationAuthenticationMode(str, Enum):
    """Server-side authentication mode supplied by a trusted caller."""

    JWT = "jwt"
    API_KEY = "api_key"


class MitigationOutcomeStatus(str, Enum):
    """Safe status for one advisory decision outcome."""

    PERSISTED = "persisted"
    IDEMPOTENT_REUSE = "idempotent_reuse"
    POLICY_UNAVAILABLE = "policy_unavailable"
    DECISION_NOT_PERSISTED = "decision_not_persisted"
    CONFLICT = "conflict"


class VerifiedMitigationPrincipal(BaseModel):
    """Pre-hashed principal derived only from a verified JWT by trusted code.

    Raw user IDs, usernames, emails, tokens, and headers are deliberately absent.
    """

    actor_key_hash: ScopeKeyHash
    role: Literal["admin", "analyst", "viewer"]

    model_config = ConfigDict(frozen=True, extra="forbid")


class MitigationDecisionOutcome(BaseModel):
    """Advisory decision result for one Stage 1 detection result."""

    result_index: int = Field(..., ge=0)
    status: MitigationOutcomeStatus
    decision: Optional[MitigationDecision] = None
    decision_uuid: Optional[str] = None
    advisory_only: bool = True

    model_config = ConfigDict(frozen=True)


class MitigationIntegrationResult(BaseModel):
    """Stage A orchestration result. No audit or enforcement data is included."""

    policy_version: Optional[str] = None
    outcomes: list[MitigationDecisionOutcome] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)
