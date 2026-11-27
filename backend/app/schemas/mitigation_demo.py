"""Schemas for the Gate E isolated local enforcement demonstration.

All models are demo-only. They never represent production enforcement state.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision,
    MitigationScopeType,
)


class DemoEnableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["ENABLE_LOCAL_DEMO"]
    policy_version: str = Field(..., min_length=1, max_length=64)
    max_requests: int = Field(default=25, ge=1, le=100)
    max_duration_seconds: int = Field(default=300, ge=10, le=900)
    # Synthetic request descriptors are provided at run time; this declares intent.
    synthetic_only_ack: bool = True
    loopback_only_ack: bool = True

    @field_validator("synthetic_only_ack", "loopback_only_ack")
    @classmethod
    def _must_be_true(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("explicit acknowledgement is required")
        return value


class DemoDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="operator_disable", min_length=1, max_length=64)


class DemoSyntheticRequest(BaseModel):
    """One deterministic synthetic request descriptor. No raw payloads are stored."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., min_length=1, max_length=64)
    client_ip: str = Field(default="127.0.0.1", min_length=3, max_length=45)
    method: str = Field(default="GET", min_length=1, max_length=16)
    path: str = Field(default="/api/v1/demo/resource", min_length=1, max_length=256)
    status_code: int = Field(default=200, ge=100, le=599)
    user_agent: str = Field(default="APISentryDemo/1.0", min_length=1, max_length=256)
    # High-level synthetic scenario label; not a raw payload.
    scenario: str = Field(default="benign", min_length=1, max_length=64)
    # Optional advisory inputs used by the demo evaluator. All are synthetic.
    bot_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    auth_failures: int = Field(default=0, ge=0, le=10000)
    authenticated: bool = False
    principal_hash: str | None = Field(default=None, max_length=71)
    attribution_status: MitigationAttributionStatus = MitigationAttributionStatus.MISSING
    scope_type: MitigationScopeType = MitigationScopeType.UNATTRIBUTED
    requested_action: Literal["allow", "monitor", "throttle", "block"] | None = None


class DemoRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    demo_id: str = Field(..., min_length=1, max_length=64)
    synthetic: Literal[True]
    requests: list[DemoSyntheticRequest] = Field(..., min_length=1, max_length=100)


class DemoRequestOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    scenario: str
    allowed: bool
    enforcement_state: Literal["advisory_only", "enforced_block", "enforced_allow"]
    intended_action: str | None
    actual_outcome: str
    reason: str
    decision_uuid: str | None
    policy_version: str | None
    audit_event_uuid: str | None
    evidence_references: list[str]
    advisory_only: bool


class DemoRunResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    demo_id: str
    demo_mode: bool
    enforcement_enabled: bool
    kill_switch_active: bool
    advisory_only: bool
    policy_version: str | None
    executed_requests: int
    max_requests: int
    max_duration_seconds: int
    started_at: datetime | None
    expires_at: datetime | None
    outcomes: list[DemoRequestOutcome]
    stopped_reason: str | None


class DemoStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    demo_mode: bool
    enforcement_enabled: bool
    kill_switch_active: bool
    advisory_only: bool
    loopback_only: bool
    synthetic_only: bool
    active_demo_id: str | None
    policy_version: str | None
    max_requests: int
    max_duration_seconds: int
    requests_executed: int
    started_at: datetime | None
    expires_at: datetime | None
    last_decision_outcome: str | None
    last_decision_uuid: str | None
    persistence_db: str
    guards: dict[str, Any]
    expired: bool = False
    status_reason: str | None = None
    real_enforcement: bool = False
