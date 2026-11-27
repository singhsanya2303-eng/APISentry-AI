"""Schemas for the dedicated isolated request-time enforcement demo (WP9).

These contracts describe only synthetic, explicitly enabled, loopback demo
state. They never represent production enforcement state or real traffic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_REQUEST_DEMO_SCENARIOS = Literal["allow", "block", "throttle"]


class RequestDemoEnableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["ENABLE_ISOLATED_REQUEST_ENFORCEMENT_DEMO"]
    demo_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    policy_version: str = Field(..., min_length=1, max_length=64)
    scenario: _REQUEST_DEMO_SCENARIOS
    max_requests: int = Field(default=12, ge=1, le=50)
    max_duration_seconds: int = Field(default=300, ge=10, le=900)
    synthetic_only_ack: bool = True
    loopback_only_ack: bool = True
    isolated_db_ack: bool = True

    @field_validator("synthetic_only_ack", "loopback_only_ack", "isolated_db_ack")
    @classmethod
    def _must_be_true(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("explicit acknowledgement is required")
        return value


class RequestDemoRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    demo_id: str = Field(..., min_length=1, max_length=64)
    synthetic: Literal[True]
    request_count: int = Field(default=1, ge=1, le=10)


class RequestDemoDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="operator_disable", min_length=1, max_length=64)


class RequestDemoStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    demo_enabled: bool
    enforcement_enabled: bool
    advisory_only: bool
    kill_switch_active: bool
    loopback_only: bool
    synthetic_only: bool
    production_middleware_registered: bool
    real_enforcement: bool
    demo_id: str | None
    scenario: str | None
    policy_version: str | None
    max_requests: int
    requests_executed: int
    started_at: datetime | None
    decision_count: int
    audit_event_count: int
    persistence_db: str
    status_reason: str
    guards: dict[str, Any]


class RequestDemoOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    status_code: int
    enforcement_action: str | None
    enforcement_outcome: str | None
    handler_reached: bool
    decision_ref: str | None
    request_ref: str | None


class RequestDemoRunResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    demo_id: str
    scenario: str
    outcomes: list[RequestDemoOutcome]
    status: RequestDemoStatusResponse


class RequestDemoFailClosedResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status_code: int
    detail: str
    enforcement_outcome: str | None
    handler_reached: bool
    real_enforcement: bool
    production_middleware_registered: bool


class RequestDemoEvidenceResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_count: int
    audit_event_count: int
    decisions: list[dict[str, Any]]
    audit_events: list[dict[str, Any]]
