"""MW4-A runtime integration schemas.

Advisory-only contracts for composing existing bot detection, MW2 advanced
advisory signals, MW1 unified risk assessment, and optional Stage A mitigation
integration. No enforcement, no persistence claims, no combined score.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.advanced_detection_signals import AdvancedDetectionEnvelope
from app.schemas.bot_detection import BotDetectionResponse
from app.schemas.mitigation_integration import MitigationIntegrationResult
from app.schemas.unified_risk_assessment import (
    SignalStatus,
    UnifiedRiskAssessment,
)


class MW4SignalNormalization(BaseModel):
    """Explicit normalization/provenance record for one runtime signal input."""

    model_config = ConfigDict(extra="forbid")

    signal: str = Field(..., min_length=1, max_length=128)
    status: str = Field(..., min_length=1, max_length=64)
    source: str = Field(default="", max_length=256)
    note: str = Field(default="", max_length=500)
    error_code: Optional[str] = Field(default=None, max_length=64)


class MW4RuntimeResult(BaseModel):
    """Per-detection-result MW4 advisory composition."""

    model_config = ConfigDict(extra="forbid")

    result_index: int = Field(..., ge=0)
    subject_ref: Optional[str] = Field(default=None, max_length=128)
    mw2_advanced_detection: AdvancedDetectionEnvelope
    mw1_unified_assessment: Optional[UnifiedRiskAssessment] = None
    mw1_status: str = Field(..., min_length=1, max_length=64)
    mw1_error: Optional[str] = Field(default=None, max_length=300)
    signal_normalization: list[MW4SignalNormalization] = Field(default_factory=list)
    advisory_only: bool = True


class MW4RuntimeTimings(BaseModel):
    """Lightweight, non-sensitive runtime timing diagnostics."""

    model_config = ConfigDict(extra="forbid")

    mw2_ms: float = Field(..., ge=0.0)
    mw1_ms: float = Field(..., ge=0.0)
    total_ms: float = Field(..., ge=0.0)


class MW4RuntimeAnalysisResponse(BaseModel):
    """Detection + MW2 + MW1 + optional Stage A mitigation, all advisory-only."""

    model_config = ConfigDict(extra="forbid")

    detection: BotDetectionResponse
    mw2_advanced_detection: list[MW4RuntimeResult] = Field(default_factory=list)
    mw1_unified_risk_assessment: list[MW4RuntimeResult] = Field(default_factory=list)
    runtime_results: list[MW4RuntimeResult] = Field(default_factory=list)
    mitigation: Optional[MitigationIntegrationResult] = None
    timings_ms: Optional[MW4RuntimeTimings] = None
    advisory_only: bool = True
    enforcement_executed: bool = False
    provenance: dict[str, Any] = Field(default_factory=dict)
    uncertainty: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "MW4RuntimeAnalysisResponse",
    "MW4RuntimeResult",
    "MW4RuntimeTimings",
    "MW4SignalNormalization",
]
