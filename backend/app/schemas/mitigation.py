"""
Mitigation Policy Schemas — Stage 2B.

Advisory-only schemas for the deterministic Mitigation Policy Engine.

SECURITY CONTRACT:
  - This module produces recommendations only. It does not enforce requests.
  - No raw request IDs, User-Agent values, credentials, tokens, cookies, API keys,
    query values, or request bodies are represented.
  - Actor, API-key principal, and network identifiers must be SHA-256 hashes in
    the documented ``sha256:<64 lowercase hex characters>`` form.
  - Stage 1 evidence references are reused only in their opaque UUID5 form.
  - Bot risk remains independent of behavioural risk scoring.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.bot_detection import OpaqueRequestId

# Explicit scope-key representation. The prefix prevents raw identifiers or
# arbitrary strings from being mistaken for pre-hashed scope keys. The same
# format is used for every scope type; field names and MitigationScopeType keep
# user, API-key principal, and network attribution distinct.
SCOPE_KEY_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"
ScopeKeyHash = Annotated[
    str,
    Field(
        pattern=SCOPE_KEY_HASH_PATTERN,
        min_length=71,
        max_length=71,
        description="SHA-256 hash encoded as sha256:<64 lowercase hex characters>",
    ),
]


class MitigationDecisionType(str, Enum):
    """Advisory mitigation decision emitted by Stage 2B."""

    ALLOW = "allow"
    MONITOR = "monitor"
    THROTTLE = "throttle"
    BLOCK = "block"


class MitigationPolicyMode(str, Enum):
    """Policy mode. ``enforce`` is configuration only in Stage 2B."""

    SHADOW = "shadow"
    MONITOR = "monitor"
    ENFORCE = "enforce"


class MitigationScopeType(str, Enum):
    """Scope class for an advisory decision."""

    VERIFIED_USER = "verified_user"
    API_KEY_PRINCIPAL = "api_key_principal"
    NETWORK_IP = "network_ip"
    UNATTRIBUTED = "unattributed"


class MitigationAttributionStatus(str, Enum):
    """Trust level of the attribution supplied to the policy engine."""

    VERIFIED_USER = "verified_user"
    API_KEY_PRINCIPAL = "api_key_principal"
    NETWORK_IP = "network_ip"
    INFERRED = "inferred"
    MISSING = "missing"


class MitigationReasonCode(str, Enum):
    """Stable machine-readable reasons for mitigation recommendations."""

    DETECTION_UNAVAILABLE = "detection_unavailable"
    POLICY_DISABLED = "policy_disabled"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    NON_FINITE_BOT_SCORE = "non_finite_bot_score"
    HUMAN_LIKE_NO_ACTION = "human_like_no_action"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NO_SUSPICIOUS_EVIDENCE = "no_suspicious_evidence"
    BENIGN_AUTOMATION_MONITOR = "benign_automation_monitor"
    USER_AGENT_NOVELTY_MONITOR_ONLY = "user_agent_novelty_monitor_only"
    HIGH_VOLUME_MONITOR_ONLY = "high_volume_monitor_only"
    WEAK_SIGNAL_ONLY = "weak_signal_only"
    SHARED_IP_AMBIGUITY = "shared_ip_ambiguity"
    SHARED_IP_NO_IP_ENFORCEMENT = "shared_ip_no_ip_enforcement"
    INFERRED_ACTOR_NOT_TRUSTED = "inferred_actor_not_trusted"
    UNVERIFIED_ATTRIBUTION = "unverified_attribution"
    ADMIN_PROTECTED = "admin_protected"
    CONTROL_PLANE_PROTECTED = "control_plane_protected"
    SHADOW_MODE_NO_ENFORCEMENT = "shadow_mode_no_enforcement"
    MONITOR_MODE_NO_ENFORCEMENT = "monitor_mode_no_enforcement"
    SUSPICIOUS_BELOW_THRESHOLD = "suspicious_below_threshold"
    BELOW_MONITORING_THRESHOLD = "below_monitoring_threshold"
    GROUPED_AUTH_FAILURE_EVIDENCE = "grouped_auth_failure_evidence"
    RAW_AUTH_FAILURE_VOLUME_EVIDENCE = "raw_auth_failure_volume_evidence"
    AUTH_FAILURE_REQUIREMENT_NOT_MET = "auth_failure_requirement_not_met"
    SCORE_BELOW_THRESHOLD = "score_below_threshold"
    THROTTLE_NOT_ENABLED = "throttle_not_enabled"
    BLOCK_NOT_ENABLED = "block_not_enabled"
    NETWORK_SCOPE_BLOCK_NOT_PERMITTED = "network_scope_block_not_permitted"
    UNATTRIBUTED_SCOPE_NO_ENFORCEMENT = "unattributed_scope_no_enforcement"
    THROTTLE_AUTH_FAILURE_EVIDENCE = "throttle_auth_failure_evidence"
    BLOCK_AUTH_FAILURE_EVIDENCE = "block_auth_failure_evidence"


class MitigationPolicyConfig(BaseModel):
    """Validated, conservative defaults for advisory mitigation decisions."""

    enabled: bool = Field(
        default=True,
        description="When false, the engine always recommends ALLOW.",
    )
    mode: MitigationPolicyMode = Field(
        default=MitigationPolicyMode.MONITOR,
        description=(
            "shadow emits no enforcement recommendation; monitor caps at MONITOR; "
            "enforce permits throttle/block recommendations. Enforce is only a "
            "policy configuration value in Stage 2B."
        ),
    )
    policy_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=64,
        description="Stable version recorded on every advisory decision.",
    )

    monitoring_score_threshold: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description=(
            "Minimum independent bot score for weak-only suspicious evidence to "
            "produce MONITOR. Below this value, weak-only suspicious evidence is "
            "treated as insufficient and returns ALLOW. Benign automation remains "
            "MONITOR regardless of score."
        ),
    )
    throttling_score_threshold: float = Field(
        default=75.0,
        ge=0.0,
        le=100.0,
        description="Bot score required for a THROTTLE recommendation.",
    )
    blocking_score_threshold: float = Field(
        default=90.0,
        ge=0.0,
        le=100.0,
        description="Bot score required for a BLOCK recommendation.",
    )

    minimum_authentication_failures: int = Field(
        default=5,
        ge=1,
        le=1000,
        description=(
            "Authentication failures required for escalation. When "
            "require_grouped_brute_force is true, only grouped failures count; when "
            "false, raw authentication-failure volume may qualify."
        ),
    )
    require_grouped_brute_force: bool = Field(
        default=True,
        description="Require grouped brute-force evidence before throttling or blocking.",
    )

    throttle_enabled: bool = Field(
        default=False,
        description="THROTTLE recommendations require this explicit opt-in.",
    )
    throttle_limit: int = Field(
        default=60,
        ge=1,
        le=100000,
        description="Advisory request limit per throttle window.",
    )
    throttle_window_seconds: int = Field(
        default=60,
        ge=1,
        le=86400,
        description="Advisory throttle window length in seconds.",
    )
    throttle_duration_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description="Bounded duration of a THROTTLE recommendation.",
    )

    block_enabled: bool = Field(
        default=False,
        description="BLOCK is disabled by default and requires explicit opt-in.",
    )
    block_duration_seconds: int = Field(
        default=900,
        ge=1,
        le=86400,
        description="Bounded duration of a BLOCK recommendation.",
    )
    max_block_duration_seconds: int = Field(
        default=3600,
        ge=1,
        le=604800,
        description="Hard upper bound for any BLOCK recommendation.",
    )

    admin_protection_enabled: bool = Field(
        default=True,
        description="Protect verified administrators from throttling and blocking.",
    )
    max_evidence_references: int = Field(
        default=25,
        ge=0,
        le=200,
        description="Maximum number of opaque evidence references emitted.",
    )

    # Reject NaN and +/-infinity for all float fields before range/order checks.
    model_config = ConfigDict(from_attributes=True, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_threshold_and_duration_ordering(self) -> "MitigationPolicyConfig":
        if not (
            0.0
            <= self.monitoring_score_threshold
            <= self.throttling_score_threshold
            <= self.blocking_score_threshold
            <= 100.0
        ):
            raise ValueError(
                "Thresholds must satisfy 0 <= monitoring <= throttling <= blocking <= 100"
            )
        if self.max_block_duration_seconds < self.block_duration_seconds:
            raise ValueError(
                "max_block_duration_seconds must be greater than or equal to "
                "block_duration_seconds"
            )
        return self


class MitigationRequestContext(BaseModel):
    """Verified, privacy-safe context supplied by the caller.

    The policy engine does not read headers, middleware state, databases, or request
    bodies. All identity values must be hashes produced by trusted upstream code.
    """

    evaluated_at: datetime = Field(
        ...,
        description="UTC timestamp used as the deterministic issued_at value.",
    )
    route_class: str = Field(
        default="general_api",
        min_length=1,
        max_length=100,
        description=(
            "Reserved for future non-enforcing audit/reporting classification. "
            "Stage 2B does not read this value when making decisions; no route-"
            "specific enforcement is implemented."
        ),
    )
    is_control_plane: bool = Field(
        default=False,
        description="True for mitigation/admin control-plane routes.",
    )
    is_admin: bool = Field(
        default=False,
        description="True only when a verified admin principal is present.",
    )
    attribution_status: MitigationAttributionStatus = Field(
        default=MitigationAttributionStatus.MISSING,
        description="Trust level of the supplied attribution.",
    )
    actor_key_hash: Optional[ScopeKeyHash] = Field(
        default=None,
        description="SHA-256 hash of a verified user actor; never a raw actor ID.",
    )
    api_key_principal_hash: Optional[ScopeKeyHash] = Field(
        default=None,
        description=(
            "SHA-256 hash of an API-key principal; distinct from a verified user."
        ),
    )
    network_key_hash: Optional[ScopeKeyHash] = Field(
        default=None,
        description=(
            "SHA-256 hash of server-derived network attribution, not an individual "
            "identity."
        ),
    )
    inferred_actor_key_hash: Optional[ScopeKeyHash] = Field(
        default=None,
        description=(
            "SHA-256 hash of an inferred/unverified actor. Accepted for visibility "
            "only; never used as an actor scope."
        ),
    )
    detection_available: bool = Field(
        default=True,
        description="False when Stage 1 detection could not be completed.",
    )
    evidence_complete: bool = Field(
        default=True,
        description="False when detection evidence is incomplete or truncated.",
    )

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def validate_verified_scope_hashes(self) -> "MitigationRequestContext":
        if (
            self.attribution_status == MitigationAttributionStatus.VERIFIED_USER
            and not self.actor_key_hash
        ):
            raise ValueError("verified user attribution requires actor_key_hash")
        if (
            self.attribution_status == MitigationAttributionStatus.API_KEY_PRINCIPAL
            and not self.api_key_principal_hash
        ):
            raise ValueError(
                "API-key principal attribution requires api_key_principal_hash"
            )
        if (
            self.attribution_status == MitigationAttributionStatus.NETWORK_IP
            and not self.network_key_hash
        ):
            raise ValueError("network attribution requires network_key_hash")
        return self

    @model_validator(mode="after")
    def validate_admin_attribution(self) -> "MitigationRequestContext":
        if self.is_admin and (
            self.attribution_status != MitigationAttributionStatus.VERIFIED_USER
            or not self.actor_key_hash
        ):
            raise ValueError(
                "is_admin=true requires verified_user attribution and a valid "
                "actor_key_hash"
            )
        return self


class MitigationDecision(BaseModel):
    """Deterministic advisory output. No enforcement is represented."""

    decision: MitigationDecisionType = Field(..., description="Advisory decision.")
    scope_type: MitigationScopeType = Field(..., description="Resolved scope class.")
    scope_key_hash: Optional[ScopeKeyHash] = Field(
        default=None,
        description=(
            "SHA-256 scope hash identifying the resolved scope; None when "
            "unattributed."
        ),
    )
    attribution_status: MitigationAttributionStatus = Field(
        ..., description="Original attribution trust level supplied by the caller."
    )
    verified_attribution: bool = Field(
        ..., description="True only for verified user or API-key principal scopes."
    )
    reason_codes: List[MitigationReasonCode] = Field(
        default_factory=list,
        description="Ordered, deduplicated machine-readable reasons.",
    )
    explanation: str = Field(
        ..., min_length=1, description="Neutral, non-sensitive explanation."
    )
    policy_version: str = Field(..., min_length=1)
    evidence_references: List[OpaqueRequestId] = Field(
        default_factory=list,
        description="Bounded opaque UUID5 references from Stage 1 evidence.",
    )
    issued_at: datetime = Field(..., description="UTC issuance time from context.")
    expires_at: Optional[datetime] = Field(
        default=None,
        description="UTC expiry for temporary throttle/block recommendations only.",
    )
    rate_limit: Optional[int] = Field(
        default=None, ge=1, description="Advisory limit for THROTTLE recommendations."
    )
    rate_limit_window_seconds: Optional[int] = Field(
        default=None,
        ge=1,
        description="Advisory window for THROTTLE recommendations.",
    )
    advisory_only: bool = Field(
        default=True,
        description="Always true in Stage 2B; no request enforcement is performed.",
    )

    model_config = ConfigDict(from_attributes=True)
