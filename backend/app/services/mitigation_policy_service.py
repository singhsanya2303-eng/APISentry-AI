"""
Mitigation Policy Service — Stage 2B.

Pure, deterministic advisory policy engine over Stage 1 bot detection results.

CONTRACT:
  - Recommendations only: no middleware, database, cache, network, scheduling,
    or request-enforcement dependency.
  - Identical policy, context, and detection inputs always produce the same decision.
  - The incoming ``BotAnalysisResult`` is read-only and is never modified.
  - Bot risk remains independent of behavioural risk; this engine never calls or
    consults RiskScorer.
  - Missing, inferred, or incomplete evidence never becomes suspicion.
  - A non-finite Stage 1 bot score is an evidence-quality failure and returns ALLOW
    before any threshold comparison.
  - User-Agent novelty, request volume, endpoint/resource diversity, and shared-IP
    ambiguity are MONITOR-only signals.
  - ``monitoring_score_threshold`` gates MONITOR for weak-only suspicious results;
    benign automation is MONITOR regardless of score.
  - ``route_class`` is reserved for future non-enforcing reporting and is never
    read when making a decision.
  - Only opaque UUID5 evidence references from Stage 1 are emitted.

SECURITY CONTRACT:
  - Raw request IDs, User-Agent values, credentials, tokens, cookies, API keys,
    query values, and request bodies are neither read nor emitted.
  - Actor, API-key principal, and network keys must be SHA-256 hashes in the
    ``sha256:<64 lowercase hex characters>`` form supplied by verified upstream code.
  - Inferred actor IDs are never promoted to verified actor scope.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from app.schemas.bot_detection import (
    OPAQUE_REQUEST_ID_PATTERN,
    BotAnalysisResult,
    BotClassification,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision,
    MitigationDecisionType,
    MitigationPolicyConfig,
    MitigationPolicyMode,
    MitigationReasonCode,
    MitigationRequestContext,
    MitigationScopeType,
)

DEFAULT_MITIGATION_POLICY: MitigationPolicyConfig = MitigationPolicyConfig()

_OPAQUE_REQUEST_ID_RE = re.compile(OPAQUE_REQUEST_ID_PATTERN)

_GROUPED_AUTH_FAILURE_CODE = "REPEATED_AUTHENTICATION_FAILURES"
_RAW_AUTH_FAILURE_VOLUME_CODE = "AUTHENTICATION_FAILURE_VOLUME"
_SHARED_IP_AMBIGUITY_CODE = "SHARED_IP_ATTRIBUTION_AMBIGUOUS"
_INSUFFICIENT_EVIDENCE_CODES = frozenset(
    {"INSUFFICIENT_EVIDENCE", "MISSING_CLIENT_ATTRIBUTION"}
)

# Weak Stage 1 signals. These may justify MONITOR but never THROTTLE or BLOCK,
# regardless of the numeric bot score.
_WEAK_SIGNAL_CODES = frozenset(
    {
        "HIGH_REQUEST_VELOCITY",
        "AUTHENTICATION_FAILURE_VOLUME",
        "USER_AGENT_NOVELTY",
        "REQUEST_METHOD_PATTERN_VARIATION",
        "REQUEST_PATH_PATTERN_VARIATION",
        "HISTORICAL_METHOD_DEVIATION",
        "HISTORICAL_PATH_DEVIATION",
        "HIGH_ENDPOINT_DIVERSITY",
        "HIGH_RESOURCE_DIVERSITY",
        "STABLE_REPEATED_REQUEST_PATTERN",
        "STABLE_USER_AGENT",
    }
)


class _EvidenceSignals(NamedTuple):
    """Privacy-safe summary derived from a Stage 1 result."""

    grouped_auth_failure_count: int
    raw_auth_failure_count: int
    auth_evidence_source: str
    strong_auth_evidence: bool
    shared_ip_ambiguous: bool
    has_user_agent_novelty: bool
    has_high_request_volume: bool
    has_other_weak_signal: bool
    has_insufficient_evidence: bool


_EMPTY_SIGNALS = _EvidenceSignals(
    grouped_auth_failure_count=0,
    raw_auth_failure_count=0,
    auth_evidence_source="none",
    strong_auth_evidence=False,
    shared_ip_ambiguous=False,
    has_user_agent_novelty=False,
    has_high_request_volume=False,
    has_other_weak_signal=False,
    has_insufficient_evidence=True,
)


_REASON_DESCRIPTIONS: Dict[MitigationReasonCode, str] = {
    MitigationReasonCode.DETECTION_UNAVAILABLE: (
        "Detection did not complete, so no adverse recommendation was produced."
    ),
    MitigationReasonCode.POLICY_DISABLED: (
        "The advisory policy is disabled."
    ),
    MitigationReasonCode.EVIDENCE_INCOMPLETE: (
        "Detection evidence was incomplete, so the decision defaulted to allow."
    ),
    MitigationReasonCode.NON_FINITE_BOT_SCORE: (
        "The Stage 1 bot score was NaN or infinite, so no threshold comparison "
        "was performed and the decision defaulted to allow."
    ),
    MitigationReasonCode.HUMAN_LIKE_NO_ACTION: (
        "Stage 1 classified the traffic as human-like without suspicious evidence."
    ),
    MitigationReasonCode.INSUFFICIENT_EVIDENCE: (
        "Available evidence was insufficient to support any adverse recommendation."
    ),
    MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE: (
        "No strong suspicious evidence was observed."
    ),
    MitigationReasonCode.BENIGN_AUTOMATION_MONITOR: (
        "Stage 1 classified the traffic as benign automation."
    ),
    MitigationReasonCode.USER_AGENT_NOVELTY_MONITOR_ONLY: (
        "User-Agent novelty is a weak signal and was capped at monitor."
    ),
    MitigationReasonCode.HIGH_VOLUME_MONITOR_ONLY: (
        "High request volume is a weak signal and was capped at monitor."
    ),
    MitigationReasonCode.WEAK_SIGNAL_ONLY: (
        "Only weak supporting signals were present."
    ),
    MitigationReasonCode.SHARED_IP_AMBIGUITY: (
        "The network address has multiple actor identities or unattributed requests."
    ),
    MitigationReasonCode.SHARED_IP_NO_IP_ENFORCEMENT: (
        "Shared-IP ambiguity prevented any IP-wide adverse recommendation."
    ),
    MitigationReasonCode.INFERRED_ACTOR_NOT_TRUSTED: (
        "Inferred actor context was not trusted as verified identity."
    ),
    MitigationReasonCode.UNVERIFIED_ATTRIBUTION: (
        "Attribution was missing or unverified."
    ),
    MitigationReasonCode.ADMIN_PROTECTED: (
        "Verified administrator traffic was protected from adverse recommendations."
    ),
    MitigationReasonCode.CONTROL_PLANE_PROTECTED: (
        "Control-plane traffic was protected from adverse recommendations."
    ),
    MitigationReasonCode.SHADOW_MODE_NO_ENFORCEMENT: (
        "Shadow mode caps all recommendations at monitor."
    ),
    MitigationReasonCode.MONITOR_MODE_NO_ENFORCEMENT: (
        "Monitor mode caps all recommendations at monitor."
    ),
    MitigationReasonCode.SUSPICIOUS_BELOW_THRESHOLD: (
        "Suspicious evidence did not meet the configured escalation threshold."
    ),
    MitigationReasonCode.BELOW_MONITORING_THRESHOLD: (
        "Weak-only suspicious evidence was below the configured monitoring threshold."
    ),
    MitigationReasonCode.GROUPED_AUTH_FAILURE_EVIDENCE: (
        "Stage 1 reported grouped authentication-failure evidence."
    ),
    MitigationReasonCode.RAW_AUTH_FAILURE_VOLUME_EVIDENCE: (
        "Stage 1 reported raw authentication-failure volume from status-code "
        "evidence; no candidate pattern was reported."
    ),
    MitigationReasonCode.AUTH_FAILURE_REQUIREMENT_NOT_MET: (
        "The configured authentication-failure requirement was not met."
    ),
    MitigationReasonCode.SCORE_BELOW_THRESHOLD: (
        "The independent bot score did not meet the configured escalation threshold."
    ),
    MitigationReasonCode.THROTTLE_NOT_ENABLED: (
        "Throttling requires an explicit policy opt-in."
    ),
    MitigationReasonCode.BLOCK_NOT_ENABLED: (
        "Blocking is disabled unless explicitly enabled by policy."
    ),
    MitigationReasonCode.NETWORK_SCOPE_BLOCK_NOT_PERMITTED: (
        "IP attribution is network-level context and is never used for a block recommendation."
    ),
    MitigationReasonCode.UNATTRIBUTED_SCOPE_NO_ENFORCEMENT: (
        "No verified scope was available for an adverse recommendation."
    ),
    MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE: (
        "Qualifying authentication-failure evidence supports a temporary throttle."
    ),
    MitigationReasonCode.BLOCK_AUTH_FAILURE_EVIDENCE: (
        "Qualifying authentication-failure evidence supports a temporary block."
    ),
}


def _ensure_utc(value: datetime) -> datetime:
    """Interpret naive timestamps as UTC without mutating the caller's value."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _dedupe_reasons(
    reasons: Iterable[MitigationReasonCode],
) -> List[MitigationReasonCode]:
    """Stable de-duplication preserving first-seen order."""
    seen: Set[MitigationReasonCode] = set()
    result: List[MitigationReasonCode] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            result.append(reason)
    return result


def _collect_evidence_references(
    detection_result: Optional[BotAnalysisResult], max_references: int
) -> List[str]:
    """Return bounded opaque UUID5 references only, without touching Stage 1 state."""
    if detection_result is None or max_references <= 0:
        return []

    candidates: List[str] = []
    for reference in detection_result.evidence_references:
        candidates.append(reference.request_id)
    for reason in detection_result.reasons:
        candidates.extend(reason.request_ids)

    seen: Set[str] = set()
    references: List[str] = []
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        if not _OPAQUE_REQUEST_ID_RE.fullmatch(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        references.append(candidate)
        if len(references) >= max_references:
            break
    return references


def _resolve_scope(
    context: MitigationRequestContext,
) -> Tuple[MitigationScopeType, Optional[str], bool]:
    """Resolve a scope class from explicit, privacy-safe attribution only."""
    status = context.attribution_status

    if status == MitigationAttributionStatus.VERIFIED_USER:
        return (
            MitigationScopeType.VERIFIED_USER,
            context.actor_key_hash,
            True,
        )
    if status == MitigationAttributionStatus.API_KEY_PRINCIPAL:
        return (
            MitigationScopeType.API_KEY_PRINCIPAL,
            context.api_key_principal_hash,
            True,
        )
    if status == MitigationAttributionStatus.NETWORK_IP:
        return (
            MitigationScopeType.NETWORK_IP,
            context.network_key_hash,
            False,
        )
    return MitigationScopeType.UNATTRIBUTED, None, False


def _summarize_signals(
    detection_result: Optional[BotAnalysisResult], policy: MitigationPolicyConfig
) -> _EvidenceSignals:
    """Derive a conservative signal summary from Stage 1 reasons."""
    if detection_result is None:
        return _EMPTY_SIGNALS

    codes: Set[str] = {reason.code for reason in detection_result.reasons}
    counts: Dict[str, int] = {}
    for reason in detection_result.reasons:
        counts[reason.code] = max(counts.get(reason.code, 0), reason.evidence_count)

    grouped_count = counts.get(_GROUPED_AUTH_FAILURE_CODE, 0)
    raw_count = counts.get(_RAW_AUTH_FAILURE_VOLUME_CODE, 0)

    if grouped_count > 0:
        auth_evidence_source = "grouped"
    elif (
        not policy.require_grouped_brute_force
        and raw_count >= policy.minimum_authentication_failures
    ):
        auth_evidence_source = "raw_volume"
    else:
        auth_evidence_source = "none"

    strong_auth_evidence = auth_evidence_source != "none"

    other_weak_codes = codes & _WEAK_SIGNAL_CODES
    other_weak_codes.discard("HIGH_REQUEST_VELOCITY")
    other_weak_codes.discard("USER_AGENT_NOVELTY")
    other_weak_codes.discard(_RAW_AUTH_FAILURE_VOLUME_CODE)

    return _EvidenceSignals(
        grouped_auth_failure_count=grouped_count,
        raw_auth_failure_count=raw_count,
        auth_evidence_source=auth_evidence_source,
        strong_auth_evidence=strong_auth_evidence,
        shared_ip_ambiguous=_SHARED_IP_AMBIGUITY_CODE in codes,
        has_user_agent_novelty="USER_AGENT_NOVELTY" in codes,
        has_high_request_volume="HIGH_REQUEST_VELOCITY" in codes,
        has_other_weak_signal=bool(other_weak_codes),
        has_insufficient_evidence=bool(codes & _INSUFFICIENT_EVIDENCE_CODES)
        or detection_result.request_count == 0,
    )


def _explanation(
    decision: MitigationDecisionType,
    scope_type: MitigationScopeType,
    classification_value: str,
    verified_attribution: bool,
    reasons: List[MitigationReasonCode],
) -> str:
    """Build a neutral explanation from fixed text and non-sensitive classifications."""
    attribution = "verified" if verified_attribution else "unverified"
    descriptions = [
        _REASON_DESCRIPTIONS.get(
            reason, "Evidence was evaluated conservatively without enforcement."
        )
        for reason in reasons[:3]
    ]
    detail = " ".join(descriptions) if descriptions else "No adverse evidence was used."
    return (
        f"Advisory {decision.value} decision for {scope_type.value} scope with "
        f"{attribution} attribution. Stage 1 classification: {classification_value}. "
        f"{detail} No request enforcement is performed."
    )


def evaluate_mitigation_decision(
    detection_result: Optional[BotAnalysisResult],
    context: MitigationRequestContext,
    policy: Optional[MitigationPolicyConfig] = None,
) -> MitigationDecision:
    """Evaluate a Stage 1 bot result and return an advisory-only decision.

    This function is the entire Stage 2B policy engine. It performs no I/O, mutates
    no input, and never enforces its recommendation.
    """
    active_policy = policy if policy is not None else DEFAULT_MITIGATION_POLICY
    issued_at = _ensure_utc(context.evaluated_at)
    scope_type, scope_key_hash, verified_attribution = _resolve_scope(context)
    evidence_references = _collect_evidence_references(
        detection_result, active_policy.max_evidence_references
    )
    signals = _summarize_signals(detection_result, active_policy)

    classification_value = (
        detection_result.classification.value if detection_result is not None else "none"
    )
    reasons: List[MitigationReasonCode] = []
    add_reason = reasons.append

    def finalize(
        decision: MitigationDecisionType,
        *,
        expires_at: Optional[datetime] = None,
        rate_limit: Optional[int] = None,
        rate_limit_window_seconds: Optional[int] = None,
    ) -> MitigationDecision:
        ordered_reasons = _dedupe_reasons(reasons)
        return MitigationDecision(
            decision=decision,
            scope_type=scope_type,
            scope_key_hash=scope_key_hash,
            attribution_status=context.attribution_status,
            verified_attribution=verified_attribution,
            reason_codes=ordered_reasons,
            explanation=_explanation(
                decision,
                scope_type,
                classification_value,
                verified_attribution,
                ordered_reasons,
            ),
            policy_version=active_policy.policy_version,
            evidence_references=evidence_references,
            issued_at=issued_at,
            expires_at=_ensure_utc(expires_at) if expires_at is not None else None,
            rate_limit=rate_limit,
            rate_limit_window_seconds=rate_limit_window_seconds,
            advisory_only=True,
        )

    # 1. Absolute protection and unusable-input checks: highest precedence.
    if context.is_control_plane:
        add_reason(MitigationReasonCode.CONTROL_PLANE_PROTECTED)
        return finalize(MitigationDecisionType.ALLOW)

    admin_capped = False
    if context.is_admin:
        add_reason(MitigationReasonCode.ADMIN_PROTECTED)
        if active_policy.admin_protection_enabled:
            return finalize(MitigationDecisionType.ALLOW)
        # Even with the protection flag disabled, administrators are never blocked;
        # their traffic is limited to a monitor recommendation.
        admin_capped = True

    if not active_policy.enabled:
        add_reason(MitigationReasonCode.POLICY_DISABLED)
        return finalize(MitigationDecisionType.ALLOW)
    if not context.detection_available:
        add_reason(MitigationReasonCode.DETECTION_UNAVAILABLE)
        return finalize(MitigationDecisionType.ALLOW)
    if not context.evidence_complete:
        add_reason(MitigationReasonCode.EVIDENCE_INCOMPLETE)
        return finalize(MitigationDecisionType.ALLOW)
    if detection_result is None:
        add_reason(MitigationReasonCode.INSUFFICIENT_EVIDENCE)
        return finalize(MitigationDecisionType.ALLOW)
    # Boundary validation: a malformed score must never reach a threshold
    # comparison or influence THROTTLE/BLOCK eligibility.
    if not math.isfinite(detection_result.bot_risk_score):
        add_reason(MitigationReasonCode.NON_FINITE_BOT_SCORE)
        return finalize(MitigationDecisionType.ALLOW)
    if context.attribution_status == MitigationAttributionStatus.INFERRED:
        add_reason(MitigationReasonCode.INFERRED_ACTOR_NOT_TRUSTED)
        return finalize(MitigationDecisionType.ALLOW)
    if context.attribution_status == MitigationAttributionStatus.MISSING:
        add_reason(MitigationReasonCode.UNVERIFIED_ATTRIBUTION)
        return finalize(MitigationDecisionType.ALLOW)

    # 2. Stage 1 classification and evidence-quality defaults.
    if signals.has_insufficient_evidence:
        add_reason(MitigationReasonCode.INSUFFICIENT_EVIDENCE)
        return finalize(MitigationDecisionType.ALLOW)
    if detection_result.classification == BotClassification.UNKNOWN:
        add_reason(MitigationReasonCode.INSUFFICIENT_EVIDENCE)
        return finalize(MitigationDecisionType.ALLOW)
    if detection_result.classification == BotClassification.HUMAN_LIKE:
        if signals.strong_auth_evidence:
            # Detection must never label grouped brute-force evidence as
            # human_like. If such a result still reaches this engine (for
            # example a persisted or externally supplied result), do not
            # describe it as human-like or as having no suspicious evidence.
            # Stay advisory and conservative: ALLOW with INSUFFICIENT_EVIDENCE,
            # never HUMAN_LIKE_NO_ACTION / NO_SUSPICIOUS_EVIDENCE. No blocking,
            # banning, throttling, or enforcement is activated by this guard.
            add_reason(MitigationReasonCode.INSUFFICIENT_EVIDENCE)
        else:
            add_reason(MitigationReasonCode.HUMAN_LIKE_NO_ACTION)
            add_reason(MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE)
        return finalize(MitigationDecisionType.ALLOW)

    monitor_capped = False

    if detection_result.classification == BotClassification.AUTOMATION_BENIGN_CANDIDATE:
        add_reason(MitigationReasonCode.BENIGN_AUTOMATION_MONITOR)
        monitor_capped = True

    # 2b. The monitoring threshold gives monitoring_score_threshold a concrete
    #     purpose: weak-only suspicious evidence below it is insufficient even for
    #     MONITOR. Benign automation and strong auth evidence are unaffected.
    if (
        detection_result.classification == BotClassification.AUTOMATION_SUSPICIOUS
        and not signals.strong_auth_evidence
        and detection_result.bot_risk_score
        < active_policy.monitoring_score_threshold
    ):
        add_reason(MitigationReasonCode.BELOW_MONITORING_THRESHOLD)
        add_reason(MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE)
        return finalize(MitigationDecisionType.ALLOW)

    # 3. Weak-signal caps. These apply to weak-only evidence even when the numeric
    #    bot score is high. They do not cancel independently strong auth evidence.
    if not signals.strong_auth_evidence:
        if signals.has_user_agent_novelty:
            add_reason(MitigationReasonCode.USER_AGENT_NOVELTY_MONITOR_ONLY)
            monitor_capped = True
        if signals.has_high_request_volume:
            add_reason(MitigationReasonCode.HIGH_VOLUME_MONITOR_ONLY)
            monitor_capped = True
        if signals.has_other_weak_signal:
            add_reason(MitigationReasonCode.WEAK_SIGNAL_ONLY)
            monitor_capped = True
    if signals.shared_ip_ambiguous:
        add_reason(MitigationReasonCode.SHARED_IP_AMBIGUITY)
        if scope_type == MitigationScopeType.NETWORK_IP:
            add_reason(MitigationReasonCode.SHARED_IP_NO_IP_ENFORCEMENT)
            monitor_capped = True

    # 4. Strong-evidence and threshold assessment.
    if detection_result.classification == BotClassification.AUTOMATION_SUSPICIOUS:
        if not signals.strong_auth_evidence:
            add_reason(MitigationReasonCode.WEAK_SIGNAL_ONLY)
            add_reason(MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE)
            monitor_capped = True
        else:
            if signals.auth_evidence_source == "grouped":
                add_reason(MitigationReasonCode.GROUPED_AUTH_FAILURE_EVIDENCE)
                auth_count = signals.grouped_auth_failure_count
            else:
                add_reason(MitigationReasonCode.RAW_AUTH_FAILURE_VOLUME_EVIDENCE)
                auth_count = signals.raw_auth_failure_count
            if auth_count < active_policy.minimum_authentication_failures:
                add_reason(MitigationReasonCode.AUTH_FAILURE_REQUIREMENT_NOT_MET)
                monitor_capped = True
            elif detection_result.bot_risk_score < active_policy.throttling_score_threshold:
                add_reason(MitigationReasonCode.SCORE_BELOW_THRESHOLD)
                monitor_capped = True
    else:
        monitor_capped = True

    # 5. Policy-mode caps. ``enforce`` is only a configuration value in Stage 2B.
    if active_policy.mode == MitigationPolicyMode.SHADOW:
        add_reason(MitigationReasonCode.SHADOW_MODE_NO_ENFORCEMENT)
        monitor_capped = True
    elif active_policy.mode == MitigationPolicyMode.MONITOR:
        add_reason(MitigationReasonCode.MONITOR_MODE_NO_ENFORCEMENT)
        monitor_capped = True

    # 6. Scope eligibility caps.
    if scope_type == MitigationScopeType.UNATTRIBUTED:
        add_reason(MitigationReasonCode.UNATTRIBUTED_SCOPE_NO_ENFORCEMENT)
        monitor_capped = True

    if admin_capped:
        monitor_capped = True

    if monitor_capped:
        return finalize(MitigationDecisionType.MONITOR)

    # 7. Block first, then throttle. BLOCK is opt-in, temporary, and never IP-wide.
    if scope_type == MitigationScopeType.NETWORK_IP:
        add_reason(MitigationReasonCode.NETWORK_SCOPE_BLOCK_NOT_PERMITTED)
    elif not active_policy.block_enabled:
        add_reason(MitigationReasonCode.BLOCK_NOT_ENABLED)
    elif detection_result.bot_risk_score < active_policy.blocking_score_threshold:
        add_reason(MitigationReasonCode.SCORE_BELOW_THRESHOLD)

    can_block = (
        active_policy.block_enabled
        and detection_result.bot_risk_score >= active_policy.blocking_score_threshold
        and scope_type
        in (MitigationScopeType.VERIFIED_USER, MitigationScopeType.API_KEY_PRINCIPAL)
    )
    if can_block:
        add_reason(MitigationReasonCode.BLOCK_AUTH_FAILURE_EVIDENCE)
        bounded_duration = min(
            active_policy.block_duration_seconds,
            active_policy.max_block_duration_seconds,
        )
        return finalize(
            MitigationDecisionType.BLOCK,
            expires_at=issued_at + timedelta(seconds=bounded_duration),
        )

    if not active_policy.throttle_enabled:
        add_reason(MitigationReasonCode.THROTTLE_NOT_ENABLED)
        return finalize(MitigationDecisionType.MONITOR)

    add_reason(MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE)
    return finalize(
        MitigationDecisionType.THROTTLE,
        expires_at=issued_at
        + timedelta(seconds=active_policy.throttle_duration_seconds),
        rate_limit=active_policy.throttle_limit,
        rate_limit_window_seconds=active_policy.throttle_window_seconds,
    )


# Descriptor-style alias for callers that prefer service naming conventions.
MitigationPolicyService = evaluate_mitigation_decision

__all__ = [
    "DEFAULT_MITIGATION_POLICY",
    "MitigationPolicyService",
    "evaluate_mitigation_decision",
]
