"""Focused unit tests for the Stage 2B advisory mitigation policy engine."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

import pytest
from pydantic import ValidationError

from app.schemas.bot_detection import (
    BotAnalysisResult,
    BotClassification,
    BotEvidenceReference,
    BotReason,
    BotReasonCategory,
    BotReasonSeverity,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecisionType,
    MitigationPolicyConfig,
    MitigationPolicyMode,
    MitigationReasonCode,
    MitigationRequestContext,
    MitigationScopeType,
)
from app.services.mitigation_policy_service import evaluate_mitigation_decision

FIXED_NOW = datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc)
_OPAQUE_NAMESPACE = uuid.UUID("7f3a2b91-6c4d-4e8f-9a2b-5c8d1e7f0a34")


def _opaque(label: str) -> str:
    """Return a valid opaque UUID5 reference in the Stage 1 namespace."""
    return str(uuid.uuid5(_OPAQUE_NAMESPACE, f"stage2b-test:{label}"))


def _scope_hash(label: str) -> str:
    """Return a valid pre-hashed scope key in the required representation."""
    digest = hashlib.sha256(f"stage2b-test:{label}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


ACTOR_SCOPE_HASH = _scope_hash("actor")
API_KEY_SCOPE_HASH = _scope_hash("api-key-principal")
NETWORK_SCOPE_HASH = _scope_hash("network")
INFERRED_SCOPE_HASH = _scope_hash("inferred-actor")


def _refs(prefix: str, count: int = 3) -> list[str]:
    return [_opaque(f"{prefix}-{index}") for index in range(count)]


def _reason(
    code: str,
    category: BotReasonCategory,
    *,
    evidence_count: int = 0,
    refs: list[str] | None = None,
) -> BotReason:
    return BotReason(
        code=code,
        category=category,
        description=f"Neutral test evidence for {code}.",
        severity=BotReasonSeverity.HIGH,
        evidence_count=evidence_count,
        request_ids=refs or [],
    )


def _result(
    classification: BotClassification,
    score: float,
    *,
    reasons: list[BotReason] | None = None,
    refs: list[str] | None = None,
    request_count: int = 10,
) -> BotAnalysisResult:
    evidence_refs = refs if refs is not None else _refs("result")
    return BotAnalysisResult(
        client_ip=None,
        actor_id=None,
        bot_risk_score=score,
        classification=classification,
        reasons=reasons or [],
        score_factors=[],
        evidence_references=[
            BotEvidenceReference(
                request_id=reference,
                source="TEST_SIGNAL",
                observed_at=FIXED_NOW,
            )
            for reference in evidence_refs
        ],
        request_count=request_count,
        first_seen=FIXED_NOW - timedelta(minutes=5),
        last_seen=FIXED_NOW,
        observation_window_seconds=300.0,
        summary="Neutral Stage 1 test summary.",
    )


def _grouped_result(
    *,
    score: float = 95.0,
    failures: int = 6,
    shared_ip: bool = False,
) -> BotAnalysisResult:
    refs = _refs("auth")
    request_count_value = 15
    reasons = [
        _reason(
            "REPEATED_AUTHENTICATION_FAILURES",
            BotReasonCategory.AUTHENTICATION,
            evidence_count=failures,
            refs=refs,
        ),
        _reason(
            "BRUTE_FORCE_OVERRIDE",
            BotReasonCategory.AUTHENTICATION,
            evidence_count=0,
        ),
    ]
    if shared_ip:
        reasons.append(
            _reason(
                "SHARED_IP_ATTRIBUTION_AMBIGUOUS",
                BotReasonCategory.EVIDENCE_QUALITY,
                evidence_count=request_count_value,
                refs=refs,
            )
        )
    return _result(
        BotClassification.AUTOMATION_SUSPICIOUS,
        score,
        reasons=reasons,
        refs=refs,
        request_count=15,
    )


def _raw_volume_result(
    *, score: float = 80.0, failures: int = 6
) -> BotAnalysisResult:
    refs = _refs("raw-auth")
    return _result(
        BotClassification.AUTOMATION_SUSPICIOUS,
        score,
        reasons=[
            _reason(
                "AUTHENTICATION_FAILURE_VOLUME",
                BotReasonCategory.AUTHENTICATION,
                evidence_count=failures,
                refs=refs,
            )
        ],
        refs=refs,
        request_count=15,
    )


def _context(**overrides: object) -> MitigationRequestContext:
    values: dict[str, object] = {
        "evaluated_at": FIXED_NOW,
        "attribution_status": MitigationAttributionStatus.VERIFIED_USER,
        "actor_key_hash": ACTOR_SCOPE_HASH,
    }
    values.update(overrides)
    return MitigationRequestContext(**values)  # type: ignore[arg-type]


def _policy(**overrides: object) -> MitigationPolicyConfig:
    return MitigationPolicyConfig(**overrides)  # type: ignore[arg-type]


def _enforce_policy(**overrides: object) -> MitigationPolicyConfig:
    values: dict[str, object] = {
        "mode": MitigationPolicyMode.ENFORCE,
        "throttle_enabled": True,
        "block_enabled": True,
    }
    values.update(overrides)
    return _policy(**values)


def _codes(decision: object) -> set[MitigationReasonCode]:
    return set(decision.reason_codes)  # type: ignore[attr-defined]


def test_normal_human_traffic_produces_allow() -> None:
    decision = evaluate_mitigation_decision(
        _result(BotClassification.HUMAN_LIKE, 2.5),
        _context(),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.advisory_only is True
    assert decision.expires_at is None
    assert decision.rate_limit is None
    assert MitigationReasonCode.HUMAN_LIKE_NO_ACTION in _codes(decision)


def test_benign_automation_produces_monitor() -> None:
    result = _result(
        BotClassification.AUTOMATION_BENIGN_CANDIDATE,
        40.0,
        reasons=[
            _reason(
                "HIGH_REQUEST_VELOCITY",
                BotReasonCategory.RATE_ANOMALY,
                evidence_count=60,
            )
        ],
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    assert decision.decision == MitigationDecisionType.MONITOR
    assert MitigationReasonCode.BENIGN_AUTOMATION_MONITOR in _codes(decision)
    assert MitigationReasonCode.HIGH_VOLUME_MONITOR_ONLY in _codes(decision)


def test_unknown_classification_produces_allow() -> None:
    result = _result(
        BotClassification.UNKNOWN,
        0.0,
        reasons=[
            _reason(
                "INSUFFICIENT_EVIDENCE",
                BotReasonCategory.EVIDENCE_QUALITY,
                evidence_count=2,
            )
        ],
        request_count=2,
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    assert decision.decision == MitigationDecisionType.ALLOW
    assert MitigationReasonCode.INSUFFICIENT_EVIDENCE in _codes(decision)


def test_user_agent_novelty_alone_never_throttles_or_blocks() -> None:
    result = _result(
        BotClassification.AUTOMATION_BENIGN_CANDIDATE,
        99.0,
        reasons=[
            _reason(
                "USER_AGENT_NOVELTY",
                BotReasonCategory.USER_AGENT,
                evidence_count=1,
            )
        ],
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    assert decision.decision == MitigationDecisionType.MONITOR
    assert MitigationReasonCode.USER_AGENT_NOVELTY_MONITOR_ONLY in _codes(decision)
    assert "NovelClient" not in decision.model_dump_json()


def test_high_request_volume_alone_never_blocks() -> None:
    result = _result(
        BotClassification.AUTOMATION_BENIGN_CANDIDATE,
        100.0,
        reasons=[
            _reason(
                "HIGH_REQUEST_VELOCITY",
                BotReasonCategory.RATE_ANOMALY,
                evidence_count=500,
            )
        ],
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    assert decision.decision == MitigationDecisionType.MONITOR
    assert decision.decision != MitigationDecisionType.BLOCK
    assert MitigationReasonCode.HIGH_VOLUME_MONITOR_ONLY in _codes(decision)


def test_shared_ip_ambiguity_prevents_ip_wide_block() -> None:
    context = _context(
        attribution_status=MitigationAttributionStatus.NETWORK_IP,
        actor_key_hash=None,
        network_key_hash=NETWORK_SCOPE_HASH,
    )
    result = _grouped_result(score=100.0, failures=10, shared_ip=True)

    decision = evaluate_mitigation_decision(result, context, _enforce_policy())

    assert decision.decision == MitigationDecisionType.MONITOR
    assert decision.scope_type == MitigationScopeType.NETWORK_IP
    assert decision.scope_key_hash == NETWORK_SCOPE_HASH
    assert MitigationReasonCode.SHARED_IP_NO_IP_ENFORCEMENT in _codes(decision)


def test_verified_actor_attribution_produces_actor_scoped_decision() -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=80.0),
        _context(),
        _enforce_policy(block_enabled=False),
    )

    assert decision.decision == MitigationDecisionType.THROTTLE
    assert decision.scope_type == MitigationScopeType.VERIFIED_USER
    assert decision.scope_key_hash == ACTOR_SCOPE_HASH
    assert decision.verified_attribution is True


def test_inferred_actor_attribution_is_not_trusted() -> None:
    context = _context(
        attribution_status=MitigationAttributionStatus.INFERRED,
        actor_key_hash=None,
        inferred_actor_key_hash=INFERRED_SCOPE_HASH,
    )

    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        context,
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.scope_type == MitigationScopeType.UNATTRIBUTED
    assert decision.scope_key_hash is None
    assert decision.verified_attribution is False
    assert MitigationReasonCode.INFERRED_ACTOR_NOT_TRUSTED in _codes(decision)


def test_api_key_scope_is_separate_from_verified_user_scope() -> None:
    context = _context(
        attribution_status=MitigationAttributionStatus.API_KEY_PRINCIPAL,
        actor_key_hash=ACTOR_SCOPE_HASH,
        api_key_principal_hash=API_KEY_SCOPE_HASH,
    )

    decision = evaluate_mitigation_decision(
        _grouped_result(score=80.0),
        context,
        _enforce_policy(block_enabled=False),
    )

    assert decision.decision == MitigationDecisionType.THROTTLE
    assert decision.scope_type == MitigationScopeType.API_KEY_PRINCIPAL
    assert decision.scope_key_hash == API_KEY_SCOPE_HASH
    assert decision.scope_key_hash != ACTOR_SCOPE_HASH
    assert decision.verified_attribution is True


def test_repeated_auth_failures_throttle_only_when_policy_enables_it() -> None:
    result = _grouped_result(score=80.0, failures=6)

    default_decision = evaluate_mitigation_decision(result, _context())
    enabled_decision = evaluate_mitigation_decision(
        result,
        _context(),
        _policy(mode=MitigationPolicyMode.ENFORCE, throttle_enabled=True),
    )

    assert default_decision.decision == MitigationDecisionType.MONITOR
    assert enabled_decision.decision == MitigationDecisionType.THROTTLE
    assert (
        MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE
        in _codes(enabled_decision)
    )


def test_block_is_disabled_by_default() -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        _context(),
        _policy(
            mode=MitigationPolicyMode.ENFORCE,
            throttle_enabled=True,
            block_enabled=False,
        ),
    )

    assert decision.decision == MitigationDecisionType.THROTTLE
    assert MitigationReasonCode.BLOCK_NOT_ENABLED in _codes(decision)


def test_block_enabled_with_qualifying_evidence_produces_temporary_block() -> None:
    policy = _enforce_policy(block_duration_seconds=120, max_block_duration_seconds=300)

    decision = evaluate_mitigation_decision(
        _grouped_result(score=95.0, failures=8),
        _context(),
        policy,
    )

    assert decision.decision == MitigationDecisionType.BLOCK
    assert decision.expires_at == FIXED_NOW + timedelta(seconds=120)
    assert decision.expires_at <= FIXED_NOW + timedelta(
        seconds=policy.max_block_duration_seconds
    )
    assert decision.advisory_only is True
    assert MitigationReasonCode.BLOCK_AUTH_FAILURE_EVIDENCE in _codes(decision)


@pytest.mark.parametrize(
    "context_overrides",
    [
        {"is_admin": True},
        {"is_control_plane": True},
    ],
)
def test_admin_and_control_plane_routes_are_protected(
    context_overrides: dict[str, object],
) -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        _context(**context_overrides),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.expires_at is None


@pytest.mark.parametrize(
    "context_overrides, result",
    [
        ({}, None),
        ({"detection_available": False}, _grouped_result(score=100.0)),
        ({"evidence_complete": False}, _grouped_result(score=100.0)),
        (
            {},
            _result(
                BotClassification.UNKNOWN,
                0.0,
                reasons=[
                    _reason(
                        "MISSING_CLIENT_ATTRIBUTION",
                        BotReasonCategory.EVIDENCE_QUALITY,
                        evidence_count=5,
                    )
                ],
            ),
        ),
    ],
)
def test_missing_evidence_defaults_conservatively(
    context_overrides: dict[str, object],
    result: BotAnalysisResult | None,
) -> None:
    decision = evaluate_mitigation_decision(
        result,
        _context(**context_overrides),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.expires_at is None


def test_invalid_policy_configuration_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _policy(
            monitoring_score_threshold=80.0,
            throttling_score_threshold=20.0,
        )
    with pytest.raises(ValidationError):
        _policy(
            block_duration_seconds=5000,
            max_block_duration_seconds=100,
        )


def test_expiry_and_duration_bounds_are_deterministic() -> None:
    context = _context(evaluated_at=FIXED_NOW.replace(tzinfo=None))
    policy = _enforce_policy(
        block_enabled=False,
        throttle_duration_seconds=45,
        throttle_limit=12,
        throttle_window_seconds=30,
    )

    decision = evaluate_mitigation_decision(
        _grouped_result(score=80.0),
        context,
        policy,
    )

    assert decision.issued_at.tzinfo is not None
    assert decision.expires_at is not None
    assert decision.expires_at - decision.issued_at == timedelta(seconds=45)
    assert decision.rate_limit == 12
    assert decision.rate_limit_window_seconds == 30


def test_shadow_mode_never_recommends_enforcement() -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        _context(),
        _enforce_policy(mode=MitigationPolicyMode.SHADOW),
    )

    assert decision.decision == MitigationDecisionType.MONITOR
    assert MitigationReasonCode.SHADOW_MODE_NO_ENFORCEMENT in _codes(decision)
    assert decision.expires_at is None


def test_identical_inputs_produce_identical_decisions() -> None:
    result = _grouped_result(score=85.0)
    context = _context()
    policy = _enforce_policy(block_enabled=False)

    first = evaluate_mitigation_decision(result, context, policy)
    second = evaluate_mitigation_decision(result, context, policy)

    assert first.model_dump() == second.model_dump()


def test_stage_one_input_is_not_modified() -> None:
    result = _grouped_result(score=100.0, shared_ip=True)
    context = _context(
        attribution_status=MitigationAttributionStatus.NETWORK_IP,
        actor_key_hash=None,
        network_key_hash=NETWORK_SCOPE_HASH,
    )
    result_before = deepcopy(result.model_dump())
    context_before = deepcopy(context.model_dump())

    evaluate_mitigation_decision(result, context, _enforce_policy())

    assert result.model_dump() == result_before
    assert context.model_dump() == context_before


def test_evidence_references_are_bounded_and_opaque() -> None:
    refs = _refs("many", count=6)
    result = _result(
        BotClassification.AUTOMATION_BENIGN_CANDIDATE,
        20.0,
        refs=refs,
    )

    decision = evaluate_mitigation_decision(
        result,
        _context(),
        _policy(max_evidence_references=2),
    )

    assert decision.evidence_references == refs[:2]
    assert all(len(reference) == 36 for reference in decision.evidence_references)
    assert "raw" not in decision.model_dump_json()


def test_scope_hash_format_is_accepted_for_all_scope_types() -> None:
    verified_user = _context()
    api_key = _context(
        attribution_status=MitigationAttributionStatus.API_KEY_PRINCIPAL,
        actor_key_hash=None,
        api_key_principal_hash=API_KEY_SCOPE_HASH,
    )
    network = _context(
        attribution_status=MitigationAttributionStatus.NETWORK_IP,
        actor_key_hash=None,
        network_key_hash=NETWORK_SCOPE_HASH,
    )
    inferred = _context(
        attribution_status=MitigationAttributionStatus.INFERRED,
        actor_key_hash=None,
        inferred_actor_key_hash=INFERRED_SCOPE_HASH,
    )

    assert verified_user.actor_key_hash == ACTOR_SCOPE_HASH
    assert api_key.api_key_principal_hash == API_KEY_SCOPE_HASH
    assert network.network_key_hash == NETWORK_SCOPE_HASH
    assert inferred.inferred_actor_key_hash == INFERRED_SCOPE_HASH


@pytest.mark.parametrize(
    "field, overrides",
    [
        (
            "actor_key_hash",
            {
                "attribution_status": MitigationAttributionStatus.VERIFIED_USER,
                "actor_key_hash": "raw-user-id",
            },
        ),
        (
            "actor_key_hash",
            {
                "attribution_status": MitigationAttributionStatus.VERIFIED_USER,
                "actor_key_hash": "sha256:" + "A" * 64,
            },
        ),
        (
            "api_key_principal_hash",
            {
                "attribution_status": MitigationAttributionStatus.API_KEY_PRINCIPAL,
                "actor_key_hash": None,
                "api_key_principal_hash": "arbitrary-string",
            },
        ),
        (
            "network_key_hash",
            {
                "attribution_status": MitigationAttributionStatus.NETWORK_IP,
                "actor_key_hash": None,
                "network_key_hash": "192.0.2.10",
            },
        ),
        (
            "inferred_actor_key_hash",
            {
                "attribution_status": MitigationAttributionStatus.INFERRED,
                "actor_key_hash": None,
                "inferred_actor_key_hash": "client-supplied-actor",
            },
        ),
    ],
)
def test_scope_hash_rejects_raw_ids_and_arbitrary_strings(
    field: str, overrides: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        _context(**overrides)

    assert field in overrides


def test_admin_requires_verified_user_attribution_and_valid_actor_hash() -> None:
    with pytest.raises(ValidationError, match="is_admin=true"):
        _context(
            is_admin=True,
            attribution_status=MitigationAttributionStatus.API_KEY_PRINCIPAL,
            actor_key_hash=None,
            api_key_principal_hash=API_KEY_SCOPE_HASH,
        )
    with pytest.raises(ValidationError, match="is_admin=true"):
        _context(
            is_admin=True,
            attribution_status=MitigationAttributionStatus.MISSING,
            actor_key_hash=None,
        )
    with pytest.raises(ValidationError):
        _context(is_admin=True, actor_key_hash="raw-admin-id")

    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        _context(is_admin=True),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.scope_type == MitigationScopeType.VERIFIED_USER


def test_admin_is_never_throttled_even_with_protection_flag_disabled() -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=100.0),
        _context(is_admin=True),
        _enforce_policy(admin_protection_enabled=False),
    )

    assert decision.decision == MitigationDecisionType.MONITOR
    assert decision.expires_at is None
    assert decision.rate_limit is None


def test_monitoring_threshold_controls_weak_only_suspicious_monitoring() -> None:
    weak_suspicious = _result(
        BotClassification.AUTOMATION_SUSPICIOUS,
        10.0,
        reasons=[
            _reason(
                "USER_AGENT_NOVELTY",
                BotReasonCategory.USER_AGENT,
                evidence_count=1,
            )
        ],
    )

    below_threshold = evaluate_mitigation_decision(
        weak_suspicious,
        _context(),
        _policy(),
    )
    above_threshold = evaluate_mitigation_decision(
        weak_suspicious,
        _context(),
        _policy(monitoring_score_threshold=5.0),
    )
    benign_below_threshold = evaluate_mitigation_decision(
        _result(BotClassification.AUTOMATION_BENIGN_CANDIDATE, 5.0),
        _context(),
        _policy(),
    )

    assert below_threshold.decision == MitigationDecisionType.ALLOW
    assert MitigationReasonCode.BELOW_MONITORING_THRESHOLD in _codes(below_threshold)
    assert above_threshold.decision == MitigationDecisionType.MONITOR
    assert MitigationReasonCode.WEAK_SIGNAL_ONLY in _codes(above_threshold)
    assert benign_below_threshold.decision == MitigationDecisionType.MONITOR


def test_grouped_auth_evidence_is_labelled_as_grouped() -> None:
    decision = evaluate_mitigation_decision(
        _grouped_result(score=80.0, failures=6),
        _context(),
        _policy(mode=MitigationPolicyMode.ENFORCE, throttle_enabled=True),
    )

    assert decision.decision == MitigationDecisionType.THROTTLE
    assert MitigationReasonCode.GROUPED_AUTH_FAILURE_EVIDENCE in _codes(decision)
    assert MitigationReasonCode.RAW_AUTH_FAILURE_VOLUME_EVIDENCE not in _codes(decision)
    assert MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE in _codes(decision)


def test_raw_volume_qualification_is_not_labelled_as_grouped() -> None:
    decision = evaluate_mitigation_decision(
        _raw_volume_result(score=80.0, failures=6),
        _context(),
        _policy(
            mode=MitigationPolicyMode.ENFORCE,
            throttle_enabled=True,
            require_grouped_brute_force=False,
        ),
    )

    assert decision.decision == MitigationDecisionType.THROTTLE
    assert MitigationReasonCode.RAW_AUTH_FAILURE_VOLUME_EVIDENCE in _codes(decision)
    assert MitigationReasonCode.GROUPED_AUTH_FAILURE_EVIDENCE not in _codes(decision)
    assert MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE in _codes(decision)
    assert "grouped_auth_failure" not in decision.model_dump_json()


def test_route_class_is_reserved_and_does_not_affect_decisions() -> None:
    result = _grouped_result(score=80.0)
    policy = _enforce_policy(block_enabled=False)

    general = evaluate_mitigation_decision(
        result,
        _context(route_class="general_api"),
        policy,
    )
    auth_route = evaluate_mitigation_decision(
        result,
        _context(route_class="auth_login"),
        policy,
    )

    assert general.model_dump() == auth_route.model_dump()


@pytest.mark.parametrize(
    "threshold_name",
    [
        "monitoring_score_threshold",
        "throttling_score_threshold",
        "blocking_score_threshold",
    ],
)
@pytest.mark.parametrize(
    "non_finite_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_policy_thresholds_reject_non_finite_values(
    threshold_name: str, non_finite_value: float
) -> None:
    with pytest.raises(ValidationError):
        _policy(**{threshold_name: non_finite_value})


@pytest.mark.parametrize(
    "malformed_score",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_stage1_score_never_produces_enforcement_recommendation(
    malformed_score: float,
) -> None:
    result = _grouped_result(score=95.0, failures=8).model_copy(
        update={"bot_risk_score": malformed_score}
    )

    decision = evaluate_mitigation_decision(
        result,
        _context(),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert MitigationReasonCode.NON_FINITE_BOT_SCORE in _codes(decision)
    assert decision.expires_at is None
    assert decision.rate_limit is None
    assert MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE not in _codes(decision)
    assert MitigationReasonCode.BLOCK_AUTH_FAILURE_EVIDENCE not in _codes(decision)


# --- F01 regression: strong brute-force evidence is never "no evidence" -------
# BEFORE: a HUMAN_LIKE result carrying REPEATED_AUTHENTICATION_FAILURES hit the
# human-like short-circuit and emitted HUMAN_LIKE_NO_ACTION +
# NO_SUSPICIOUS_EVIDENCE despite grouped brute-force evidence being present.
# AFTER: whenever strong grouped authentication evidence is present, the engine
# never emits either of those codes. It stays advisory-only: ALLOW, no throttle,
# no block, no enforcement. Ordinary human traffic is unaffected.


def test_f01_repeated_auth_failures_never_produce_human_like_no_action() -> None:
    refs = _refs("f01-human")
    result = _result(
        BotClassification.HUMAN_LIKE,
        30.0,
        reasons=[
            _reason(
                "REPEATED_AUTHENTICATION_FAILURES",
                BotReasonCategory.AUTHENTICATION,
                evidence_count=6,
                refs=refs,
            )
        ],
        refs=refs,
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    codes = _codes(decision)
    assert MitigationReasonCode.HUMAN_LIKE_NO_ACTION not in codes
    assert MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE not in codes
    assert MitigationReasonCode.INSUFFICIENT_EVIDENCE in codes
    assert decision.decision == MitigationDecisionType.ALLOW


def test_f01_strong_brute_force_evidence_never_produces_no_suspicious_evidence() -> None:
    refs = _refs("f01-unknown")
    result = _result(
        BotClassification.UNKNOWN,
        30.0,
        reasons=[
            _reason(
                "REPEATED_AUTHENTICATION_FAILURES",
                BotReasonCategory.AUTHENTICATION,
                evidence_count=6,
                refs=refs,
            )
        ],
        refs=refs,
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    codes = _codes(decision)
    assert MitigationReasonCode.NO_SUSPICIOUS_EVIDENCE not in codes
    assert MitigationReasonCode.HUMAN_LIKE_NO_ACTION not in codes
    assert decision.decision == MitigationDecisionType.ALLOW


def test_f01_fix_does_not_activate_blocking_or_enforcement() -> None:
    refs = _refs("f01-advisory")
    result = _result(
        BotClassification.UNKNOWN,
        30.0,
        reasons=[
            _reason(
                "REPEATED_AUTHENTICATION_FAILURES",
                BotReasonCategory.AUTHENTICATION,
                evidence_count=6,
                refs=refs,
            )
        ],
        refs=refs,
    )

    decision = evaluate_mitigation_decision(result, _context(), _enforce_policy())

    assert decision.decision == MitigationDecisionType.ALLOW
    assert decision.advisory_only is True
    assert decision.expires_at is None
    assert decision.rate_limit is None
    assert decision.rate_limit_window_seconds is None
    codes = _codes(decision)
    assert MitigationReasonCode.THROTTLE_AUTH_FAILURE_EVIDENCE not in codes
    assert MitigationReasonCode.BLOCK_AUTH_FAILURE_EVIDENCE not in codes


def test_f01_ordinary_human_traffic_retains_expected_decision() -> None:
    decision = evaluate_mitigation_decision(
        _result(BotClassification.HUMAN_LIKE, 2.5),
        _context(),
        _enforce_policy(),
    )

    assert decision.decision == MitigationDecisionType.ALLOW
    assert MitigationReasonCode.HUMAN_LIKE_NO_ACTION in _codes(decision)
