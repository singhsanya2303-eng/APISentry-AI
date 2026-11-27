"""MW3 Gate A focused tests for the in-memory policy/decision workflow.

These tests use only in-memory objects and the project interpreter. No database,
HTTP route, frontend file, credential, or enforcement path is exercised.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from pathlib import Path
import uuid

import pytest

from app.models.mitigation import (
    MitigationActivationEventType,
    MitigationActivationReasonCode,
    MitigationAuditEventType,
)
from app.schemas.advanced_detection_signals import (
    AdvancedDetectionEnvelope,
    AdvancedSignalName,
    AdvancedSignalResult,
    SignalLimits,
    SignalStatus,
)
from app.schemas.behavior import RiskLevel
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
)
from app.schemas.mitigation_policy_lifecycle import (
    LifecycleActor,
    LifecycleErrorCode,
    LifecycleRole,
    LifecycleWorkflowReasonCode,
    PolicyLifecycleState,
)
from app.schemas.unified_risk_assessment import (
    CoverageSummary,
    ThreatCategory,
    UnifiedRiskAssessment,
)
from app.services import mitigation_policy_lifecycle_service as lifecycle_module
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)

FIXED_NOW = datetime(2026, 3, 12, 10, 0, tzinfo=timezone.utc)
_OPAQUE_NAMESPACE = uuid.UUID("7f3a2b91-6c4d-4e8f-9a2b-5c8d1e7f0a34")
_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _opaque(label: str) -> str:
    return str(uuid.uuid5(_OPAQUE_NAMESPACE, f"mw3-gate-a:{label}"))


def _scope_hash(label: str) -> str:
    digest = hashlib.sha256(f"mw3-gate-a:{label}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


ACTOR_SCOPE_HASH = _scope_hash("admin-actor")
ANALYST_SCOPE_HASH = _scope_hash("analyst-actor")
VIEWER_SCOPE_HASH = _scope_hash("viewer-actor")


def _actor(role: LifecycleRole = LifecycleRole.ADMIN) -> LifecycleActor:
    hashes = {
        LifecycleRole.ADMIN: ACTOR_SCOPE_HASH,
        LifecycleRole.ANALYST: ANALYST_SCOPE_HASH,
        LifecycleRole.VIEWER: VIEWER_SCOPE_HASH,
    }
    return LifecycleActor(
        role=role,
        actor_hash=hashes.get(role),
    )


def _api_key_actor() -> LifecycleActor:
    return LifecycleActor(role=LifecycleRole.API_KEY)


def _config(version: str = "policy-1", **overrides: object) -> MitigationPolicyConfig:
    values: dict[str, object] = {"policy_version": version}
    values.update(overrides)
    return MitigationPolicyConfig(**values)  # type: ignore[arg-type]


def _enforce_config(version: str = "block-policy") -> MitigationPolicyConfig:
    return _config(
        version,
        mode=MitigationPolicyMode.ENFORCE,
        throttle_enabled=True,
        block_enabled=True,
        throttling_score_threshold=70.0,
        blocking_score_threshold=90.0,
    )


def _context(**overrides: object) -> MitigationRequestContext:
    values: dict[str, object] = {
        "evaluated_at": FIXED_NOW,
        "attribution_status": MitigationAttributionStatus.VERIFIED_USER,
        "actor_key_hash": ACTOR_SCOPE_HASH,
    }
    values.update(overrides)
    return MitigationRequestContext(**values)  # type: ignore[arg-type]


def _reason(
    code: str, *, evidence_count: int = 0, refs: list[str] | None = None
) -> BotReason:
    return BotReason(
        code=code,
        category=BotReasonCategory.AUTHENTICATION,
        description="Neutral Gate A test evidence.",
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
    evidence_refs = refs if refs is not None else [_opaque("stage1")]
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


def _grouped_result(score: float = 95.0) -> BotAnalysisResult:
    refs = [_opaque("auth-1"), _opaque("auth-2")]
    return _result(
        BotClassification.AUTOMATION_SUSPICIOUS,
        score,
        reasons=[
            _reason(
                "REPEATED_AUTHENTICATION_FAILURES",
                evidence_count=6,
                refs=refs,
            ),
            _reason("BRUTE_FORCE_OVERRIDE", evidence_count=0),
        ],
        refs=refs,
        request_count=15,
    )


def _human_result() -> BotAnalysisResult:
    return _result(BotClassification.HUMAN_LIKE, 5.0)


def _coverage(*, complete: bool = True) -> CoverageSummary:
    if complete:
        missing = unavailable = errors = invalid = 0
        ratio = 1.0
    else:
        missing = 1
        unavailable = errors = invalid = 0
        ratio = 0.8
    return CoverageSummary(
        signals_expected=5,
        signals_available=4 if not complete else 5,
        signals_missing=missing,
        signals_unavailable=unavailable,
        signals_error=errors,
        signals_invalid=invalid,
        coverage_ratio=ratio,
    )


def _mw1(
    severity: RiskLevel = RiskLevel.LOW,
    *,
    complete: bool = True,
    score: float = 20.0,
) -> UnifiedRiskAssessment:
    return UnifiedRiskAssessment(
        risk_score=score,
        severity=severity,
        raw_contribution_total=score,
        clamp_applied=False,
        coverage=_coverage(complete=complete),
        contributions=[],
        reasons=[],
        signal_statuses=[],
        uncertainty_notes=[],
        limits=[],
    )


def _mw2_signal(
    severity: RiskLevel = RiskLevel.HIGH,
    *,
    status: SignalStatus = SignalStatus.AVAILABLE,
    truncated: bool = False,
) -> AdvancedSignalResult:
    available = status is SignalStatus.AVAILABLE
    return AdvancedSignalResult(
        signal=AdvancedSignalName.CREDENTIAL_ABUSE,
        detection_name="credential_abuse_review",
        threat_category=ThreatCategory.BEHAVIORAL,
        severity=severity,
        observed_indicator="Bounded advisory indicator.",
        explanation="Advisory review signal only.",
        source_module="tests.mw3_gate_a",
        source_function="_mw2_signal",
        status=status,
        points=10.0 if available else 0.0,
        cap=25.0,
        evidence_refs=[_opaque("mw2-signal")],
        source_confidence=None,
        coverage_note=None,
        subject_ref="subject-ref-1",
        dedupe_key="mw2-dedupe-1",
        limits=SignalLimits(truncated=truncated),
    )


def _mw2(
    severity: RiskLevel = RiskLevel.HIGH,
    *,
    status: SignalStatus = SignalStatus.AVAILABLE,
    truncated: bool = False,
) -> AdvancedDetectionEnvelope:
    return AdvancedDetectionEnvelope(
        subject_ref="envelope-ref-1",
        signals=[_mw2_signal(severity, status=status, truncated=truncated)],
    )


def _active_service(
    version: str = "policy-1",
    config: MitigationPolicyConfig | None = None,
) -> MitigationPolicyLifecycleService:
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_actor(),
        config=config or _config(version),
        created_at=FIXED_NOW - timedelta(days=1),
    )
    assert proposed.ok
    validated = service.validate_policy(actor=_actor(), version=version, at=FIXED_NOW)
    assert validated.ok
    activated = service.activate_policy(actor=_actor(), version=version, at=FIXED_NOW)
    assert activated.ok
    return service


def _evaluate(
    service: MitigationPolicyLifecycleService,
    *,
    version: str | None = None,
    at: datetime = FIXED_NOW,
    detection: BotAnalysisResult | None = None,
    context: MitigationRequestContext | None = None,
    actor: LifecycleActor | None = None,
    risk_assessment: UnifiedRiskAssessment | None = None,
    advanced_envelope: AdvancedDetectionEnvelope | None = None,
    dry_run: bool = True,
    idempotency_token: str | None = None,
):
    resolved_version = version or service.active_version or "policy-1"
    return service.evaluate_policy(
        actor=actor or _actor(LifecycleRole.ANALYST),
        version=resolved_version,
        at=at,
        detection_result=detection if detection is not None else _human_result(),
        context=context or _context(),
        risk_assessment=risk_assessment,
        advanced_envelope=advanced_envelope,
        dry_run=dry_run,
        idempotency_token=idempotency_token,
    )


# ---------------------------------------------------------------------------
# Policy lifecycle
# ---------------------------------------------------------------------------


def test_valid_policy_creation_is_in_memory_and_inactive() -> None:
    service = MitigationPolicyLifecycleService()
    result = service.propose_policy(
        actor=_actor(LifecycleRole.ANALYST),
        config=_config("proposal-1"),
        created_at=FIXED_NOW,
    )

    assert result.ok
    assert result.error is None
    assert result.policy is not None
    assert result.policy.state is PolicyLifecycleState.PROPOSED
    assert result.policy.owner_role == "analyst"
    assert result.policy.owner_actor_hash == ANALYST_SCOPE_HASH
    assert service.active_version is None
    assert result.activation_events == ()
    assert result.audit_events == ()


def test_invalid_policy_configuration_is_rejected_before_registration() -> None:
    service = MitigationPolicyLifecycleService()
    result = service.propose_policy(
        actor=_actor(),
        config={
            "policy_version": "invalid-1",
            "monitoring_score_threshold": 80.0,
            "throttling_score_threshold": 40.0,
        },
        created_at=FIXED_NOW,
    )

    assert not result.ok
    assert result.error is not None
    assert result.error.code is LifecycleErrorCode.VALIDATION_ERROR
    assert service.policy_versions() == ()


def test_invalid_thresholds_and_unsupported_actions_are_explicit() -> None:
    service = MitigationPolicyLifecycleService()
    invalid_config = service.propose_policy(
        actor=_actor(),
        config={"policy_version": "bad-thresholds", "block_duration_seconds": 5000},
        created_at=FIXED_NOW,
    )
    assert not invalid_config.ok

    proposed = service.propose_policy(
        actor=_actor(), config=_config("unsupported"), created_at=FIXED_NOW
    )
    assert proposed.ok
    validated = service.validate_policy(
        actor=_actor(), version="unsupported", at=FIXED_NOW
    )
    assert validated.ok
    unsupported = service.activate_policy(
        actor=_actor(),
        version="unsupported",
        at=FIXED_NOW,
        reason_code="force_activate",  # type: ignore[arg-type]
    )
    assert not unsupported.ok
    assert unsupported.error is not None
    assert unsupported.error.code is LifecycleErrorCode.UNSUPPORTED_ACTION
    assert service.active_version is None


def test_state_transitions_activation_and_deactivation_are_deterministic() -> None:
    service = MitigationPolicyLifecycleService()
    proposed = service.propose_policy(
        actor=_actor(), config=_config("transition-1"), created_at=FIXED_NOW
    )
    validated = service.validate_policy(
        actor=_actor(), version="transition-1", at=FIXED_NOW
    )
    activated = service.activate_policy(
        actor=_actor(), version="transition-1", at=FIXED_NOW
    )
    assert service.active_version == "transition-1"
    deactivated = service.deactivate_policy(
        actor=_actor(), version="transition-1", at=FIXED_NOW + timedelta(minutes=1)
    )

    assert [state for state in (proposed, validated, activated, deactivated) if state.ok] == [
        proposed,
        validated,
        activated,
        deactivated,
    ]
    assert proposed.policy is not None
    assert proposed.policy.state is PolicyLifecycleState.PROPOSED
    assert validated.policy is not None
    assert validated.policy.state is PolicyLifecycleState.VALIDATED
    assert validated.policy.approved_by_hash == ACTOR_SCOPE_HASH
    assert activated.policy is not None
    assert activated.policy.state is PolicyLifecycleState.ACTIVE
    assert deactivated.policy is not None
    assert deactivated.policy.state is PolicyLifecycleState.INACTIVE
    assert service.active_version is None
    assert activated.audit_events[0].event_type is MitigationAuditEventType.POLICY_ACTIVATED
    assert deactivated.audit_events[0].event_type is MitigationAuditEventType.POLICY_DEACTIVATED
    assert activated.activation_events[0].event_type is MitigationActivationEventType.ACTIVATE
    assert deactivated.activation_events[0].event_type is MitigationActivationEventType.DEACTIVATE

    replay = MitigationPolicyLifecycleService()
    replay.propose_policy(actor=_actor(), config=_config("transition-1"), created_at=FIXED_NOW)
    replay.validate_policy(actor=_actor(), version="transition-1", at=FIXED_NOW)
    replay_activation = replay.activate_policy(
        actor=_actor(), version="transition-1", at=FIXED_NOW
    )
    assert replay_activation.ok
    assert replay_activation.activation_events == activated.activation_events
    assert replay_activation.audit_events == activated.audit_events


def test_invalid_transitions_fail_without_changing_state() -> None:
    service = MitigationPolicyLifecycleService()
    service.propose_policy(actor=_actor(), config=_config("invalid-transition"), created_at=FIXED_NOW)

    premature = service.activate_policy(
        actor=_actor(), version="invalid-transition", at=FIXED_NOW
    )
    assert not premature.ok
    assert premature.error is not None
    assert premature.error.code is LifecycleErrorCode.INVALID_TRANSITION
    assert service.active_version is None

    service.validate_policy(actor=_actor(), version="invalid-transition", at=FIXED_NOW)
    repeat = service.validate_policy(
        actor=_actor(), version="invalid-transition", at=FIXED_NOW
    )
    assert not repeat.ok
    assert repeat.error is not None
    assert repeat.error.code is LifecycleErrorCode.INVALID_TRANSITION

    service.activate_policy(actor=_actor(), version="invalid-transition", at=FIXED_NOW)
    retire_active = service.retire_policy(
        actor=_actor(), version="invalid-transition", at=FIXED_NOW
    )
    assert not retire_active.ok
    assert retire_active.error is not None
    assert retire_active.error.code is LifecycleErrorCode.INVALID_TRANSITION

    service.deactivate_policy(actor=_actor(), version="invalid-transition", at=FIXED_NOW)
    retired = service.retire_policy(
        actor=_actor(), version="invalid-transition", at=FIXED_NOW
    )
    assert retired.ok
    reactivate = service.activate_policy(
        actor=_actor(), version="invalid-transition", at=FIXED_NOW
    )
    assert not reactivate.ok
    assert reactivate.error is not None
    assert reactivate.error.code is LifecycleErrorCode.INVALID_TRANSITION


def test_version_conflict_and_expected_active_guard() -> None:
    service = _active_service("guard-1")
    duplicate = service.propose_policy(
        actor=_actor(), config=_config("guard-1"), created_at=FIXED_NOW
    )
    assert not duplicate.ok
    assert duplicate.error is not None
    assert duplicate.error.code is LifecycleErrorCode.VERSION_CONFLICT

    service.propose_policy(actor=_actor(), config=_config("guard-2"), created_at=FIXED_NOW)
    service.validate_policy(actor=_actor(), version="guard-2", at=FIXED_NOW)
    mismatched = service.activate_policy(
        actor=_actor(), version="guard-2", at=FIXED_NOW, expected_active_version="other"
    )
    assert not mismatched.ok
    assert mismatched.error is not None
    assert mismatched.error.code is LifecycleErrorCode.VERSION_CONFLICT
    assert service.active_version == "guard-1"

    omitted = service.activate_policy(actor=_actor(), version="guard-2", at=FIXED_NOW)
    assert not omitted.ok
    assert omitted.error is not None
    assert omitted.error.code is LifecycleErrorCode.VERSION_CONFLICT

    replaced = service.activate_policy(
        actor=_actor(),
        version="guard-2",
        at=FIXED_NOW,
        expected_active_version="guard-1",
        reason_code=MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
    )
    assert replaced.ok
    assert service.active_version == "guard-2"
    assert replaced.audit_events[0].event_type is MitigationAuditEventType.POLICY_VERSION_CHANGED
    assert len(replaced.activation_events) == 2


def test_rollback_uses_prior_version_and_ordered_events() -> None:
    service = _active_service("roll-1")
    service.propose_policy(actor=_actor(), config=_config("roll-2"), created_at=FIXED_NOW)
    service.validate_policy(actor=_actor(), version="roll-2", at=FIXED_NOW)
    service.activate_policy(
        actor=_actor(),
        version="roll-2",
        at=FIXED_NOW,
        expected_active_version="roll-1",
        reason_code=MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
    )
    rolled_back = service.rollback_policy(
        actor=_actor(),
        target_version="roll-1",
        at=FIXED_NOW + timedelta(minutes=1),
        expected_active_version="roll-2",
    )

    assert rolled_back.ok
    assert service.active_version == "roll-1"
    assert rolled_back.policy is not None
    assert rolled_back.policy.state is PolicyLifecycleState.ACTIVE
    assert [event.event_type for event in rolled_back.activation_events] == [
        MitigationActivationEventType.DEACTIVATE,
        MitigationActivationEventType.ACTIVATE,
    ]
    assert rolled_back.audit_events[0].event_type is MitigationAuditEventType.POLICY_VERSION_CHANGED

    never_active = service.propose_policy(
        actor=_actor(), config=_config("roll-3"), created_at=FIXED_NOW
    )
    assert never_active.ok
    bad_target = service.rollback_policy(
        actor=_actor(),
        target_version="roll-3",
        at=FIXED_NOW,
        expected_active_version="roll-1",
    )
    assert not bad_target.ok
    assert bad_target.error is not None
    assert bad_target.error.code is LifecycleErrorCode.INVALID_TRANSITION


def test_lifecycle_authorization_matrix_is_enforced() -> None:
    service = MitigationPolicyLifecycleService()
    viewer_proposal = service.propose_policy(
        actor=_actor(LifecycleRole.VIEWER), config=_config("viewer-1"), created_at=FIXED_NOW
    )
    api_proposal = service.propose_policy(
        actor=_api_key_actor(), config=_config("api-1"), created_at=FIXED_NOW
    )
    assert not viewer_proposal.ok and viewer_proposal.error is not None
    assert viewer_proposal.error.code is LifecycleErrorCode.UNAUTHORIZED
    assert not api_proposal.ok and api_proposal.error is not None
    assert api_proposal.error.code is LifecycleErrorCode.UNAUTHORIZED

    service.propose_policy(
        actor=_actor(LifecycleRole.ANALYST), config=_config("auth-1"), created_at=FIXED_NOW
    )
    analyst_validation = service.validate_policy(
        actor=_actor(LifecycleRole.ANALYST), version="auth-1", at=FIXED_NOW
    )
    assert not analyst_validation.ok
    assert analyst_validation.error is not None
    assert analyst_validation.error.code is LifecycleErrorCode.UNAUTHORIZED

    service.validate_policy(actor=_actor(), version="auth-1", at=FIXED_NOW)
    for denied_actor in (_actor(LifecycleRole.ANALYST), _actor(LifecycleRole.VIEWER), _api_key_actor()):
        denied = service.activate_policy(
            actor=denied_actor, version="auth-1", at=FIXED_NOW
        )
        assert not denied.ok
        assert denied.error is not None
        assert denied.error.code is LifecycleErrorCode.UNAUTHORIZED
    assert service.active_version is None


def test_expired_policy_cannot_be_validated_or_activated() -> None:
    service = MitigationPolicyLifecycleService()
    service.propose_policy(
        actor=_actor(),
        config=_config("expired-1"),
        created_at=FIXED_NOW - timedelta(days=2),
        valid_from=FIXED_NOW - timedelta(days=2),
        valid_until=FIXED_NOW - timedelta(days=1),
    )
    validation = service.validate_policy(
        actor=_actor(), version="expired-1", at=FIXED_NOW
    )
    assert not validation.ok
    assert validation.error is not None
    assert validation.error.code is LifecycleErrorCode.POLICY_EXPIRED

    service2 = _active_service("expiring-1")
    expiring = service2.get_policy("expiring-1")
    assert expiring is not None
    updated = expiring.model_copy(
        update={"valid_until": FIXED_NOW + timedelta(minutes=1)}
    )
    service2._policies["expiring-1"] = updated  # simulate caller-supplied window fixture

    evaluation = _evaluate(service2, version="expiring-1", at=FIXED_NOW + timedelta(minutes=2))
    assert not evaluation.ok
    assert evaluation.error is not None
    assert evaluation.error.code is LifecycleErrorCode.POLICY_EXPIRED


def test_policy_snapshot_is_isolated_from_registry_mutation() -> None:
    service = _active_service("immutable-1")
    snapshot = service.get_policy("immutable-1")
    assert snapshot is not None
    snapshot.config.enabled = False

    original = service.get_policy("immutable-1")
    assert original is not None
    assert original.config.enabled is True
    assert service.active_version == "immutable-1"


# ---------------------------------------------------------------------------
# Evaluation and decisions
# ---------------------------------------------------------------------------


def test_normal_and_high_risk_evaluations_remain_advisory() -> None:
    normal_service = _active_service("normal-1")
    normal = _evaluate(
        normal_service,
        risk_assessment=_mw1(RiskLevel.LOW, score=15.0),
        advanced_envelope=_mw2(RiskLevel.LOW),
    )
    assert normal.ok
    assert normal.decision is not None
    assert normal.decision.intended_action is MitigationDecisionType.ALLOW
    assert normal.decision.decision.advisory_only is True
    assert normal.decision.policy_version == "normal-1"
    assert normal.decision.policy_state is PolicyLifecycleState.ACTIVE

    high_service = _active_service("high-1", _enforce_config("high-1"))
    high = _evaluate(
        high_service,
        version="high-1",
        detection=_grouped_result(95.0),
        risk_assessment=_mw1(RiskLevel.HIGH, score=90.0),
        advanced_envelope=_mw2(RiskLevel.HIGH),
    )
    assert high.ok
    assert high.decision is not None
    assert high.decision.intended_action is MitigationDecisionType.BLOCK
    assert high.decision.decision.expires_at is not None
    assert high.decision.decision.advisory_only is True
    assert high.audit_event is not None
    assert high.audit_event.event_type is MitigationAuditEventType.DECISION_ISSUED


def test_mw2_high_severity_conflict_caps_advisory_action_at_monitor() -> None:
    service = _active_service("mw2-1")
    result = _evaluate(
        service,
        detection=_human_result(),
        risk_assessment=_mw1(RiskLevel.LOW),
        advanced_envelope=_mw2(RiskLevel.HIGH),
    )

    assert result.ok
    assert result.decision is not None
    assert result.decision.intended_action is MitigationDecisionType.MONITOR
    assert (
        LifecycleWorkflowReasonCode.ADVISORY_SIGNAL_CONFLICT_MONITOR_ONLY
        in result.decision.workflow_reason_codes
    )
    assert MitigationReasonCode.SUSPICIOUS_BELOW_THRESHOLD in result.decision.decision.reason_codes
    assert result.decision.decision.advisory_only is True


def test_low_severity_conflict_caps_block_at_monitor() -> None:
    service = _active_service("conflict-1", _enforce_config("conflict-1"))
    result = _evaluate(
        service,
        version="conflict-1",
        detection=_grouped_result(95.0),
        risk_assessment=_mw1(RiskLevel.LOW, score=10.0),
        advanced_envelope=_mw2(RiskLevel.LOW),
    )

    assert result.ok
    assert result.decision is not None
    assert result.decision.intended_action is MitigationDecisionType.MONITOR
    assert (
        LifecycleWorkflowReasonCode.ADVISORY_SIGNAL_CONFLICT_MONITOR_ONLY
        in result.decision.workflow_reason_codes
    )


def test_missing_signals_are_explicit_and_not_treated_as_clean() -> None:
    service = _active_service("missing-1")
    result = _evaluate(service)

    assert result.ok
    assert result.decision is not None
    assert "mw1_output_missing" in result.decision.missing_signals
    assert "mw2_envelope_missing" in result.decision.missing_signals
    assert MitigationReasonCode.EVIDENCE_INCOMPLETE in result.decision.decision.reason_codes
    assert LifecycleWorkflowReasonCode.MW1_OUTPUT_MISSING in result.decision.workflow_reason_codes
    assert LifecycleWorkflowReasonCode.MW2_ENVELOPE_MISSING in result.decision.workflow_reason_codes
    assert result.decision.uncertain_signals is False


def test_uncertain_signals_are_retained_explicitly() -> None:
    service = _active_service("uncertain-1")
    result = _evaluate(
        service,
        risk_assessment=_mw1(RiskLevel.HIGH, complete=False),
        advanced_envelope=_mw2(RiskLevel.HIGH, status=SignalStatus.ERROR),
    )

    assert result.ok
    assert result.decision is not None
    assert result.decision.uncertain_signals is True
    assert LifecycleWorkflowReasonCode.MW1_COVERAGE_INCOMPLETE in result.decision.workflow_reason_codes
    assert LifecycleWorkflowReasonCode.MW2_SIGNAL_UNCERTAIN in result.decision.workflow_reason_codes
    assert MitigationReasonCode.EVIDENCE_INCOMPLETE in result.decision.decision.reason_codes


def test_inactive_and_expired_policies_cannot_be_evaluated_as_active() -> None:
    service = _active_service("inactive-1")
    service.deactivate_policy(actor=_actor(), version="inactive-1", at=FIXED_NOW)
    inactive = _evaluate(service, version="inactive-1")
    assert not inactive.ok
    assert inactive.error is not None
    assert inactive.error.code is LifecycleErrorCode.POLICY_NOT_ACTIVE

    service2 = _active_service("expired-eval-1")
    original = service2.get_policy("expired-eval-1")
    assert original is not None
    service2._policies["expired-eval-1"] = original.model_copy(
        update={"valid_until": FIXED_NOW - timedelta(seconds=1)}
    )
    expired = _evaluate(service2, version="expired-eval-1")
    assert not expired.ok
    assert expired.error is not None
    assert expired.error.code is LifecycleErrorCode.POLICY_EXPIRED


def test_dry_run_review_of_validated_policy_does_not_activate_it() -> None:
    service = MitigationPolicyLifecycleService()
    service.propose_policy(actor=_actor(), config=_config("dry-1"), created_at=FIXED_NOW)
    service.validate_policy(actor=_actor(), version="dry-1", at=FIXED_NOW)

    dry_run = _evaluate(service, version="dry-1", dry_run=True)
    assert dry_run.ok
    assert dry_run.decision is not None
    assert dry_run.decision.policy_state is PolicyLifecycleState.VALIDATED
    assert service.active_version is None

    non_dry_run = _evaluate(service, version="dry-1", dry_run=False)
    assert not non_dry_run.ok
    assert non_dry_run.error is not None
    assert non_dry_run.error.code is LifecycleErrorCode.POLICY_NOT_ACTIVE


def test_evaluation_is_deterministic_and_has_explainable_provenance() -> None:
    service = _active_service("deterministic-1")
    kwargs = {
        "detection": _human_result(),
        "risk_assessment": _mw1(RiskLevel.LOW, score=12.0),
        "advanced_envelope": _mw2(RiskLevel.LOW),
        "idempotency_token": "review-token-1",
    }
    first = _evaluate(service, version="deterministic-1", **kwargs)
    second = _evaluate(service, version="deterministic-1", **kwargs)

    assert first.ok and second.ok
    assert first.decision is not None and second.decision is not None
    assert first.decision.decision_ref == second.decision.decision_ref
    assert first.decision.correlation_ref == second.decision.correlation_ref
    assert first.audit_event is not None and second.audit_event is not None
    assert first.audit_event.content_digest == second.audit_event.content_digest
    assert _UUID5_RE.fullmatch(first.decision.decision_ref)
    assert _UUID5_RE.fullmatch(first.decision.policy_ref)
    assert _UUID5_RE.fullmatch(first.audit_event.event_uuid)
    assert first.decision.workflow_reason_codes
    assert first.decision.decision.explanation


def test_evaluation_requires_analyst_or_admin_and_rejects_invalid_inputs() -> None:
    service = _active_service("eval-auth-1")
    for actor in (_actor(LifecycleRole.VIEWER), _api_key_actor()):
        denied = _evaluate(service, version="eval-auth-1", actor=actor)
        assert not denied.ok
        assert denied.error is not None
        assert denied.error.code is LifecycleErrorCode.UNAUTHORIZED

    bad_context = _evaluate(
        service, version="eval-auth-1", context="raw-context"  # type: ignore[arg-type]
    )
    assert not bad_context.ok
    assert bad_context.error is not None
    assert bad_context.error.code is LifecycleErrorCode.VALIDATION_ERROR

    bad_token = _evaluate(service, version="eval-auth-1", idempotency_token="token with spaces")
    assert not bad_token.ok
    assert bad_token.error is not None
    assert bad_token.error.code is LifecycleErrorCode.VALIDATION_ERROR


# ---------------------------------------------------------------------------
# Audit construction, safety, and privacy
# ---------------------------------------------------------------------------


def test_audit_events_carry_actor_and_opaque_correlation_without_secrets() -> None:
    fresh = MitigationPolicyLifecycleService()
    fresh.propose_policy(actor=_actor(), config=_config("audit-2"), created_at=FIXED_NOW)
    fresh.validate_policy(actor=_actor(), version="audit-2", at=FIXED_NOW)
    activation = fresh.activate_policy(actor=_actor(), version="audit-2", at=FIXED_NOW)
    assert activation.ok
    event = activation.audit_events[0]
    assert event.actor_hash == ACTOR_SCOPE_HASH
    assert event.actor_role == "admin"
    assert _UUID5_RE.fullmatch(event.event_uuid)
    assert _UUID5_RE.fullmatch(event.correlation_ref)
    assert event.content_digest.startswith("sha256:")
    assert "tamper" not in json.dumps(event.model_dump(mode="json")).lower()

    result = _evaluate(
        fresh,
        version="audit-2",
        idempotency_token="review-token-private",
        risk_assessment=_mw1(RiskLevel.LOW),
    )
    assert result.ok
    assert result.audit_event is not None
    assert result.audit_event.decision_ref is not None
    serialized = json.dumps(
        {
            "decision": result.decision.model_dump(mode="json"),
            "audit": result.audit_event.model_dump(mode="json"),
        }
    )
    assert "review-token-private" not in serialized
    assert "api_key=" not in serialized
    assert "password" not in serialized


def test_gate_a_has_no_persistence_or_enforcement_surface() -> None:
    source = Path(lifecycle_module.__file__).read_text(encoding="utf-8")
    forbidden_fragments = (
        "sqlalchemy",
        "Session",
        "commit(",
        "rollback(",
        "execute(",
        "requests.",
        "httpx.",
        "subprocess",
        "rate_limit_service",
        "block_request",
        "enforce(",
    )
    assert [fragment for fragment in forbidden_fragments if fragment in source] == []
    assert not hasattr(lifecycle_module.MitigationPolicyLifecycleService(), "db")
