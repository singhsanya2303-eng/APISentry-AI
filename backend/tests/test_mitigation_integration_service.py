"""Focused Stage 2C Phase 4 Stage A orchestration tests.

All database work uses isolated in-memory SQLite. No configured database,
PostgreSQL connection, API route, or audit persistence is involved.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from types import SimpleNamespace

import pytest

from app.models.mitigation import MitigationDecision as MitigationDecisionRow
from app.schemas.bot_detection import (
    BotAnalysisLimits,
    BotAnalysisResult,
    BotAnalysisSummary,
    BotClassification,
    BotEvidenceReference,
    BotDetectionResponse,
    BotReason,
    BotReasonCategory,
    BotReasonSeverity,
)
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision as EvaluatedDecision,
    MitigationDecisionType,
    MitigationPolicyConfig,
)
from app.schemas.mitigation_integration import (
    MitigationAuthenticationMode,
    MitigationOutcomeStatus,
    VerifiedMitigationPrincipal,
)
from app.services import mitigation_integration_service as integration_service
from app.services.mitigation_decision_persistence_service import (
    DecisionPersistenceResult,
)
from app.services.mitigation_persistence_common import (
    ActivePolicyNotFoundError,
    DecisionPersistenceError,
)
from app.services.mitigation_policy_persistence_service import LoadedPolicy
from tests.mitigation_persistence_helpers import (
    VALID_HASH,
    activate_policy,
    evaluated_decision,
    policy_record,
    sqlite_session_factory,
    unique_uuid5,
)


@pytest.fixture
def db_session():
    engine, factory = sqlite_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed_policy(session, policy_version: str = "stage-a-1.0.0"):
    stored = policy_record(policy_version=policy_version)
    session.add(stored)
    session.flush()
    activate_policy(session, stored)
    session.commit()
    return stored


def _result(
    *,
    client_ip: str | None = None,
    actor_id: str | None = None,
    evidence_refs: list[str] | None = None,
    last_seen: datetime | None = None,
    reasons: list[BotReason] | None = None,
) -> BotAnalysisResult:
    return BotAnalysisResult(
        client_ip=client_ip,
        actor_id=actor_id,
        bot_risk_score=10.0,
        classification=BotClassification.HUMAN_LIKE,
        reasons=reasons or [],
        evidence_references=[
            BotEvidenceReference(request_id=ref, source="test")
            for ref in (evidence_refs or [])
        ],
        request_count=1,
        summary="Neutral Stage 1 summary.",
        last_seen=last_seen or datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc),
    )


def _detection(
    results: list[BotAnalysisResult],
    *,
    truncated: bool = False,
    analysis_window_end: datetime | None = None,
) -> BotDetectionResponse:
    return BotDetectionResponse(
        results=results,
        total_clients=len(results),
        total_events_analyzed=sum(result.request_count for result in results),
        analysis_window_end=analysis_window_end
        or datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc),
        limits=BotAnalysisLimits(
            requested_page=1,
            requested_page_size=200,
            max_records=1000,
            records_analyzed=sum(result.request_count for result in results),
            truncated=truncated,
        ),
        summary=BotAnalysisSummary(summary="Neutral aggregate summary."),
    )


def _principal(role: str = "analyst") -> VerifiedMitigationPrincipal:
    return VerifiedMitigationPrincipal(actor_key_hash=VALID_HASH, role=role)


def test_active_policy_loaded_once_and_config_passed_to_engine(db_session, monkeypatch):
    stored = _seed_policy(db_session)
    config = MitigationPolicyConfig(policy_version="stage-a-1.0.0")
    load_calls: list[object] = []

    def fake_load(db, *, expected_policy_version=None):
        load_calls.append(expected_policy_version)
        return LoadedPolicy(record=stored, config=config)

    evaluate_calls: list[tuple[object, object, object]] = []
    decision = evaluated_decision(config.policy_version)

    def fake_evaluate(result, context, policy):
        evaluate_calls.append((result, context, policy))
        return decision

    persist_calls: list[tuple[object, str]] = []

    def fake_persist(db, decision_arg, *, dedupe_key, decision_uuid=None, created_at=None):
        persist_calls.append((decision_arg, dedupe_key))
        return DecisionPersistenceResult(
            decision=SimpleNamespace(decision_uuid=unique_uuid5()),
            created=True,
        )

    monkeypatch.setattr(integration_service, "load_active_policy", fake_load)
    monkeypatch.setattr(integration_service, "evaluate_mitigation_decision", fake_evaluate)
    monkeypatch.setattr(integration_service, "persist_evaluated_decision", fake_persist)

    detection = _detection(
        [
            _result(evidence_refs=[unique_uuid5()]),
            _result(evidence_refs=[unique_uuid5()]),
        ]
    )

    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert load_calls == [None]
    assert len(evaluate_calls) == 2
    assert all(call[2] is config for call in evaluate_calls)
    assert len(persist_calls) == 2
    assert [item.status for item in outcome.outcomes] == [
        MitigationOutcomeStatus.PERSISTED,
        MitigationOutcomeStatus.PERSISTED,
    ]
    assert outcome.policy_version == config.policy_version


def test_one_advisory_decision_is_persisted_per_detection_result(db_session):
    _seed_policy(db_session)
    detection = _detection(
        [
            _result(evidence_refs=[unique_uuid5()]),
            _result(evidence_refs=[unique_uuid5()]),
        ]
    )

    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert len(outcome.outcomes) == 2
    assert all(
        item.status is MitigationOutcomeStatus.PERSISTED for item in outcome.outcomes
    )
    assert all(item.decision is not None for item in outcome.outcomes)
    assert all(item.decision.advisory_only is True for item in outcome.outcomes)
    rows = db_session.query(MitigationDecisionRow).all()
    assert len(rows) == 2
    assert all(row.advisory_only is True for row in rows)


def test_verified_jwt_attribution_is_used_only_with_a_verified_principal():
    detection = _detection([_result(evidence_refs=[unique_uuid5()])])
    result = detection.results[0]

    verified = integration_service.build_mitigation_context(
        detection=detection,
        result=result,
        authentication_mode=MitigationAuthenticationMode.JWT,
        verified_principal=_principal("admin"),
    )
    assert verified.attribution_status is MitigationAttributionStatus.VERIFIED_USER
    assert verified.actor_key_hash == VALID_HASH
    assert verified.is_admin is True

    missing = integration_service.build_mitigation_context(
        detection=detection,
        result=result,
        authentication_mode=MitigationAuthenticationMode.JWT,
        verified_principal=None,
    )
    assert missing.attribution_status is MitigationAttributionStatus.MISSING
    assert missing.actor_key_hash is None
    assert missing.is_admin is False


def test_api_key_attribution_always_remains_missing():
    detection = _detection([_result(evidence_refs=[unique_uuid5()])])
    result = detection.results[0]

    context = integration_service.build_mitigation_context(
        detection=detection,
        result=result,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
        verified_principal=None,
    )
    assert context.attribution_status is MitigationAttributionStatus.MISSING
    assert context.actor_key_hash is None
    assert context.api_key_principal_hash is None
    assert context.is_admin is False

    with pytest.raises(integration_service.MitigationIntegrationValidationError):
        integration_service.build_mitigation_context(
            detection=detection,
            result=result,
            authentication_mode=MitigationAuthenticationMode.API_KEY,
            verified_principal=_principal("admin"),
        )


def test_no_raw_sensitive_values_reach_context_dedupe_decisions_or_logs(
    db_session, monkeypatch, caplog
):
    _seed_policy(db_session)
    caplog.set_level(logging.ERROR)

    raw_ip = "203.0.113.10"
    raw_email = "victim@example.com"
    raw_user_agent = "UA-SECRET-AGENT"
    raw_request_id = "raw-request-123"
    reason = BotReason(
        code="REQUEST_PATTERN_TEST",
        category=BotReasonCategory.REQUEST_PATTERN,
        description="Neutral reason.",
        severity=BotReasonSeverity.INFO,
        details={"request_id": raw_request_id, "user_agent": raw_user_agent},
    )
    detection = _detection(
        [
            _result(
                client_ip=raw_ip,
                actor_id=raw_email,
                evidence_refs=[unique_uuid5()],
                reasons=[reason],
            )
        ]
    )

    captured: dict[str, object] = {}
    decision = evaluated_decision("stage-a-1.0.0")

    def fake_evaluate(result, context, policy):
        captured["context"] = context
        return decision

    def fake_persist(db, decision_arg, *, dedupe_key, decision_uuid=None, created_at=None):
        captured["dedupe_key"] = dedupe_key
        return DecisionPersistenceResult(
            decision=SimpleNamespace(decision_uuid=unique_uuid5()),
            created=True,
        )

    monkeypatch.setattr(integration_service, "evaluate_mitigation_decision", fake_evaluate)
    monkeypatch.setattr(integration_service, "persist_evaluated_decision", fake_persist)

    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    serialized = json.dumps(
        {
            "context": captured["context"].model_dump(mode="json"),
            "dedupe_key": captured["dedupe_key"],
            "outcome": [item.model_dump(mode="json") for item in outcome.outcomes],
        },
        default=str,
    )
    for raw_value in (raw_ip, raw_email, raw_user_agent, raw_request_id):
        assert raw_value not in serialized
        assert raw_value not in caplog.text

    assert str(captured["dedupe_key"]).startswith("mitigation-")


def test_equivalent_retries_reuse_the_existing_decision(db_session):
    _seed_policy(db_session)
    detection = _detection([_result(evidence_refs=[unique_uuid5()])])

    first = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    second = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert first.outcomes[0].status is MitigationOutcomeStatus.PERSISTED
    assert second.outcomes[0].status is MitigationOutcomeStatus.IDEMPOTENT_REUSE
    assert first.outcomes[0].decision_uuid == second.outcomes[0].decision_uuid
    assert db_session.query(MitigationDecisionRow).count() == 1


def test_conflicting_material_payload_is_rejected_without_overwrite(
    db_session, monkeypatch
):
    _seed_policy(db_session)
    reference = unique_uuid5()
    detection = _detection([_result(evidence_refs=[reference])])

    first_decision = evaluated_decision(
        "stage-a-1.0.0", evidence_references=[reference]
    )
    conflicting_decision = evaluated_decision(
        "stage-a-1.0.0",
        decision=MitigationDecisionType.MONITOR,
        explanation="A different but still safe advisory explanation.",
        evidence_references=[reference],
    )
    decisions = iter([first_decision, conflicting_decision])

    def fake_evaluate(result, context, policy):
        return next(decisions)

    monkeypatch.setattr(integration_service, "evaluate_mitigation_decision", fake_evaluate)

    first = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )
    second = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert first.outcomes[0].status is MitigationOutcomeStatus.PERSISTED
    assert second.outcomes[0].status is MitigationOutcomeStatus.CONFLICT
    assert second.outcomes[0].decision is None
    row = db_session.query(MitigationDecisionRow).one()
    assert row.explanation == first_decision.explanation
    assert row.decision_type == MitigationDecisionType.ALLOW.value


def test_policy_load_failure_prevents_evaluation_and_persistence(
    db_session, monkeypatch
):
    def fake_load(db, *, expected_policy_version=None):
        raise ActivePolicyNotFoundError("missing policy")

    def unexpected(*args, **kwargs):
        raise AssertionError("evaluation or persistence must not run")

    monkeypatch.setattr(integration_service, "load_active_policy", fake_load)
    monkeypatch.setattr(
        integration_service, "evaluate_mitigation_decision", unexpected
    )
    monkeypatch.setattr(
        integration_service, "persist_evaluated_decision", unexpected
    )

    detection = _detection(
        [
            _result(evidence_refs=[unique_uuid5()]),
            _result(evidence_refs=[unique_uuid5()]),
        ]
    )
    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert outcome.policy_version is None
    assert [item.status for item in outcome.outcomes] == [
        MitigationOutcomeStatus.POLICY_UNAVAILABLE,
        MitigationOutcomeStatus.POLICY_UNAVAILABLE,
    ]
    assert all(item.decision is None for item in outcome.outcomes)
    assert db_session.query(MitigationDecisionRow).count() == 0


def test_persistence_failure_produces_safe_status(db_session, monkeypatch, caplog):
    _seed_policy(db_session)
    caplog.set_level(logging.ERROR)
    raw_ip = "203.0.113.10"
    detection = _detection(
        [_result(client_ip=raw_ip, evidence_refs=[unique_uuid5()])]
    )

    def fake_persist(db, decision_arg, *, dedupe_key, decision_uuid=None, created_at=None):
        raise DecisionPersistenceError("database unavailable")

    monkeypatch.setattr(integration_service, "persist_evaluated_decision", fake_persist)

    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    assert outcome.outcomes[0].status is MitigationOutcomeStatus.DECISION_NOT_PERSISTED
    assert outcome.outcomes[0].decision is None
    assert "DecisionPersistenceError" in caplog.text
    assert raw_ip not in caplog.text


def test_orchestration_never_commits_or_rolls_back_outer_transaction(
    db_session, monkeypatch
):
    _seed_policy(db_session)

    def unexpected(*args, **kwargs):
        raise AssertionError("commit or rollback must not be called")

    monkeypatch.setattr(db_session, "commit", unexpected)
    monkeypatch.setattr(db_session, "rollback", unexpected)

    db_session.query(MitigationDecisionRow).count()
    before = db_session.in_transaction()
    detection = _detection([_result(evidence_refs=[unique_uuid5()])])

    outcome = integration_service.evaluate_and_persist_bot_detection(
        db_session,
        detection,
        authentication_mode=MitigationAuthenticationMode.API_KEY,
    )

    after = db_session.in_transaction()
    assert before is True
    assert after is True
    assert outcome.outcomes[0].status is MitigationOutcomeStatus.PERSISTED


def test_raw_sensitive_idempotency_key_is_rejected(db_session):
    _seed_policy(db_session)
    detection = _detection([_result(evidence_refs=[unique_uuid5()])])

    with pytest.raises(integration_service.MitigationIntegrationValidationError):
        integration_service.evaluate_and_persist_bot_detection(
            db_session,
            detection,
            authentication_mode=MitigationAuthenticationMode.API_KEY,
            idempotency_key="203.0.113.10",
        )


def test_unexpected_programming_errors_are_not_swallowed(db_session, monkeypatch):
    _seed_policy(db_session)

    def unexpected(*args, **kwargs):
        raise RuntimeError("programming error")

    monkeypatch.setattr(integration_service, "evaluate_mitigation_decision", unexpected)

    detection = _detection([_result(evidence_refs=[unique_uuid5()])])
    with pytest.raises(RuntimeError, match="programming error"):
        integration_service.evaluate_and_persist_bot_detection(
            db_session,
            detection,
            authentication_mode=MitigationAuthenticationMode.API_KEY,
        )
