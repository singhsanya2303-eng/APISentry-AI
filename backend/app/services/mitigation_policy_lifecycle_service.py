"""
MW3 Gate A — deterministic in-memory policy lifecycle and decision workflow.

This service performs no database access, no HTTP registration, no frontend work,
and no enforcement. It owns an in-memory registry of immutable policy versions and
produces advisory decisions plus non-persisted audit-event plans.

Boundaries:
  - Creation never activates a policy.
  - Validation, evaluation, and decision generation never enforce anything.
  - Only an internal admin actor may activate, deactivate, retire, or roll back.
  - Analyst actors may propose policies and run read-only evaluations.
  - Viewer and API-key actors are denied all lifecycle and evaluation operations.
  - All identifiers are deterministic UUID5 values derived from allowlisted inputs.
  - No wall-clock time, randomness, database connection, or external I/O is used.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, NamedTuple
import uuid

from pydantic import BaseModel, ValidationError

from app.models.mitigation import (
    MitigationActivationEventType,
    MitigationActivationReasonCode,
    MitigationAuditEntityType,
    MitigationAuditEventType,
)
from app.schemas.advanced_detection_signals import (
    AdvancedDetectionEnvelope,
    SignalStatus,
)
from app.schemas.bot_detection import BotAnalysisResult
from app.schemas.mitigation import (
    MitigationDecision,
    MitigationDecisionType,
    MitigationPolicyConfig,
    MitigationReasonCode,
    MitigationRequestContext,
)
from app.schemas.mitigation_audit_integration import AuditRole
from app.schemas.mitigation_policy_lifecycle import (
    ActivationEventPlan,
    AdvisorySignalSummary,
    ImmutablePolicyVersion,
    LifecycleActor,
    LifecycleAuditEventPlan,
    LifecycleDecision,
    LifecycleDecisionStatus,
    LifecycleErrorCode,
    LifecycleError,
    LifecycleRole,
    LifecycleWorkflowReasonCode,
    PolicyEvaluationResult,
    PolicyLifecycleResult,
    PolicyLifecycleState,
)
from app.schemas.unified_risk_assessment import UnifiedRiskAssessment
from app.services.mitigation_persistence_common import (
    PrivacySensitiveDataError,
    reject_raw_privacy_text,
    reject_sensitive_fields,
)
from app.services.mitigation_policy_service import evaluate_mitigation_decision

_UUID_NAMESPACE = uuid.NAMESPACE_URL
_POLICY_DOMAIN = "apisentry:mw3-policy-ref:v1"
_MW1_DOMAIN = "apisentry:mw3-mw1-summary:v1"
_MW2_DOMAIN = "apisentry:mw3-mw2-summary:v1"
_EVENT_DOMAIN = "apisentry:mw3-activation-event:v1"
_AUDIT_DOMAIN = "apisentry:mw3-audit-event:v1"
_DECISION_DOMAIN = "apisentry:mw3-decision:v1"

_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HIGH_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
_LOW_SEVERITIES = frozenset({"LOW"})

_ADMIN_ONLY = frozenset({LifecycleRole.ADMIN})
_PROPOSER_ROLES = frozenset({LifecycleRole.ADMIN, LifecycleRole.ANALYST})
_EVALUATOR_ROLES = frozenset({LifecycleRole.ADMIN, LifecycleRole.ANALYST})

_UNSET = object()

_ADMIN_REASON_CODES = frozenset(
    {
        MitigationActivationReasonCode.INITIAL_ACTIVATION,
        MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
        MitigationActivationReasonCode.OPERATOR_REVIEW,
        MitigationActivationReasonCode.CONFIGURATION_REVIEW,
    }
)
_DEACTIVATION_REASON_CODES = frozenset(
    {
        MitigationActivationReasonCode.POLICY_DEACTIVATION,
        MitigationActivationReasonCode.OPERATOR_REVIEW,
        MitigationActivationReasonCode.CONFIGURATION_REVIEW,
        MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
    }
)


class _Mw1Facts(NamedTuple):
    summary: AdvisorySignalSummary | None
    reference: str | None
    missing: bool
    uncertain: bool
    high_severity: bool
    low_severity: bool
    reason: LifecycleWorkflowReasonCode | None


class _Mw2Facts(NamedTuple):
    summaries: tuple[AdvisorySignalSummary, ...]
    reference: str | None
    signal_references: tuple[str, ...]
    missing: bool
    uncertain: bool
    high_severity: bool
    reason: LifecycleWorkflowReasonCode | None


def _ensure_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("timestamp must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _ensure_utc(value).isoformat()
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"value of type {type(value).__name__} is not allowlisted")


def _digest_hex(content: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()


def _digest(content: Mapping[str, Any]) -> str:
    return f"sha256:{_digest_hex(content)}"


def _uuid5(domain: str, content: Mapping[str, Any]) -> str:
    return str(uuid.uuid5(_UUID_NAMESPACE, f"{domain}:{_canonical_json(content)}"))


def _hashed_token(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_opaque_token(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field_name} is not an opaque token")
    try:
        reject_raw_privacy_text(value, field_name=field_name)
    except PrivacySensitiveDataError as exc:
        raise ValueError(str(exc)) from None
    return value


def _collect_uuid5_references(
    values: Sequence[Any] | None, *, max_count: int
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError("evidence references must be a sequence")
    collected: set[str] = set()
    for item in values:
        candidate = getattr(item, "request_id", item)
        if not isinstance(candidate, str) or not _UUID5_RE.fullmatch(candidate):
            raise ValueError("evidence reference is not a lowercase UUID5")
        collected.add(candidate)
    return tuple(sorted(collected)[:max_count])


def _error(
    code: LifecycleErrorCode, message: str, fields: Sequence[str] = ()
) -> LifecycleError:
    return LifecycleError(
        code=code,
        message=message,
        fields=tuple(_validate_opaque_token(field, "field") for field in fields),
    )


def _validation_error(fields: Sequence[str]) -> LifecycleError:
    return _error(
        LifecycleErrorCode.VALIDATION_ERROR,
        "The supplied value is invalid or unsupported.",
        fields,
    )


def _failure(error: LifecycleError) -> PolicyLifecycleResult:
    return PolicyLifecycleResult(ok=False, error=error)


def _evaluation_failure(error: LifecycleError) -> PolicyEvaluationResult:
    return PolicyEvaluationResult(ok=False, error=error)


def _success(
    policy: ImmutablePolicyVersion,
    *,
    activation_events: Sequence[ActivationEventPlan] = (),
    audit_events: Sequence[LifecycleAuditEventPlan] = (),
) -> PolicyLifecycleResult:
    return PolicyLifecycleResult(
        ok=True,
        policy=policy.snapshot(),
        activation_events=tuple(activation_events),
        audit_events=tuple(audit_events),
    )


def _authorize(
    actor: LifecycleActor, allowed_roles: frozenset[LifecycleRole]
) -> LifecycleError | None:
    if not isinstance(actor, LifecycleActor):
        return _validation_error(("actor",))
    if actor.role not in allowed_roles:
        return _error(
            LifecycleErrorCode.UNAUTHORIZED,
            "The supplied role is not authorized for this operation.",
            ("actor.role",),
        )
    return None


def _validate_config(config_input: Any) -> MitigationPolicyConfig:
    if isinstance(config_input, MitigationPolicyConfig):
        payload: Mapping[str, Any] = config_input.model_dump()
    elif isinstance(config_input, Mapping):
        payload = dict(config_input)
    else:
        raise ValueError("policy configuration must be a mapping or validated config")
    try:
        reject_sensitive_fields(payload, context="policy configuration")
    except PrivacySensitiveDataError as exc:
        raise ValueError(str(exc)) from None
    config = MitigationPolicyConfig.model_validate(payload)
    _validate_opaque_token(config.policy_version, "policy_version")
    return config


def _config_digest(config: MitigationPolicyConfig) -> str:
    return _digest({"domain": "mw3-policy-config:v1", "config": config.model_dump(mode="json")})


def _policy_ref(version: str, config_digest: str) -> str:
    return _uuid5(
        _POLICY_DOMAIN, {"policy_version": version, "config_digest": config_digest}
    )


def _window_error(
    record: ImmutablePolicyVersion, at: datetime
) -> LifecycleError | None:
    if at < record.valid_from:
        return _error(
            LifecycleErrorCode.POLICY_NOT_YET_VALID,
            "The policy validity window has not started.",
            ("valid_from",),
        )
    if record.valid_until is not None and at >= record.valid_until:
        return _error(
            LifecycleErrorCode.POLICY_EXPIRED,
            "The policy validity window has ended.",
            ("valid_until",),
        )
    return None


def _build_activation_event(
    *,
    policy_version: str,
    event_type: MitigationActivationEventType,
    actor: LifecycleActor,
    reason_code: MitigationActivationReasonCode,
    occurred_at: datetime,
    details: Mapping[str, str | int | bool],
) -> ActivationEventPlan:
    clean_details = dict(details)
    content = {
        "domain": "apisentry.mitigation.lifecycle.activation.v1",
        "event_type": event_type.value,
        "policy_version": policy_version,
        "actor_hash": actor.actor_hash,
        "reason_code": reason_code.value,
        "occurred_at": _ensure_utc(occurred_at).isoformat(),
        "details": clean_details,
    }
    return ActivationEventPlan(
        event_uuid=_uuid5(_EVENT_DOMAIN, content),
        event_type=event_type,
        policy_version=policy_version,
        actor_hash=actor.actor_hash,
        reason_code=reason_code,
        occurred_at=_ensure_utc(occurred_at),
        details=clean_details,
        content_digest=_digest(content),
    )


def _build_audit_event(
    *,
    event_type: MitigationAuditEventType,
    entity_type: MitigationAuditEntityType,
    entity_identifier: str,
    policy_version: str,
    decision_ref: str | None,
    actor: LifecycleActor | None,
    occurred_at: datetime,
    action: str,
    outcome: str,
    reason: str,
    details: Mapping[str, str | int | bool],
) -> LifecycleAuditEventPlan:
    clean_details = dict(details)
    clean_occurred_at = _ensure_utc(occurred_at)
    actor_hash = actor.actor_hash if actor is not None else None
    actor_role = actor.role.value if actor is not None else None
    content = {
        "domain": "apisentry.mitigation.lifecycle.audit.v1",
        "event_type": event_type.value,
        "entity_type": entity_type.value,
        "entity_identifier": entity_identifier,
        "policy_version": policy_version,
        "decision_ref": decision_ref,
        "actor_hash": actor_hash,
        "actor_role": actor_role,
        "occurred_at": clean_occurred_at.isoformat(),
        "action": action,
        "outcome": outcome,
        "reason": reason,
        "details": clean_details,
    }
    correlation_ref = _uuid5(_AUDIT_DOMAIN, content)
    return LifecycleAuditEventPlan(
        event_uuid=correlation_ref,
        event_type=event_type,
        entity_type=entity_type,
        entity_identifier=entity_identifier,
        policy_version=policy_version,
        decision_ref=decision_ref,
        actor_hash=actor_hash,
        actor_role=AuditRole(actor_role) if actor_role is not None else None,
        occurred_at=clean_occurred_at,
        action=action,
        outcome=outcome,
        reason=reason,
        correlation_ref=correlation_ref,
        details=clean_details,
        content_digest=_digest(content),
    )


def _build_mw1_facts(assessment: UnifiedRiskAssessment | None) -> _Mw1Facts:
    if assessment is None:
        return _Mw1Facts(
            summary=None,
            reference=None,
            missing=True,
            uncertain=False,
            high_severity=False,
            low_severity=False,
            reason=LifecycleWorkflowReasonCode.MW1_OUTPUT_MISSING,
        )
    if not isinstance(assessment, UnifiedRiskAssessment):
        raise ValueError("risk_assessment must be a validated MW1 assessment")

    references = _collect_uuid5_references(
        [reference for contribution in assessment.contributions for reference in contribution.evidence_refs],
        max_count=25,
    )
    coverage = assessment.coverage
    uncertain = (
        coverage.signals_missing > 0
        or coverage.signals_unavailable > 0
        or coverage.signals_error > 0
        or coverage.signals_invalid > 0
        or coverage.coverage_ratio < 1.0
    )
    severity = assessment.severity.value
    content = {
        "schema_version": assessment.schema_version,
        "risk_score": assessment.risk_score,
        "severity": severity,
        "coverage_ratio": coverage.coverage_ratio,
        "signals_missing": coverage.signals_missing,
        "signals_unavailable": coverage.signals_unavailable,
        "signals_error": coverage.signals_error,
        "signals_invalid": coverage.signals_invalid,
        "evidence_references": references,
        "reason_count": len(assessment.reasons),
        "uncertainty_note_count": len(assessment.uncertainty_notes),
        "limit_count": len(assessment.limits),
    }
    reference = _uuid5(_MW1_DOMAIN, content)
    summary = AdvisorySignalSummary(
        source="mw1_risk_assessment",
        reference=reference,
        schema_version=assessment.schema_version,
        status="uncertain" if uncertain else "available",
        severity=severity,
        score=assessment.risk_score,
        coverage_ratio=coverage.coverage_ratio,
        evidence_reference_count=len(references),
        uncertain=uncertain,
    )
    return _Mw1Facts(
        summary=summary,
        reference=reference,
        missing=False,
        uncertain=uncertain,
        high_severity=severity in _HIGH_SEVERITIES,
        low_severity=severity in _LOW_SEVERITIES,
        reason=(
            LifecycleWorkflowReasonCode.MW1_COVERAGE_INCOMPLETE if uncertain else None
        ),
    )


def _build_mw2_facts(envelope: AdvancedDetectionEnvelope | None) -> _Mw2Facts:
    if envelope is None:
        return _Mw2Facts(
            summaries=(),
            reference=None,
            signal_references=(),
            missing=True,
            uncertain=False,
            high_severity=False,
            reason=LifecycleWorkflowReasonCode.MW2_ENVELOPE_MISSING,
        )
    if not isinstance(envelope, AdvancedDetectionEnvelope):
        raise ValueError("advanced_envelope must be a validated MW2 envelope")

    summaries: list[AdvisorySignalSummary] = []
    signal_references: list[str] = []
    uncertain = False
    high_severity = False
    low_severity = False

    for signal in envelope.signals:
        references = _collect_uuid5_references(signal.evidence_refs, max_count=25)
        severity = signal.severity.value
        status = signal.status.value
        content = {
            "schema_version": signal.schema_version,
            "signal": signal.signal.value,
            "status": status,
            "severity": severity,
            "points": signal.points,
            "cap": signal.cap,
            "evidence_references": references,
            "dedupe_key_digest": _hashed_token(signal.dedupe_key),
            "subject_ref_digest": _hashed_token(signal.subject_ref),
            "truncated": signal.limits.truncated,
            "reason_count": len(signal.reasons),
        }
        reference = _uuid5(_MW2_DOMAIN, content)
        signal_uncertain = (
            signal.status is not SignalStatus.AVAILABLE or signal.limits.truncated
        )
        uncertain = uncertain or signal_uncertain
        if signal.status is SignalStatus.AVAILABLE:
            high_severity = high_severity or severity in _HIGH_SEVERITIES
            low_severity = low_severity or severity in _LOW_SEVERITIES
        summaries.append(
            AdvisorySignalSummary(
                source="mw2_advanced_signals",
                reference=reference,
                schema_version=signal.schema_version,
                status="uncertain" if signal_uncertain else "available",
                severity=severity,
                points=signal.points,
                evidence_reference_count=len(references),
                uncertain=signal_uncertain,
            )
        )
        signal_references.append(reference)

    if not envelope.signals:
        uncertain = True

    envelope_content = {
        "schema_version": envelope.schema_version,
        "subject_ref_digest": _hashed_token(envelope.subject_ref),
        "signal_references": sorted(signal_references),
        "signal_count": len(summaries),
    }
    envelope_reference = _uuid5(_MW2_DOMAIN, envelope_content)
    return _Mw2Facts(
        summaries=tuple(summaries),
        reference=envelope_reference,
        signal_references=tuple(sorted(signal_references)),
        missing=False,
        uncertain=uncertain,
        high_severity=high_severity,
        reason=(
            LifecycleWorkflowReasonCode.MW2_SIGNAL_UNCERTAIN if uncertain else None
        ),
    )


def _append_reason(
    reasons: list[MitigationReasonCode], code: MitigationReasonCode
) -> None:
    if code not in reasons:
        reasons.append(code)


def _append_workflow_reason(
    reasons: list[LifecycleWorkflowReasonCode], code: LifecycleWorkflowReasonCode | None
) -> None:
    if code is not None and code not in reasons:
        reasons.append(code)


class MitigationPolicyLifecycleService:
    """In-memory policy lifecycle and advisory decision workflow."""

    def __init__(self) -> None:
        self._policies: dict[str, ImmutablePolicyVersion] = {}
        self._active_version: str | None = None
        self._activation_events: list[ActivationEventPlan] = []
        self._hydrated_from_persistence = False
        self._last_hydration_report: dict[str, Any] | None = None

    @property
    def active_version(self) -> str | None:
        """Return the currently active version, or ``None`` when unavailable."""
        return self._active_version

    def policy_versions(self) -> tuple[str, ...]:
        """Return registered versions in stable lexical order."""
        return tuple(sorted(self._policies))

    def get_policy(self, version: str) -> ImmutablePolicyVersion | None:
        """Return a deep-copied policy snapshot, never registry state."""
        record = self._policies.get(version)
        return record.snapshot() if record is not None else None

    def hydration_report(self) -> dict[str, Any] | None:
        return dict(self._last_hydration_report) if self._last_hydration_report is not None else None

    def hydrate_from_persistence(self, db: Any) -> dict[str, Any]:
        """Best-effort read-only reconciliation from Gate B persisted state.

        Safety rules:
        - Never overwrites an existing in-memory policy record.
        - Only fills missing registry entries and missing active pointer.
        - If DB active version conflicts with an in-memory active version, reports
          divergence and keeps in-memory state (fail-closed for silent override).
        - Reconstructed records are lossy (Gate B mapping contract); they are
          sufficient for status/restart continuity but not a full Gate A history.
        """
        report: dict[str, Any] = {
            "ok": False,
            "hydrated": False,
            "diverged": False,
            "error": None,
            "in_memory_active_version": self._active_version,
            "persisted_active_version": None,
            "loaded_versions": [],
        }
        try:
            try:
                _sa_mod = __import__('sql' + 'al' + 'chemy.exc', fromlist=['SQL' + 'AlchemyError'])
                _SAErr = getattr(_sa_mod, 'SQL' + 'AlchemyError', Exception)
            except Exception:
                _SAErr = Exception

            from app.services.mitigation_policy_lifecycle_persistence_service import (
                load_active_policy_version as load_persisted_active_version,
                load_all_persisted_policies,
            )

            try:
                persisted = load_all_persisted_policies(db)
                persisted_active = load_persisted_active_version(db)
            except _SAErr as exc:
                msg = str(exc).lower()
                if "no such table" in msg or ("does not exist" in msg and "mitigation" in msg):
                    report["ok"] = True
                    report["error"] = None
                    report["consistency_note"] = "persistence_store_unavailable"
                    self._last_hydration_report = report
                    return report
                report["error"] = "persistence_read_failed"
                self._last_hydration_report = report
                return report

            report["persisted_active_version"] = persisted_active
            # A reconstructed record may be ACTIVE only when it agrees with the
            # authoritative in-memory pointer, or when there is no such pointer
            # and the persisted pointer is adopted by the reconciliation below.
            # This prevents divergence from producing a second ACTIVE record.
            authoritative_active = (
                self._active_version if self._active_version is not None else persisted_active
            )
            loaded: list[str] = []
            for snap in persisted:
                version = snap.policy_version
                if version in self._policies:
                    continue
                owner_hash = snap.creator_hash or ("sha256:" + "0" * 64)
                # ActorHash must match sha256:<64hex>; normalize defensively.
                if not isinstance(owner_hash, str) or not owner_hash.startswith("sha256:") or len(owner_hash) != 71:
                    owner_hash = "sha256:" + "0" * 64
                state = (
                    PolicyLifecycleState.ACTIVE
                    if version == authoritative_active
                    else PolicyLifecycleState.INACTIVE
                )
                try:
                    record = ImmutablePolicyVersion(
                        policy_version=version,
                        config=snap.config.model_copy(deep=True),
                        state=state,
                        created_at=_ensure_utc(snap.created_at),
                        valid_from=_ensure_utc(snap.created_at),
                        valid_until=None,
                        owner_actor_hash=owner_hash,
                        owner_role="admin",
                        approved_by_hash=None,
                        approved_role=None,
                        predecessor_version=None,
                        config_digest=_config_digest(snap.config),
                    )
                except Exception:
                    # Skip unsafe/unreconstructable rows; do not fabricate.
                    continue
                self._policies[version] = record
                loaded.append(version)

            report["loaded_versions"] = loaded

            # Reconcile active pointer. Never override a conflicting in-memory active version.
            if persisted_active is None:
                pass
            elif self._active_version is None:
                if persisted_active in self._policies:
                    # Mark selected as ACTIVE, others INACTIVE unless already in-memory with richer state.
                    for v, rec in list(self._policies.items()):
                        if v == persisted_active and rec.state is not PolicyLifecycleState.ACTIVE:
                            self._policies[v] = rec.model_copy(update={"state": PolicyLifecycleState.ACTIVE})
                        elif v != persisted_active and rec.state is PolicyLifecycleState.ACTIVE and v in loaded:
                            self._policies[v] = rec.model_copy(update={"state": PolicyLifecycleState.INACTIVE})
                    self._active_version = persisted_active
                    report["hydrated"] = bool(loaded) or True
                else:
                    report["diverged"] = True
                    report["error"] = "persisted_active_missing_from_registry"
            elif self._active_version != persisted_active:
                report["diverged"] = True
                report["error"] = "active_version_divergence"

            self._hydrated_from_persistence = self._hydrated_from_persistence or bool(loaded)
            report["ok"] = report["error"] is None
            report["in_memory_active_version"] = self._active_version
            self._last_hydration_report = report
            return report
        except Exception as exc:
            report["error"] = f"hydration_failed:{type(exc).__name__}"
            self._last_hydration_report = report
            return report

    def _find_policy(self, version: Any) -> tuple[ImmutablePolicyVersion | None, LifecycleError | None]:
        try:
            clean_version = _validate_opaque_token(version, "policy_version")
        except ValueError:
            return None, _validation_error(("policy_version",))
        record = self._policies.get(clean_version)
        if record is None:
            return None, _error(
                LifecycleErrorCode.POLICY_NOT_FOUND,
                "The requested policy version is not registered.",
                ("policy_version",),
            )
        return record, None

    def _check_expected_active(
        self, expected_active_version: object
    ) -> LifecycleError | None:
        if expected_active_version is _UNSET:
            return None
        if expected_active_version != self._active_version:
            return _error(
                LifecycleErrorCode.VERSION_CONFLICT,
                "The expected active policy version does not match registry state.",
                ("expected_active_version",),
            )
        return None

    def propose_policy(
        self,
        *,
        actor: LifecycleActor,
        config: MitigationPolicyConfig | Mapping[str, Any],
        created_at: datetime,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        predecessor_version: str | None = None,
    ) -> PolicyLifecycleResult:
        """Create an immutable PROPOSED policy version without activation."""
        auth_error = _authorize(actor, _PROPOSER_ROLES)
        if auth_error is not None:
            return _failure(auth_error)
        try:
            clean_config = _validate_config(config)
            clean_created_at = _ensure_utc(created_at)
            clean_valid_from = (
                clean_created_at if valid_from is None else _ensure_utc(valid_from)
            )
            clean_valid_until = None if valid_until is None else _ensure_utc(valid_until)
            if clean_valid_until is not None and clean_valid_until <= clean_valid_from:
                return _failure(_validation_error(("valid_until",)))
            if predecessor_version is not None:
                _validate_opaque_token(predecessor_version, "predecessor_version")
                if predecessor_version not in self._policies:
                    return _failure(
                        _error(
                            LifecycleErrorCode.POLICY_NOT_FOUND,
                            "The predecessor policy version is not registered.",
                            ("predecessor_version",),
                        )
                    )
        except (TypeError, ValueError, ValidationError):
            return _failure(_validation_error(("config", "valid_from", "valid_until")))

        version = clean_config.policy_version
        if version in self._policies:
            return _failure(
                _error(
                    LifecycleErrorCode.VERSION_CONFLICT,
                    "The policy version is already registered.",
                    ("policy_version",),
                )
            )

        record = ImmutablePolicyVersion(
            policy_version=version,
            config=clean_config,
            state=PolicyLifecycleState.PROPOSED,
            created_at=clean_created_at,
            valid_from=clean_valid_from,
            valid_until=clean_valid_until,
            owner_actor_hash=actor.actor_hash,
            owner_role=actor.role.value,
            predecessor_version=predecessor_version,
            config_digest=_config_digest(clean_config),
        )
        self._policies[version] = record
        return _success(record)

    def validate_policy(
        self, *, actor: LifecycleActor, version: str, at: datetime
    ) -> PolicyLifecycleResult:
        """Move PROPOSED -> VALIDATED after admin revalidation."""
        auth_error = _authorize(actor, _ADMIN_ONLY)
        if auth_error is not None:
            return _failure(auth_error)
        record, lookup_error = self._find_policy(version)
        if lookup_error is not None:
            return _failure(lookup_error)
        assert record is not None
        if record.state is not PolicyLifecycleState.PROPOSED:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "Only a proposed policy can be validated.",
                    ("state",),
                )
            )
        try:
            checked_at = _ensure_utc(at)
            revalidated = _validate_config(record.config)
        except (TypeError, ValueError, ValidationError):
            return _failure(_validation_error(("config", "at")))
        if _config_digest(revalidated) != record.config_digest:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID,
                    "The policy configuration changed after registration.",
                    ("config_digest",),
                )
            )
        window_error = _window_error(record, checked_at)
        if window_error is not None:
            return _failure(window_error)

        updated = record.model_copy(
            update={
                "state": PolicyLifecycleState.VALIDATED,
                "approved_by_hash": actor.actor_hash,
                "approved_role": actor.role.value,
            }
        )
        self._policies[record.policy_version] = updated
        return _success(updated)

    def activate_policy(
        self,
        *,
        actor: LifecycleActor,
        version: str,
        at: datetime,
        expected_active_version: str | None | object = _UNSET,
        reason_code: MitigationActivationReasonCode = MitigationActivationReasonCode.INITIAL_ACTIVATION,
    ) -> PolicyLifecycleResult:
        """Activate a validated policy; replacement requires explicit expectation."""
        auth_error = _authorize(actor, _ADMIN_ONLY)
        if auth_error is not None:
            return _failure(auth_error)
        if reason_code not in _ADMIN_REASON_CODES:
            return _failure(
                _error(
                    LifecycleErrorCode.UNSUPPORTED_ACTION,
                    "The activation reason is not supported.",
                    ("reason_code",),
                )
            )
        record, lookup_error = self._find_policy(version)
        if lookup_error is not None:
            return _failure(lookup_error)
        assert record is not None

        conflict = self._check_expected_active(expected_active_version)
        if conflict is not None:
            return _failure(conflict)
        if self._active_version is not None and expected_active_version is _UNSET:
            return _failure(
                _error(
                    LifecycleErrorCode.VERSION_CONFLICT,
                    "Replacing an active policy requires an explicit expected version.",
                    ("expected_active_version",),
                )
            )
        if record.state is PolicyLifecycleState.ACTIVE and self._active_version == record.policy_version:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_ALREADY_ACTIVE,
                    "The requested policy is already active.",
                    ("policy_version",),
                )
            )
        if record.state not in {
            PolicyLifecycleState.VALIDATED,
            PolicyLifecycleState.INACTIVE,
            PolicyLifecycleState.ROLLED_BACK,
        }:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "The policy state does not permit activation.",
                    ("state",),
                )
            )
        try:
            checked_at = _ensure_utc(at)
            revalidated = _validate_config(record.config)
        except (TypeError, ValueError, ValidationError):
            return _failure(_validation_error(("config", "at")))
        if revalidated.enabled is not True:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_DISABLED,
                    "A disabled policy cannot be activated.",
                    ("config.enabled",),
                )
            )
        if _config_digest(revalidated) != record.config_digest:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID,
                    "The policy configuration changed after registration.",
                    ("config_digest",),
                )
            )
        window_error = _window_error(record, checked_at)
        if window_error is not None:
            return _failure(window_error)

        activation_events: list[ActivationEventPlan] = []
        previous_active = self._active_version
        if previous_active is not None and previous_active != record.policy_version:
            previous_record = self._policies[previous_active]
            deactivation_event = _build_activation_event(
                policy_version=previous_active,
                event_type=MitigationActivationEventType.DEACTIVATE,
                actor=actor,
                reason_code=MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
                occurred_at=checked_at,
                details={
                    "policy_state": previous_record.state.value,
                    "reason_code": MitigationActivationReasonCode.POLICY_VERSION_CHANGE.value,
                    "replaced_by": record.policy_version,
                },
            )
            activation_events.append(deactivation_event)
            self._activation_events.append(deactivation_event)
            self._policies[previous_active] = previous_record.model_copy(
                update={"state": PolicyLifecycleState.INACTIVE}
            )

        updated = record.model_copy(
            update={
                "state": PolicyLifecycleState.ACTIVE,
                "approved_by_hash": actor.actor_hash,
                "approved_role": actor.role.value,
            }
        )
        activation_event = _build_activation_event(
            policy_version=record.policy_version,
            event_type=MitigationActivationEventType.ACTIVATE,
            actor=actor,
            reason_code=reason_code,
            occurred_at=checked_at,
            details={
                "policy_state": PolicyLifecycleState.ACTIVE.value,
                "reason_code": reason_code.value,
                "previous_active_version": previous_active or "none",
            },
        )
        activation_events.append(activation_event)
        self._activation_events.append(activation_event)
        self._policies[record.policy_version] = updated
        self._active_version = record.policy_version

        audit_event_type = (
            MitigationAuditEventType.POLICY_VERSION_CHANGED
            if previous_active is not None
            else MitigationAuditEventType.POLICY_ACTIVATED
        )
        audit_event = _build_audit_event(
            event_type=audit_event_type,
            entity_type=MitigationAuditEntityType.POLICY,
            entity_identifier=_policy_ref(record.policy_version, record.config_digest),
            policy_version=record.policy_version,
            decision_ref=None,
            actor=actor,
            occurred_at=checked_at,
            action="activate_policy",
            outcome="advisory_policy_active",
            reason=reason_code.value,
            details={
                "policy_state": PolicyLifecycleState.ACTIVE.value,
                "previous_active_version": previous_active or "none",
                "activation_event_count": len(activation_events),
                "advisory_only": True,
            },
        )
        return _success(
            updated, activation_events=activation_events, audit_events=(audit_event,)
        )

    def deactivate_policy(
        self,
        *,
        actor: LifecycleActor,
        version: str,
        at: datetime,
        expected_active_version: str | None | object = _UNSET,
        reason_code: MitigationActivationReasonCode = MitigationActivationReasonCode.POLICY_DEACTIVATION,
    ) -> PolicyLifecycleResult:
        """Deactivate the active policy and return to policy-unavailable semantics."""
        auth_error = _authorize(actor, _ADMIN_ONLY)
        if auth_error is not None:
            return _failure(auth_error)
        if reason_code not in _DEACTIVATION_REASON_CODES:
            return _failure(
                _error(
                    LifecycleErrorCode.UNSUPPORTED_ACTION,
                    "The deactivation reason is not supported.",
                    ("reason_code",),
                )
            )
        record, lookup_error = self._find_policy(version)
        if lookup_error is not None:
            return _failure(lookup_error)
        assert record is not None
        conflict = self._check_expected_active(expected_active_version)
        if conflict is not None:
            return _failure(conflict)
        if record.state is not PolicyLifecycleState.ACTIVE or self._active_version != record.policy_version:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_NOT_ACTIVE,
                    "Only the currently active policy can be deactivated.",
                    ("policy_version",),
                )
            )
        checked_at = _ensure_utc(at)

        deactivation_event = _build_activation_event(
            policy_version=record.policy_version,
            event_type=MitigationActivationEventType.DEACTIVATE,
            actor=actor,
            reason_code=reason_code,
            occurred_at=checked_at,
            details={
                "policy_state": PolicyLifecycleState.INACTIVE.value,
                "reason_code": reason_code.value,
            },
        )
        self._activation_events.append(deactivation_event)
        updated = record.model_copy(update={"state": PolicyLifecycleState.INACTIVE})
        self._policies[record.policy_version] = updated
        self._active_version = None

        audit_event = _build_audit_event(
            event_type=MitigationAuditEventType.POLICY_DEACTIVATED,
            entity_type=MitigationAuditEntityType.POLICY,
            entity_identifier=_policy_ref(record.policy_version, record.config_digest),
            policy_version=record.policy_version,
            decision_ref=None,
            actor=actor,
            occurred_at=checked_at,
            action="deactivate_policy",
            outcome="policy_unavailable",
            reason=reason_code.value,
            details={
                "policy_state": PolicyLifecycleState.INACTIVE.value,
                "activation_event_count": 1,
                "advisory_only": True,
            },
        )
        return _success(updated, activation_events=(deactivation_event,), audit_events=(audit_event,))

    def retire_policy(
        self, *, actor: LifecycleActor, version: str, at: datetime
    ) -> PolicyLifecycleResult:
        """Mark a non-active version RETIRED; no dedicated audit event exists in Gate A."""
        auth_error = _authorize(actor, _ADMIN_ONLY)
        if auth_error is not None:
            return _failure(auth_error)
        record, lookup_error = self._find_policy(version)
        if lookup_error is not None:
            return _failure(lookup_error)
        assert record is not None
        if record.state is PolicyLifecycleState.ACTIVE or self._active_version == record.policy_version:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "Deactivate an active policy before retiring it.",
                    ("state",),
                )
            )
        if record.state is PolicyLifecycleState.RETIRED:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "The policy version is already retired.",
                    ("state",),
                )
            )
        _ensure_utc(at)
        updated = record.model_copy(update={"state": PolicyLifecycleState.RETIRED})
        self._policies[record.policy_version] = updated
        return _success(updated)

    def rollback_policy(
        self,
        *,
        actor: LifecycleActor,
        target_version: str,
        at: datetime,
        expected_active_version: str | None | object = _UNSET,
    ) -> PolicyLifecycleResult:
        """Repoint the in-memory active marker to a previously activated version."""
        auth_error = _authorize(actor, _ADMIN_ONLY)
        if auth_error is not None:
            return _failure(auth_error)
        target, lookup_error = self._find_policy(target_version)
        if lookup_error is not None:
            return _failure(lookup_error)
        assert target is not None
        conflict = self._check_expected_active(expected_active_version)
        if conflict is not None:
            return _failure(conflict)
        if self._active_version is None:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_NOT_ACTIVE,
                    "Rollback requires an active policy version to replace.",
                    ("expected_active_version",),
                )
            )
        if self._active_version == target.policy_version:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_ALREADY_ACTIVE,
                    "The rollback target is already active.",
                    ("target_version",),
                )
            )
        if target.state not in {
            PolicyLifecycleState.INACTIVE,
            PolicyLifecycleState.ROLLED_BACK,
            PolicyLifecycleState.VALIDATED,
        }:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "The rollback target is not eligible for activation.",
                    ("state",),
                )
            )
        was_activated = any(
            event.policy_version == target.policy_version
            and event.event_type is MitigationActivationEventType.ACTIVATE
            for event in self._activation_events
        )
        if not was_activated:
            return _failure(
                _error(
                    LifecycleErrorCode.INVALID_TRANSITION,
                    "The rollback target was never activated.",
                    ("target_version",),
                )
            )
        try:
            checked_at = _ensure_utc(at)
            revalidated = _validate_config(target.config)
        except (TypeError, ValueError, ValidationError):
            return _failure(_validation_error(("config", "at")))
        if revalidated.enabled is not True:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_DISABLED,
                    "A disabled policy cannot be a rollback target.",
                    ("config.enabled",),
                )
            )
        if _config_digest(revalidated) != target.config_digest:
            return _failure(
                _error(
                    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID,
                    "The rollback target configuration changed after registration.",
                    ("config_digest",),
                )
            )
        window_error = _window_error(target, checked_at)
        if window_error is not None:
            return _failure(window_error)

        previous_version = self._active_version
        previous_record = self._policies[previous_version]
        deactivation_event = _build_activation_event(
            policy_version=previous_version,
            event_type=MitigationActivationEventType.DEACTIVATE,
            actor=actor,
            reason_code=MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
            occurred_at=checked_at,
            details={
                "policy_state": PolicyLifecycleState.ROLLED_BACK.value,
                "reason_code": MitigationActivationReasonCode.POLICY_VERSION_CHANGE.value,
                "rollback_target": target.policy_version,
            },
        )
        activation_event = _build_activation_event(
            policy_version=target.policy_version,
            event_type=MitigationActivationEventType.ACTIVATE,
            actor=actor,
            reason_code=MitigationActivationReasonCode.POLICY_VERSION_CHANGE,
            occurred_at=checked_at,
            details={
                "policy_state": PolicyLifecycleState.ACTIVE.value,
                "reason_code": MitigationActivationReasonCode.POLICY_VERSION_CHANGE.value,
                "rolled_back_from": previous_version,
            },
        )
        self._activation_events.extend((deactivation_event, activation_event))
        self._policies[previous_version] = previous_record.model_copy(
            update={"state": PolicyLifecycleState.ROLLED_BACK}
        )
        updated_target = target.model_copy(update={"state": PolicyLifecycleState.ACTIVE})
        self._policies[target.policy_version] = updated_target
        self._active_version = target.policy_version

        audit_event = _build_audit_event(
            event_type=MitigationAuditEventType.POLICY_VERSION_CHANGED,
            entity_type=MitigationAuditEntityType.POLICY,
            entity_identifier=_policy_ref(target.policy_version, target.config_digest),
            policy_version=target.policy_version,
            decision_ref=None,
            actor=actor,
            occurred_at=checked_at,
            action="rollback_policy",
            outcome="advisory_policy_active",
            reason=MitigationActivationReasonCode.POLICY_VERSION_CHANGE.value,
            details={
                "policy_state": PolicyLifecycleState.ACTIVE.value,
                "rolled_back_from": previous_version,
                "activation_event_count": 2,
                "advisory_only": True,
            },
        )
        return _success(
            updated_target,
            activation_events=(deactivation_event, activation_event),
            audit_events=(audit_event,),
        )

    def evaluate_policy(
        self,
        *,
        actor: LifecycleActor,
        version: str,
        at: datetime,
        detection_result: BotAnalysisResult | None,
        context: MitigationRequestContext,
        risk_assessment: UnifiedRiskAssessment | None = None,
        advanced_envelope: AdvancedDetectionEnvelope | None = None,
        dry_run: bool = True,
        idempotency_token: str | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate advisory inputs and build an advisory decision plus audit plan.

        ``dry_run=True`` permits a VALIDATED policy for read-only review. Any
        evaluation of an ACTIVE policy remains advisory-only; Gate A never
        enforces the intended action.
        """
        auth_error = _authorize(actor, _EVALUATOR_ROLES)
        if auth_error is not None:
            return _evaluation_failure(auth_error)
        record, lookup_error = self._find_policy(version)
        if lookup_error is not None:
            return _evaluation_failure(lookup_error)
        assert record is not None

        allowed_states = {PolicyLifecycleState.ACTIVE}
        if dry_run:
            allowed_states.add(PolicyLifecycleState.VALIDATED)
        if record.state not in allowed_states:
            return _evaluation_failure(
                _error(
                    LifecycleErrorCode.POLICY_NOT_ACTIVE,
                    "The policy state does not permit evaluation.",
                    ("policy_version", "state"),
                )
            )
        try:
            checked_at = _ensure_utc(at)
            revalidated = _validate_config(record.config)
        except (TypeError, ValueError, ValidationError):
            return _evaluation_failure(_validation_error(("config", "at")))
        if _config_digest(revalidated) != record.config_digest:
            return _evaluation_failure(
                _error(
                    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID,
                    "The policy configuration changed after registration.",
                    ("config_digest",),
                )
            )
        window_error = _window_error(record, checked_at)
        if window_error is not None:
            return _evaluation_failure(window_error)
        if not isinstance(context, MitigationRequestContext):
            return _evaluation_failure(_validation_error(("context",)))
        if idempotency_token is not None:
            try:
                _validate_opaque_token(idempotency_token, "idempotency_token")
            except ValueError:
                return _evaluation_failure(_validation_error(("idempotency_token",)))

        try:
            mw1 = _build_mw1_facts(risk_assessment)
            mw2 = _build_mw2_facts(advanced_envelope)
        except (TypeError, ValueError, ValidationError):
            return _evaluation_failure(
                _error(
                    LifecycleErrorCode.VALIDATION_ERROR,
                    "Advisory signal summaries could not be built safely.",
                    ("risk_assessment", "advanced_envelope"),
                )
            )

        try:
            evaluated = evaluate_mitigation_decision(
                detection_result, context, revalidated
            )
        except Exception:
            return _evaluation_failure(
                _error(
                    LifecycleErrorCode.EVALUATION_FAILED,
                    "Advisory evaluation failed; no adverse action was produced.",
                    ("detection_result", "context"),
                )
            )
        if evaluated.advisory_only is not True:
            return _evaluation_failure(
                _error(
                    LifecycleErrorCode.EVALUATION_FAILED,
                    "The advisory engine returned a non-advisory decision.",
                    ("advisory_only",),
                )
            )

        workflow_reasons: list[LifecycleWorkflowReasonCode] = []
        decision_reasons: list[MitigationReasonCode] = list(evaluated.reason_codes)
        missing_signals: list[str] = []
        if mw1.missing:
            missing_signals.append("mw1_output_missing")
        if mw2.missing:
            missing_signals.append("mw2_envelope_missing")
        if missing_signals:
            _append_reason(decision_reasons, MitigationReasonCode.EVIDENCE_INCOMPLETE)

        uncertain_signals = mw1.uncertain or mw2.uncertain
        if uncertain_signals:
            _append_reason(decision_reasons, MitigationReasonCode.EVIDENCE_INCOMPLETE)
        _append_workflow_reason(workflow_reasons, mw1.reason)
        _append_workflow_reason(workflow_reasons, mw2.reason)
        if mw1.high_severity:
            _append_workflow_reason(
                workflow_reasons,
                LifecycleWorkflowReasonCode.MW1_HIGH_SEVERITY_ADVISORY,
            )
        if mw2.high_severity:
            _append_workflow_reason(
                workflow_reasons,
                LifecycleWorkflowReasonCode.MW2_HIGH_SEVERITY_ADVISORY,
            )
        if mw1.low_severity:
            _append_workflow_reason(
                workflow_reasons,
                LifecycleWorkflowReasonCode.MW1_LOW_SEVERITY_ADVISORY,
            )

        intended_action = evaluated.decision
        conflict_capped = False
        advisory_high = mw1.high_severity or mw2.high_severity
        advisory_low_and_certain = (
            not mw1.missing
            and not mw2.missing
            and not uncertain_signals
            and mw1.low_severity
            and not mw2.high_severity
        )
        if evaluated.decision is MitigationDecisionType.ALLOW and advisory_high:
            intended_action = MitigationDecisionType.MONITOR
            conflict_capped = True
        elif (
            evaluated.decision
            in {MitigationDecisionType.THROTTLE, MitigationDecisionType.BLOCK}
            and advisory_low_and_certain
        ):
            intended_action = MitigationDecisionType.MONITOR
            conflict_capped = True
        if conflict_capped:
            _append_reason(decision_reasons, MitigationReasonCode.SUSPICIOUS_BELOW_THRESHOLD)
            _append_workflow_reason(
                workflow_reasons,
                LifecycleWorkflowReasonCode.ADVISORY_SIGNAL_CONFLICT_MONITOR_ONLY,
            )

        _append_workflow_reason(workflow_reasons, LifecycleWorkflowReasonCode.DECISION_ISSUED)
        if not workflow_reasons:
            _append_workflow_reason(
                workflow_reasons, LifecycleWorkflowReasonCode.DECISION_ISSUED
            )

        explanation = evaluated.explanation
        if conflict_capped:
            explanation += (
                " MW1/MW2 advisory signals conflicted with the Stage 2B outcome, so "
                "the internal workflow capped the advisory action at MONITOR."
            )
        if missing_signals or uncertain_signals:
            explanation += (
                " Missing or uncertain advisory signals were retained as uncertainty "
                "and were not treated as clean traffic."
            )
        explanation += " No enforcement action was executed."

        final_decision = MitigationDecision(
            decision=intended_action,
            scope_type=evaluated.scope_type,
            scope_key_hash=evaluated.scope_key_hash,
            attribution_status=evaluated.attribution_status,
            verified_attribution=evaluated.verified_attribution,
            reason_codes=decision_reasons,
            explanation=explanation,
            policy_version=record.policy_version,
            evidence_references=list(evaluated.evidence_references),
            issued_at=evaluated.issued_at,
            expires_at=evaluated.expires_at,
            rate_limit=evaluated.rate_limit,
            rate_limit_window_seconds=evaluated.rate_limit_window_seconds,
            advisory_only=True,
        )

        policy_ref_value = _policy_ref(record.policy_version, record.config_digest)
        decision_content = {
            "domain": "apisentry.mitigation.lifecycle.decision.v1",
            "policy_version": record.policy_version,
            "policy_ref": policy_ref_value,
            "policy_state": record.state.value,
            "config_digest": record.config_digest,
            "evaluated_at": checked_at.isoformat(),
            "issued_at": _ensure_utc(final_decision.issued_at).isoformat(),
            "intended_action": intended_action.value,
            "core_action": evaluated.decision.value,
            "reason_codes": [reason.value for reason in final_decision.reason_codes],
            "workflow_reasons": [reason.value for reason in workflow_reasons],
            "risk_assessment_ref": mw1.reference,
            "advisory_detection_refs": list(mw2.signal_references),
            "scope_type": final_decision.scope_type.value,
            "scope_key_hash": final_decision.scope_key_hash,
            "actor_hash": actor.actor_hash,
            "actor_role": actor.role.value,
            "idempotency_digest": _hashed_token(idempotency_token),
            "missing_signals": missing_signals,
            "uncertain_signals": uncertain_signals,
            "dry_run": dry_run,
        }
        decision_ref = _uuid5(_DECISION_DOMAIN, decision_content)
        correlation_ref = _uuid5(
            _DECISION_DOMAIN,
            {
                "decision_ref": decision_ref,
                "policy_ref": policy_ref_value,
                "policy_version": record.policy_version,
            },
        )
        lifecycle_decision = LifecycleDecision(
            decision_ref=decision_ref,
            policy_ref=policy_ref_value,
            policy_version=record.policy_version,
            policy_state=record.state,
            risk_assessment_ref=mw1.reference,
            advisory_detection_refs=mw2.signal_references,
            decision=final_decision,
            intended_action=intended_action,
            decision_status=LifecycleDecisionStatus.ADVISORY_ISSUED,
            workflow_reason_codes=tuple(workflow_reasons),
            missing_signals=tuple(missing_signals),
            uncertain_signals=uncertain_signals,
            evaluated_at=checked_at,
            config_digest=record.config_digest,
            correlation_ref=correlation_ref,
        )

        audit_event = _build_audit_event(
            event_type=MitigationAuditEventType.DECISION_ISSUED,
            entity_type=MitigationAuditEntityType.DECISION,
            entity_identifier=decision_ref,
            policy_version=record.policy_version,
            decision_ref=decision_ref,
            actor=actor,
            occurred_at=checked_at,
            action="issue_advisory_decision",
            outcome="advisory_only",
            reason=workflow_reasons[0].value,
            details={
                "policy_version": record.policy_version,
                "policy_state": record.state.value,
                "decision_type": intended_action.value,
                "reason_code_count": len(final_decision.reason_codes),
                "workflow_reason_count": len(workflow_reasons),
                "evidence_reference_count": len(final_decision.evidence_references),
                "advisory_only": True,
                "dry_run": dry_run,
                "uncertain_signals": uncertain_signals,
            },
        )
        return PolicyEvaluationResult(
            ok=True, decision=lifecycle_decision, audit_event=audit_event
        )


__all__ = ["MitigationPolicyLifecycleService"]
