"""
Advisory Unified Risk Assessment Service — Master Workstream 1.

Consumes existing detector outputs as snapshots and produces one explainable
0-100 assessment. This service:

  - does not execute detectors;
  - does not read traffic or any database;
  - does not persist policies, decisions or audits;
  - does not block, throttle or mitigate;
  - does not reinterpret the frozen payload classifier decision margin.

All signal failures are contained per signal. A failed detector contributes zero
points and an explicit data-quality reason, never a silent "safe" result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ValidationError

from app.detection.risk_scorer import get_risk_level
from app.schemas.behavior import RiskLevel
from app.schemas.bot_detection import BotClassification
from app.schemas.rate_anomaly import RateAnomalyVerdict
from app.schemas.unified_risk_assessment import (
    BehaviorRiskSignalInput,
    BotDetectionSignalInput,
    CoverageSummary,
    MitigationContextSignalInput,
    PayloadClassifierSignalInput,
    RequestPatternSignalInput,
    RiskContribution,
    RiskReason,
    SignalErrorCode,
    SignalInputBase,
    SignalName,
    SignalStatus,
    SignalStatusRecord,
    ThreatCategory,
    TrafficAnomalySignalInput,
    UnifiedRiskAssessment,
    UnifiedRiskInput,
)

SIGNAL_MODELS: dict[SignalName, type[SignalInputBase]] = {
    SignalName.BOT_DETECTION: BotDetectionSignalInput,
    SignalName.BEHAVIOR_RISK: BehaviorRiskSignalInput,
    SignalName.TRAFFIC_ANOMALY: TrafficAnomalySignalInput,
    SignalName.PAYLOAD_CLASSIFIER: PayloadClassifierSignalInput,
    SignalName.REQUEST_PATTERN: RequestPatternSignalInput,
    SignalName.MITIGATION_CONTEXT: MitigationContextSignalInput,
}

SIGNAL_SOURCES: dict[SignalName, tuple[str, str]] = {
    SignalName.BOT_DETECTION: (
        "app.services.bot_detection_service",
        "analyze_traffic_for_bot_detection",
    ),
    SignalName.BEHAVIOR_RISK: (
        "app.detection.risk_scorer",
        "RiskScorer.score_features",
    ),
    SignalName.TRAFFIC_ANOMALY: (
        "app.detection.rate_anomaly_detector",
        "RateAnomalyDetector.analyze_events",
    ),
    SignalName.PAYLOAD_CLASSIFIER: (
        "app.services.http_payload_classifier_service",
        "predict_payloads",
    ),
    SignalName.REQUEST_PATTERN: (
        "app.services.request_pattern_anomaly_service",
        "analyze_http_method_frequency",
    ),
    SignalName.MITIGATION_CONTEXT: (
        "app.services.mitigation_policy_service",
        "evaluate_mitigation_decision",
    ),
}

SIGNAL_CATEGORIES: dict[SignalName, ThreatCategory] = {
    SignalName.BOT_DETECTION: ThreatCategory.BOT_AUTOMATION,
    SignalName.BEHAVIOR_RISK: ThreatCategory.BEHAVIORAL,
    SignalName.TRAFFIC_ANOMALY: ThreatCategory.TRAFFIC_ANOMALY,
    SignalName.PAYLOAD_CLASSIFIER: ThreatCategory.PAYLOAD,
    SignalName.REQUEST_PATTERN: ThreatCategory.REQUEST_PATTERN,
    SignalName.MITIGATION_CONTEXT: ThreatCategory.MITIGATION_CONTEXT,
}

DISPLAY_NAMES: dict[SignalName, str] = {
    SignalName.BOT_DETECTION: "Bot detection",
    SignalName.BEHAVIOR_RISK: "Behavioral risk",
    SignalName.TRAFFIC_ANOMALY: "Traffic anomaly",
    SignalName.PAYLOAD_CLASSIFIER: "Payload classifier",
    SignalName.REQUEST_PATTERN: "Request pattern",
    SignalName.MITIGATION_CONTEXT: "Mitigation context",
}

# Documented caps from MW1 risk_design.txt. They sum to 100 so ordinary
# assessments need no clamping; clamping remains a defensive backstop.
CAPS: dict[SignalName, float] = {
    SignalName.BOT_DETECTION: 30.0,
    SignalName.BEHAVIOR_RISK: 30.0,
    SignalName.TRAFFIC_ANOMALY: 25.0,
    SignalName.PAYLOAD_CLASSIFIER: 10.0,
    SignalName.REQUEST_PATTERN: 5.0,
    SignalName.MITIGATION_CONTEXT: 0.0,
}

STATUS_MESSAGES: dict[SignalStatus, str] = {
    SignalStatus.MISSING: "was not supplied; zero points were assigned",
    SignalStatus.UNAVAILABLE: "was reported unavailable; zero points were assigned",
    SignalStatus.ERROR: "reported a detector error; zero points were assigned",
    SignalStatus.INVALID: "failed signal validation; zero points were assigned",
}


@dataclass(frozen=True)
class _SignalResult:
    points: float
    rationale: str
    evidence_refs: list[str]
    source_confidence: float | None = None


def _read(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _normalise_error_code(signal: BaseModel) -> BaseModel:
    if signal.status == SignalStatus.ERROR and signal.error_code is None:
        signal.error_code = SignalErrorCode.DETECTOR_EXCEPTION
    elif signal.status == SignalStatus.INVALID and signal.error_code is None:
        signal.error_code = SignalErrorCode.INVALID_OUTPUT
    return signal


def _parse_signal(
    name: SignalName, raw: Any, model_type: type[BaseModel]
) -> BaseModel:
    if raw is None:
        return model_type(status=SignalStatus.MISSING)
    if isinstance(raw, BaseModel):
        data = raw.model_dump(mode="python")
    elif isinstance(raw, Mapping):
        data = dict(raw)
    else:
        return model_type(
            status=SignalStatus.INVALID,
            error_code=SignalErrorCode.INVALID_OUTPUT,
        )
    try:
        return _normalise_error_code(model_type.model_validate(data))
    except ValidationError:
        return model_type(
            status=SignalStatus.INVALID,
            error_code=SignalErrorCode.INVALID_OUTPUT,
        )


def _status_note(name: SignalName, signal: BaseModel) -> str:
    display = DISPLAY_NAMES[name]
    if signal.status == SignalStatus.AVAILABLE:
        return f"{display} output was supplied and normalized."
    code = getattr(signal, "error_code", None)
    suffix = f" ({code.value})" if code is not None else ""
    return f"{display} {STATUS_MESSAGES[signal.status]}{suffix}."


def _inactive_result(name: SignalName, signal: BaseModel) -> _SignalResult:
    return _SignalResult(
        points=0.0,
        rationale=(
            f"{DISPLAY_NAMES[name]} status is {signal.status.value}; no points were "
            "assigned and the result is not treated as a clean signal."
        ),
        evidence_refs=[],
        source_confidence=None,
    )


def _add_inactive_reason(
    name: SignalName, signal: BaseModel, reasons: list[RiskReason]
) -> None:
    code = getattr(signal, "error_code", None)
    code_text = f" ({code.value})" if code is not None else ""
    reason_code = f"{name.value.upper()}_{signal.status.value.upper()}"
    if code is not None and signal.status in {
        SignalStatus.ERROR,
        SignalStatus.INVALID,
    }:
        reason_code += f"_{code.value.upper()}"
    reasons.append(
        RiskReason(
            code=reason_code,
            message=(
                f"{DISPLAY_NAMES[name]} {STATUS_MESSAGES[signal.status]}"
                f"{code_text}."
            ),
            category=ThreatCategory.DATA_QUALITY,
            signal=name,
        )
    )


def _add_conflict(
    name: SignalName,
    code: str,
    message: str,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> None:
    reasons.append(
        RiskReason(
            code=code,
            message=message,
            category=ThreatCategory.DATA_QUALITY,
            signal=name,
        )
    )
    uncertainty_notes.append("Conflicting detector fields were retained as data-quality reasons.")


def _bot_result(
    signal: BotDetectionSignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.BOT_DETECTION, signal)

    score = float(signal.bot_risk_score or 0.0)
    points = round(min(CAPS[SignalName.BOT_DETECTION], score * 0.30), 1)
    rationale = (
        f"Existing bot risk score {score:.1f}/100 preserved on its native scale and "
        f"capped at {CAPS[SignalName.BOT_DETECTION]:.1f} points to prevent one "
        "detector from dominating."
    )

    if (
        signal.classification == BotClassification.AUTOMATION_SUSPICIOUS
        and score < 50.0
    ):
        _add_conflict(
            SignalName.BOT_DETECTION,
            "BOT_SCORE_CLASSIFICATION_CONFLICT",
            "Bot classification is suspicious while the numeric bot score is below the existing 50-point threshold; the numeric score was retained.",
            reasons,
            uncertainty_notes,
        )

    if signal.limits_truncated:
        uncertainty_notes.append("Bot detection reported truncated results; completeness is reduced.")

    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=list(signal.evidence_references or []),
        source_confidence=None,
    )


def _behavior_result(
    signal: BehaviorRiskSignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.BEHAVIOR_RISK, signal)

    score = float(signal.risk_score or 0.0)
    points = round(min(CAPS[SignalName.BEHAVIOR_RISK], score * 0.30), 1)
    expected = get_risk_level(score)
    if signal.risk_level is not None and signal.risk_level != expected:
        _add_conflict(
            SignalName.BEHAVIOR_RISK,
            "BEHAVIOR_SCORE_LEVEL_CONFLICT",
            "Behavioral risk level disagrees with the numeric score; the numeric score from the deterministic scorer was retained.",
            reasons,
            uncertainty_notes,
        )

    factors = [str(f) for f in (signal.factor_names or []) if str(f)]
    rationale = (
        f"Existing deterministic behavioral risk score {score:.1f}/100 preserved "
        f"and capped at {CAPS[SignalName.BEHAVIOR_RISK]:.1f} points."
    )
    if factors:
        rationale += " Source factors: " + ", ".join(factors[:5]) + "."

    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=[],
        source_confidence=None,
    )


def _traffic_result(
    signal: TrafficAnomalySignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.TRAFFIC_ANOMALY, signal)

    verdict = _enum_value(signal.verdict)
    count = signal.anomalous_request_count
    points = 0.0

    if verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY.value:
        if count == 0:
            _add_conflict(
                SignalName.TRAFFIC_ANOMALY,
                "TRAFFIC_VERDICT_COUNT_CONFLICT",
                "Traffic verdict is suspicious but reports zero anomalous requests; no points were assigned.",
                reasons,
                uncertainty_notes,
            )
        else:
            points = CAPS[SignalName.TRAFFIC_ANOMALY]
    elif verdict == RateAnomalyVerdict.NO_ANOMALY.value and count is not None and count > 0:
        _add_conflict(
            SignalName.TRAFFIC_ANOMALY,
            "TRAFFIC_VERDICT_COUNT_CONFLICT",
            "Traffic verdict is no_anomaly but reports anomalous requests; no points were assigned.",
            reasons,
            uncertainty_notes,
        )

    if verdict == RateAnomalyVerdict.INSUFFICIENT_EVIDENCE.value:
        uncertainty_notes.append(
            "Traffic anomaly detector reported insufficient evidence; this is not a clean result."
        )
    if signal.truncated:
        uncertainty_notes.append("Traffic anomaly results were marked truncated; completeness is reduced.")

    rationale = (
        f"Existing rate-anomaly verdict '{verdict}' mapped to {points:.1f} points "
        f"(cap {CAPS[SignalName.TRAFFIC_ANOMALY]:.1f}); source confidence is "
        "provenance only and was not multiplied into the score."
    )
    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=[],
        source_confidence=signal.source_confidence,
    )


def _payload_result(
    signal: PayloadClassifierSignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.PAYLOAD_CLASSIFIER, signal)

    results = signal.results or []
    anomalous = sum(1 for item in results if item.label == "anomalous")
    low_margin = sum(1 for item in results if item.low_margin)
    points = CAPS[SignalName.PAYLOAD_CLASSIFIER] if anomalous else 0.0

    if low_margin:
        reasons.append(
            RiskReason(
                code="PAYLOAD_LOW_MARGIN_DESCRIPTIVE",
                message=f"{low_margin} low-margin flag(s) are descriptive only and did not alter the contribution.",
                category=ThreatCategory.PAYLOAD,
                signal=SignalName.PAYLOAD_CLASSIFIER,
            )
        )

    rationale = (
        f"{anomalous} categorical anomalous label(s) from the frozen research "
        f"classifier mapped to {points:.1f} points. The uncalibrated decision "
        "margin, low-margin flag and payload echo were excluded from scoring."
    )
    if signal.artifact_sha256:
        rationale += f" Artifact prefix: {signal.artifact_sha256[:12]}."
    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=[],
        source_confidence=None,
    )


def _request_pattern_result(
    signal: RequestPatternSignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.REQUEST_PATTERN, signal)

    flags = [str(f) for f in (signal.flags or []) if str(f)]
    points = CAPS[SignalName.REQUEST_PATTERN] if flags else 0.0
    rationale = (
        f"{len(flags)} review-only novelty flag(s) present; capped at "
        f"{CAPS[SignalName.REQUEST_PATTERN]:.1f} point(s) and never used alone "
        "to set severity."
    )
    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=[],
        source_confidence=None,
    )


def _mitigation_result(
    signal: MitigationContextSignalInput,
    reasons: list[RiskReason],
    uncertainty_notes: list[str],
) -> _SignalResult:
    if signal.status != SignalStatus.AVAILABLE:
        return _inactive_result(SignalName.MITIGATION_CONTEXT, signal)

    decision = _enum_value(signal.decision) or "unknown"
    points = 0.0
    if decision in {"throttle", "block"}:
        reasons.append(
            RiskReason(
                code="MITIGATION_ADVISORY_RECOMMENDATION_ONLY",
                message=f"The {decision} recommendation is advisory context only and was not executed or persisted.",
                category=ThreatCategory.MITIGATION_CONTEXT,
                signal=SignalName.MITIGATION_CONTEXT,
            )
        )
    rationale = (
        f"Advisory policy decision '{decision}' recorded as context with zero points "
        "because it is derived from bot output and the persisting integration is out of scope."
    )
    if signal.policy_version:
        rationale += f" Policy version: {signal.policy_version}."
    return _SignalResult(
        points=points,
        rationale=rationale,
        evidence_refs=[],
        source_confidence=None,
    )


HANDLERS = {
    SignalName.BOT_DETECTION: _bot_result,
    SignalName.BEHAVIOR_RISK: _behavior_result,
    SignalName.TRAFFIC_ANOMALY: _traffic_result,
    SignalName.PAYLOAD_CLASSIFIER: _payload_result,
    SignalName.REQUEST_PATTERN: _request_pattern_result,
    SignalName.MITIGATION_CONTEXT: _mitigation_result,
}


def assess_risk(data: UnifiedRiskInput | Mapping[str, Any]) -> UnifiedRiskAssessment:
    """Build an advisory unified assessment from detector output snapshots."""

    if isinstance(data, Mapping):
        data = UnifiedRiskInput.model_validate(dict(data))

    parsed: dict[SignalName, BaseModel] = {
        name: _parse_signal(name, getattr(data, name.value), model_type)
        for name, model_type in SIGNAL_MODELS.items()
    }

    reasons: list[RiskReason] = []
    uncertainty_notes: list[str] = []
    contributions: list[RiskContribution] = []
    signal_statuses: list[SignalStatusRecord] = []

    for name, signal in parsed.items():
        module, function = SIGNAL_SOURCES[name]
        signal_statuses.append(
            SignalStatusRecord(
                signal=name,
                status=signal.status,
                error_code=getattr(signal, "error_code", None),
                source_module=module,
                source_function=function,
                note=_status_note(name, signal),
            )
        )
        if signal.status != SignalStatus.AVAILABLE:
            _add_inactive_reason(name, signal, reasons)

        result = HANDLERS[name](signal, reasons, uncertainty_notes)
        contributions.append(
            RiskContribution(
                signal=name,
                category=SIGNAL_CATEGORIES[name],
                source_module=module,
                source_function=function,
                points=result.points,
                status=signal.status,
                rationale=result.rationale,
                evidence_refs=result.evidence_refs,
                source_confidence=result.source_confidence,
            )
        )
        if result.points > 0:
            reasons.append(
                RiskReason(
                    code=f"{name.value.upper()}_CONTRIBUTION",
                    message=result.rationale[:300],
                    category=SIGNAL_CATEGORIES[name],
                    signal=name,
                )
            )

    raw_total = round(sum(item.points for item in contributions), 1)
    clamped_total = min(100.0, max(0.0, raw_total))
    final_score = round(clamped_total, 1)
    severity: RiskLevel = get_risk_level(final_score)

    if not any(item.points > 0 for item in contributions):
        reasons.append(
            RiskReason(
                code="NO_POINTS_CONTRIBUTED",
                message="No supplied signal contributed points; this is absence of reported risk indicators, not proof of safety.",
                category=ThreatCategory.DATA_QUALITY,
                signal=SignalName.REQUEST_PATTERN,
            )
        )

    counts = {status.value: 0 for status in SignalStatus}
    for signal in parsed.values():
        counts[signal.status.value] += 1
    expected = len(parsed)
    coverage = CoverageSummary(
        signals_expected=expected,
        signals_available=counts[SignalStatus.AVAILABLE.value],
        signals_missing=counts[SignalStatus.MISSING.value],
        signals_unavailable=counts[SignalStatus.UNAVAILABLE.value],
        signals_error=counts[SignalStatus.ERROR.value],
        signals_invalid=counts[SignalStatus.INVALID.value],
        coverage_ratio=round(counts[SignalStatus.AVAILABLE.value] / expected, 4),
    )

    if counts[SignalStatus.AVAILABLE.value] < expected:
        unavailable_total = expected - counts[SignalStatus.AVAILABLE.value]
        uncertainty_notes.insert(
            0,
            f"{unavailable_total} of {expected} signals were not available; the score reflects only supplied signals.",
        )
    if not uncertainty_notes:
        uncertainty_notes.append(
            "All six signals were available; no truncation, conflict or missing-signal uncertainty was reported."
        )

    category_set = {item.category for item in contributions}
    if any(item.category == ThreatCategory.DATA_QUALITY for item in reasons):
        category_set.add(ThreatCategory.DATA_QUALITY)
    categories = sorted(category_set, key=lambda item: item.value)

    return UnifiedRiskAssessment(
        risk_score=final_score,
        severity=severity,
        raw_contribution_total=raw_total,
        clamp_applied=round(raw_total, 1) != final_score,
        categories=categories,
        contributions=contributions,
        reasons=reasons,
        signal_statuses=signal_statuses,
        coverage=coverage,
        uncertainty_notes=uncertainty_notes,
        limits=[
            "Internal source-level assessment only; MW1 adds no HTTP endpoint or frontend wiring.",
            "This service consumes detector snapshots; it does not execute detectors, read traffic from the database, or contact external services.",
            "Payload classifier decision margins, low-margin flags and payload echoes are excluded from scoring.",
            "Original detector windows differ; this score does not claim equivalent time alignment.",
        ],
    )


# ---------------------------------------------------------------------------
# Adapters from existing response shapes
# ---------------------------------------------------------------------------


def from_bot_detection_response(response: Any) -> dict[str, Any]:
    """Extract an opaque, normalized bot signal from an existing response."""

    results = _as_list(_read(response, "results", []))
    scored = [
        float(_read(item, "bot_risk_score", 0.0))
        for item in results
        if _read(item, "bot_risk_score", None) is not None
    ]
    top = None
    if scored:
        top_index = scored.index(max(scored))
        top = results[top_index]

    references: list[str] = []
    for item in results:
        for reference in _as_list(_read(item, "evidence_references", [])):
            request_id = _read(reference, "request_id", None)
            if isinstance(request_id, str):
                references.append(request_id)

    summary = _read(response, "summary", {})
    limits = _read(response, "limits", {})
    return {
        "status": SignalStatus.AVAILABLE.value,
        "bot_risk_score": max(scored) if scored else 0.0,
        "classification": _enum_value(_read(top, "classification", None)),
        "suspicious_automation_candidates": int(
            _read(summary, "suspicious_automation_candidates", 0) or 0
        ),
        "evidence_references": references[:25],
        "limits_truncated": bool(_read(limits, "truncated", False)),
    }


def from_behavior_analysis_response(response: Any) -> dict[str, Any]:
    """Extract the highest bounded behavioral score from an existing response."""

    results = _as_list(_read(response, "results", []))
    scored = [
        (float(_read(item, "risk_score", 0.0)), item)
        for item in results
        if _read(item, "risk_score", None) is not None
    ]
    if not scored:
        return {
            "status": SignalStatus.AVAILABLE.value,
            "risk_score": 0.0,
            "risk_level": RiskLevel.LOW.value,
            "factor_names": [],
        }
    score, top = max(scored, key=lambda pair: pair[0])
    factors = _as_list(_read(top, "factors", []))
    return {
        "status": SignalStatus.AVAILABLE.value,
        "risk_score": score,
        "risk_level": _enum_value(_read(top, "risk_level", None)),
        "factor_names": [
            str(_read(factor, "factor_name", ""))
            for factor in factors
            if _read(factor, "factor_name", None)
        ][:25],
    }


def from_rate_anomaly_result(response: Any) -> dict[str, Any]:
    """Extract rate verdict/count while preserving confidence as provenance only."""

    evidences = _as_list(_read(response, "evidences", []))
    confidences = [
        float(_read(item, "confidence_score", 0.0))
        for item in evidences
        if _read(item, "confidence_score", None) is not None
    ]
    windows = [
        float(_read(item, "time_window_seconds", 0.0))
        for item in evidences
        if _read(item, "time_window_seconds", None) is not None
    ]
    return {
        "status": SignalStatus.AVAILABLE.value,
        "verdict": _enum_value(_read(response, "verdict", None)),
        "anomalous_request_count": int(
            _read(response, "anomalous_request_count", 0) or 0
        ),
        "source_confidence": max(confidences) if confidences else None,
        "window_seconds": max(windows) if windows else None,
        "truncated": False,
    }


def from_payload_classifier_response(response: Any) -> dict[str, Any]:
    """Extract categorical labels only; never forward decision margins."""

    results = _as_list(_read(response, "results", []))
    normalized = [
        {
            "index": int(_read(item, "index", position)),
            "label": _enum_value(_read(item, "label", None)),
            "low_margin": bool(_read(item, "low_margin", False)),
        }
        for position, item in enumerate(results)
    ]
    return {
        "status": SignalStatus.AVAILABLE.value,
        "results": normalized,
        "artifact_sha256": _read(response, "artifact_sha256", None),
    }


def from_mitigation_decision(decision: Any) -> dict[str, Any]:
    """Extract pure advisory context from an existing policy decision."""

    return {
        "status": SignalStatus.AVAILABLE.value,
        "decision": _enum_value(_read(decision, "decision", None)),
        "policy_version": _read(decision, "policy_version", None),
        "advisory_only": True,
    }


__all__ = [
    "assess_risk",
    "from_behavior_analysis_response",
    "from_bot_detection_response",
    "from_mitigation_decision",
    "from_payload_classifier_response",
    "from_rate_anomaly_result",
]
