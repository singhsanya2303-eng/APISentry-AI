"""MW4-A runtime orchestration service.

Composes existing MW2 advanced advisory detection and MW1 unified risk
assessment over existing bot detection results. This module is additive and
does not modify MW1/MW2 implementation modules.

Safety boundaries:
- Advisory only; no enforcement, no policy activation, no DB writes.
- No fabricated MW1 score on invalid assessment; errors are surfaced.
- Missing/unavailable/error signal states are preserved as explicit statuses.
- No raw payloads, credentials, tokens, or tracebacks in returned structures.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.schemas.advanced_detection_signals import (
    AdvancedDetectionEnvelope,
    AdvancedSnapshots,
    SignalStatus as MW2SignalStatus,
)
from app.schemas.bot_detection import BotAnalysisResult, BotDetectionResponse
from app.schemas.mw4_runtime import (
    MW4RuntimeResult,
    MW4RuntimeTimings,
    MW4SignalNormalization,
)
from app.schemas.unified_risk_assessment import (
    SignalStatus as MW1SignalStatus,
    UnifiedRiskAssessment,
)
from app.services.advanced_detection.advisory_orchestrator import (
    build_advisory_envelope,
)
from app.services.unified_risk_assessment_service import (
    assess_risk,
    from_bot_detection_response,
)

logger = logging.getLogger("apisentry.services.mw4_runtime")

_MW1_SAFE_ERROR = "MW1 unified risk assessment could not produce a valid assessment."


def _safe_subject_ref(result: BotAnalysisResult, index: int) -> str:
    # Use index-based opaque ref; never include raw client IP/actor identifiers.
    return f"bot-result:{index}"


def _bot_result_to_mw2_snapshots(
    detection: BotDetectionResponse,
    result: BotAnalysisResult,
    index: int,
) -> tuple[dict[str, Any], list[MW4SignalNormalization]]:
    """Build MW2 AdvancedSnapshots dict from unambiguous BotAnalysisResult fields.

    Only fields that can be mapped unambiguously are populated. All others remain
    missing so MW2 reports them explicitly as MISSING (not clean).
    """
    norms: list[MW4SignalNormalization] = []
    subject_ref = _safe_subject_ref(result, index)

    # Behavior snapshot: map directly available aggregate counts/scores.
    auth_failures = 0
    for factor in result.score_factors:
        if factor.factor_name == "authentication_failures":
            auth_failures = max(auth_failures, int(factor.evidence_count or 0))

    behavior = {
        "status": MW2SignalStatus.AVAILABLE.value,
        "subject_ref": subject_ref,
        "source_module": "app.services.bot_detection_service",
        "source_function": "analyze_traffic_for_bot_detection",
        "request_count": int(result.request_count or 0),
        "auth_failure_count": int(auth_failures),
        "bot_risk_score": float(result.bot_risk_score),
        "classification": str(result.classification.value),
        "limits": {"truncated": bool(detection.limits.truncated)},
        "evidence_refs": [str(ref.request_id) for ref in result.evidence_references[:25]],
    }
    norms.append(
        MW4SignalNormalization(
            signal="mw2.behavior",
            status=MW2SignalStatus.AVAILABLE.value,
            source="bot_detection_result",
            note="Mapped from BotAnalysisResult aggregate fields; unobserved behavior fields remain defaults.",
        )
    )

    # Credential snapshot: only auth failure count is unambiguous.
    credential = {
        "status": MW2SignalStatus.AVAILABLE.value,
        "subject_ref": subject_ref,
        "source_module": "app.services.bot_detection_service",
        "source_function": "analyze_traffic_for_bot_detection",
        "failure_count": int(auth_failures),
        "limits": {"truncated": bool(detection.limits.truncated)},
        "evidence_refs": [str(ref.request_id) for ref in result.evidence_references[:25]],
    }
    norms.append(
        MW4SignalNormalization(
            signal="mw2.credential",
            status=MW2SignalStatus.AVAILABLE.value,
            source="bot_detection_result.authentication_failures",
            note="Only auth failure count mapped; other credential dimensions unavailable in bot detection response.",
        )
    )

    # API abuse snapshot: request count is unambiguous; other fields unavailable.
    api_abuse = {
        "status": MW2SignalStatus.AVAILABLE.value,
        "subject_ref": subject_ref,
        "source_module": "app.services.bot_detection_service",
        "source_function": "analyze_traffic_for_bot_detection",
        "request_count": int(result.request_count or 0),
        "limits": {"truncated": bool(detection.limits.truncated)},
        "evidence_refs": [str(ref.request_id) for ref in result.evidence_references[:25]],
    }
    norms.append(
        MW4SignalNormalization(
            signal="mw2.api_abuse",
            status=MW2SignalStatus.AVAILABLE.value,
            source="bot_detection_result.request_count",
            note="Only request_count mapped; endpoint/method/error/burst details not present in BotAnalysisResult.",
        )
    )

    # Payload, attribution, trend: no unambiguous mapping from BotDetectionResponse.
    for name, reason in (
        ("mw2.payload", "No payload classifier labels available in bot detection response."),
        ("mw2.attribution", "Attribution quality snapshot not provided by bot detection response."),
        ("mw2.trend", "Trend/baseline window snapshot not provided by bot detection response."),
    ):
        norms.append(
            MW4SignalNormalization(
                signal=name,
                status=MW2SignalStatus.MISSING.value,
                source="not_mapped",
                note=reason,
            )
        )

    snapshots = {
        "subject_ref": subject_ref,
        "behavior": behavior,
        "credential": credential,
        "api_abuse": api_abuse,
        "payload": None,
        "attribution": None,
        "trend": None,
    }
    return snapshots, norms


def _build_mw1_input(
    detection: BotDetectionResponse,
    result: BotAnalysisResult,
    index: int,
) -> tuple[dict[str, Any], list[MW4SignalNormalization]]:
    """Build MW1 input dict using existing adapters where unambiguous."""
    norms: list[MW4SignalNormalization] = []
    subject_ref = _safe_subject_ref(result, index)

    # Use the existing adapter for bot_detection signal from full response.
    # For per-result assessment, provide a single-result response-shaped view so
    # the adapter attributes to this result.
    single_view = detection.model_copy(
        update={
            "results": [result],
            "total_clients": 1,
            "summary": detection.summary.model_copy(
                update={
                    "total_clients": 1,
                    "suspicious_automation_candidates": (
                        1
                        if result.classification.value == "automation_suspicious"
                        else 0
                    ),
                }
            ),
        }
    )
    bot_signal = from_bot_detection_response(single_view)
    norms.append(
        MW4SignalNormalization(
            signal="mw1.bot_detection",
            status=str(bot_signal.get("status", MW1SignalStatus.AVAILABLE.value)),
            source="unified_risk_assessment_service.from_bot_detection_response",
            note="Mapped via existing MW1 adapter from single-result bot detection view.",
        )
    )

    # Other MW1 signals are not unambiguously available from BotDetectionResponse.
    missing_signals = {
        "behavior_risk": "No separate BehaviorAnalysisResponse provided to runtime composition.",
        "traffic_anomaly": "No separate RateAnomalyDetectionResponse provided to runtime composition.",
        "payload_classifier": "No payload classifier response provided to runtime composition.",
        "request_pattern": "No request pattern novelty flags provided as separate MW1 signal.",
        "mitigation_context": "Mitigation context not included in MW1 input for this advisory composition.",
    }
    for name, note in missing_signals.items():
        norms.append(
            MW4SignalNormalization(
                signal=f"mw1.{name}",
                status=MW1SignalStatus.MISSING.value,
                source="not_mapped",
                note=note,
            )
        )

    mw1_input = {
        "subject_ref": subject_ref,
        "bot_detection": bot_signal,
        "behavior_risk": None,
        "traffic_anomaly": None,
        "payload_classifier": None,
        "request_pattern": None,
        "mitigation_context": None,
    }
    return mw1_input, norms


def _assess_mw1_safe(mw1_input: dict[str, Any]) -> tuple[UnifiedRiskAssessment | None, str, str | None]:
    try:
        assessment = assess_risk(mw1_input)
        return assessment, "assessed", None
    except Exception as exc:
        logger.warning("MW1 runtime assessment failed: %s", type(exc).__name__)
        return None, "error", _MW1_SAFE_ERROR


def orchestrate_mw4_runtime(
    detection: BotDetectionResponse,
) -> tuple[list[MW4RuntimeResult], MW4RuntimeTimings]:
    """Run MW2 then MW1 for each bot detection result. Advisory-only.

    Returns per-result runtime compositions and lightweight timings.
    Never raises raw detector exceptions; failures are represented in-result.
    """
    started = time.perf_counter()
    total_mw2_ms = 0.0
    total_mw1_ms = 0.0
    results: list[MW4RuntimeResult] = []

    for index, item in enumerate(detection.results):
        subject_ref = _safe_subject_ref(item, index)
        norms: list[MW4SignalNormalization] = []

        # MW2
        mw2_started = time.perf_counter()
        try:
            snapshots, mw2_norms = _bot_result_to_mw2_snapshots(detection, item, index)
            norms.extend(mw2_norms)
            envelope = build_advisory_envelope(snapshots)
        except Exception as exc:
            logger.warning("MW2 runtime envelope failed: %s", type(exc).__name__)
            norms.append(
                MW4SignalNormalization(
                    signal="mw2.envelope",
                    status="ERROR",
                    source="advanced_detection.advisory_orchestrator.build_advisory_envelope",
                    note="MW2 envelope build failed; no fabricated envelope returned.",
                    error_code=type(exc).__name__,
                )
            )
            try:
                envelope = AdvancedDetectionEnvelope(subject_ref=subject_ref, signals=[])
            except Exception:
                # Last-resort schema-safe empty envelope without subject_ref
                envelope = AdvancedDetectionEnvelope(signals=[])
        mw2_ms = (time.perf_counter() - mw2_started) * 1000.0
        total_mw2_ms += mw2_ms

        # MW1
        mw1_started = time.perf_counter()
        mw1_input, mw1_norms = _build_mw1_input(detection, item, index)
        norms.extend(mw1_norms)
        assessment, mw1_status, mw1_error = _assess_mw1_safe(mw1_input)
        mw1_ms = (time.perf_counter() - mw1_started) * 1000.0
        total_mw1_ms += mw1_ms

        results.append(
            MW4RuntimeResult(
                result_index=index,
                subject_ref=subject_ref,
                mw2_advanced_detection=envelope,
                mw1_unified_assessment=assessment,
                mw1_status=mw1_status,
                mw1_error=mw1_error,
                signal_normalization=norms,
                advisory_only=True,
            )
        )

    total_ms = (time.perf_counter() - started) * 1000.0
    timings = MW4RuntimeTimings(
        mw2_ms=round(total_mw2_ms, 3),
        mw1_ms=round(total_mw1_ms, 3),
        total_ms=round(total_ms, 3),
    )
    return results, timings


__all__ = ["orchestrate_mw4_runtime"]
