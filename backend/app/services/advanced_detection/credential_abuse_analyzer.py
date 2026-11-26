"""
Aggregated authentication-abuse review analyzer — MW2 (advisory only).

Consumes ONLY aggregated counts. No username, password, token, cookie, header or
request-body value is accepted. Account cardinality is supplied as a count of
caller-side hashed keys, never as an identifier.

WINDOW DEFINITION
  Caller-supplied through ``CredentialSnapshot.window``; no clock value is used.

THRESHOLDS (advisory review only, bounded to 15 points)
  grouped auth failures ............... failure_count >= 5
  cross-account spraying shape ........ distinct_account_keys >= 3 with failures >= 5
  success after failure ............... success_after_failure_count >= 1
  shared-IP ambiguity ................. reported as coverage context, never escalated
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    CredentialSnapshot,
)
from app.schemas.unified_risk_assessment import ThreatCategory
from app.services.advanced_detection.common_signal_contract import (
    active_result,
    inactive_result,
)
from app.services.advanced_detection.evidence_catalog import (
    bounded_refs,
    dedupe_key,
)

SOURCE_MODULE = "app.services.advanced_detection.credential_abuse_analyzer"
SOURCE_FUNCTION = "analyze_credential_abuse"

AUTH_FAILURE_THRESHOLD = 5
SPRAY_ACCOUNT_THRESHOLD = 3
POST_FAILURE_SUCCESS_MIN = 1
POINTS_GROUPED_FAILURES = 5.0
POINTS_CROSS_ACCOUNT = 5.0
POINTS_POST_FAILURE_SUCCESS = 3.0


def analyze_credential_abuse(snapshot: CredentialSnapshot | None):
    """Return a bounded authentication-review signal from aggregate counts."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.CREDENTIAL_ABUSE,
            detection_name="Aggregated authentication abuse review",
            threat_category=ThreatCategory.BEHAVIORAL,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
        )

    reasons: list[AdvancedReason] = []
    indicator_codes: list[str] = []
    raw_points = 0.0

    if snapshot.failure_count >= AUTH_FAILURE_THRESHOLD:
        indicator_codes.append("GROUPED_AUTH_FAILURES")
        raw_points += POINTS_GROUPED_FAILURES
        reasons.append(
            AdvancedReason(
                code="GROUPED_AUTH_FAILURES",
                message=(
                    f"{snapshot.failure_count} aggregated authentication failure(s) were "
                    "supplied across the window; this is a review signal, not a confirmed "
                    "compromise."
                ),
                evidence_count=snapshot.failure_count,
                score_contribution=POINTS_GROUPED_FAILURES,
            )
        )

    if (
        snapshot.distinct_account_keys >= SPRAY_ACCOUNT_THRESHOLD
        and snapshot.failure_count >= AUTH_FAILURE_THRESHOLD
    ):
        indicator_codes.append("CROSS_ACCOUNT_FAILURE_SHAPE")
        raw_points += POINTS_CROSS_ACCOUNT
        reasons.append(
            AdvancedReason(
                code="CROSS_ACCOUNT_FAILURE_SHAPE",
                message=(
                    "Failures span multiple hashed account keys; only key counts are "
                    "represented and no account identifier is emitted."
                ),
                evidence_count=snapshot.distinct_account_keys,
                score_contribution=POINTS_CROSS_ACCOUNT,
            )
        )

    if snapshot.success_after_failure_count >= POST_FAILURE_SUCCESS_MIN:
        indicator_codes.append("SUCCESS_AFTER_FAILURE")
        raw_points += POINTS_POST_FAILURE_SUCCESS
        reasons.append(
            AdvancedReason(
                code="SUCCESS_AFTER_FAILURE",
                message=(
                    "An aggregated success-after-failure transition was supplied; this is "
                    "a weak review indicator and never establishes intent on its own."
                ),
                evidence_count=snapshot.success_after_failure_count,
                score_contribution=POINTS_POST_FAILURE_SUCCESS,
            )
        )

    coverage_notes: list[str] = []
    if snapshot.shared_ip_failure_groups > 0:
        coverage_notes.append(
            "Shared-IP failure groups were reported; cross-actor evidence was not "
            "used against unrelated actors."
        )
    if len(indicator_codes) == 1 and indicator_codes[0] == "SUCCESS_AFTER_FAILURE":
        coverage_notes.append(
            "Only one weak indicator is present; no suspicious conclusion is inferred."
        )
    if snapshot.limits.truncated:
        coverage_notes.append("Authentication snapshot was truncated.")

    return active_result(
        signal=AdvancedSignalName.CREDENTIAL_ABUSE,
        detection_name="Aggregated authentication abuse review",
        threat_category=ThreatCategory.BEHAVIORAL,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        observed_indicator=", ".join(indicator_codes) or "no_auth_abuse_indicator",
        explanation=(
            "Authentication review is derived only from supplied aggregate counts. "
            "No credential, account value, header or body was inspected."
        ),
        reasons=reasons,
        raw_points=raw_points,
        evidence_refs=bounded_refs(snapshot.evidence_refs),
        dedupe_key=dedupe_key(
            f"credential:{snapshot.subject_ref or 'anonymous'}:{snapshot.failure_count}"
        ),
        coverage_note=" ".join(coverage_notes) or None,
    )


__all__ = ["analyze_credential_abuse"]
