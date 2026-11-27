import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ACTION_FORM,
  DEFAULT_AUDIT_FILTERS,
  DEFAULT_DECISION_FILTERS,
  DEFAULT_DRY_RUN_FORM,
  DEFAULT_POLICY_FORM,
  buildAuditParams,
  buildCreatePolicyPayload,
  buildDecisionParams,
  buildDryRunPayload,
  buildPolicyActionPayload,
  canManagePolicies,
  canUseMitigationDashboard,
  confirmationMessage,
  nextVersion,
  parseAuditList,
  parseDecisionList,
  parseDryRunResult,
  parseEnforcementStatus,
  parsePolicyDetail,
  parsePolicyList,
  safeDetailEntries,
  safeErrorMessage,
} from "../src/utils/mitigationAdminHelpers.js";

const CREATED_AT = "2026-11-22T10:00";
const createdIso = new Date(CREATED_AT).toISOString();

function basePolicyForm(overrides = {}) {
  return { ...DEFAULT_POLICY_FORM, created_at: CREATED_AT, ...overrides };
}

function baseDryRunForm(overrides = {}) {
  return {
    ...DEFAULT_DRY_RUN_FORM,
    version: "1.0.0",
    at: CREATED_AT,
    context_evaluated_at: CREATED_AT,
    ...overrides,
  };
}

test("role helpers mirror Gate C permissions and never elevate viewers", () => {
  assert.equal(canUseMitigationDashboard("admin"), true);
  assert.equal(canUseMitigationDashboard("analyst"), true);
  assert.equal(canUseMitigationDashboard("viewer"), false);
  assert.equal(canManagePolicies("admin"), true);
  assert.equal(canManagePolicies("analyst"), false);
  assert.equal(canManagePolicies("viewer"), false);
});

test("create policy payload matches the required config and omits empty optional fields", () => {
  const payload = buildCreatePolicyPayload(basePolicyForm());
  assert.deepEqual(Object.keys(payload).sort(), ["config", "created_at"]);
  assert.equal(payload.created_at, createdIso);
  assert.equal(payload.config.policy_version, "1.0.0");
  assert.equal(payload.config.mode, "monitor");
  assert.equal(payload.config.enabled, true);
  assert.equal(payload.config.throttle_enabled, false);
  assert.equal(payload.config.block_enabled, false);
  assert.equal(payload.config.monitoring_score_threshold, 25);
  assert.equal(payload.config.minimum_authentication_failures, 5);
  assert.equal(Object.hasOwn(payload, "predecessor_version"), false);
});

test("create policy payload includes valid optional fields and predecessor", () => {
  const payload = buildCreatePolicyPayload(
    basePolicyForm({
      valid_from: "2026-11-22T11:00",
      valid_until: "2026-11-22T12:00",
      predecessor_version: "0.9.0",
    })
  );
  assert.equal(payload.valid_from, new Date("2026-11-22T11:00").toISOString());
  assert.equal(payload.valid_until, new Date("2026-11-22T12:00").toISOString());
  assert.equal(payload.predecessor_version, "0.9.0");
});

test("create policy form validation rejects invalid ranges and ordering", () => {
  assert.throws(() => buildCreatePolicyPayload(basePolicyForm({ policy_version: "" })), /policy version/i);
  assert.throws(() => buildCreatePolicyPayload(basePolicyForm({ mode: "enforced" })), /policy mode/i);
  assert.throws(() => buildCreatePolicyPayload(basePolicyForm({ monitoring_score_threshold: "101" })), /between 0 and 100/i);
  assert.throws(
    () => buildCreatePolicyPayload(basePolicyForm({ monitoring_score_threshold: "80", throttling_score_threshold: "70" })),
    /Thresholds must satisfy/i
  );
  assert.throws(
    () => buildCreatePolicyPayload(basePolicyForm({ block_duration_seconds: "5000", max_block_duration_seconds: "900" })),
    /Maximum block duration/i
  );
  assert.throws(
    () => buildCreatePolicyPayload(basePolicyForm({ created_at: "not-a-date" })),
    /valid creation time/i
  );
});

test("action payload preserves omitted versus explicit null expected_active_version", () => {
  const base = { ...DEFAULT_ACTION_FORM, at: CREATED_AT };
  const omitted = buildPolicyActionPayload(base, "activate");
  assert.equal(Object.hasOwn(omitted, "expected_active_version"), false);
  assert.equal(omitted.reason_code, "initial_activation");

  const explicitNull = buildPolicyActionPayload({ ...base, expectedMode: "null" }, "activate");
  assert.equal(Object.hasOwn(explicitNull, "expected_active_version"), true);
  assert.equal(explicitNull.expected_active_version, null);

  const version = buildPolicyActionPayload(
    { ...base, expectedMode: "version", expectedVersion: "1.0.0" },
    "rollback"
  );
  assert.equal(version.expected_active_version, "1.0.0");
  assert.equal(Object.hasOwn(version, "reason_code"), false);
});

test("action payloads use the exact deactivate and retire contracts", () => {
  const base = { ...DEFAULT_ACTION_FORM, at: CREATED_AT, version: "2.0.0", reason_code: "operator_review" };
  const deactivate = buildPolicyActionPayload(base, "deactivate");
  assert.deepEqual(Object.keys(deactivate).sort(), ["at", "reason_code", "version"]);
  assert.equal(deactivate.version, "2.0.0");
  assert.equal(deactivate.reason_code, "operator_review");

  const retire = buildPolicyActionPayload({ ...base, expectedMode: "version" }, "retire");
  assert.deepEqual(retire, { at: createdIso });
  assert.throws(() => buildPolicyActionPayload(base, "unknown"), /Unsupported lifecycle action/i);
});

test("dry-run payload sends dry_run true, required context, and only supplied optional fields", () => {
  const payload = buildDryRunPayload(baseDryRunForm());
  assert.equal(payload.version, "1.0.0");
  assert.equal(payload.at, createdIso);
  assert.equal(payload.dry_run, true);
  assert.equal(payload.context.evaluated_at, createdIso);
  assert.equal(payload.context.attribution_status, "missing");
  assert.equal(payload.context.is_admin, false);
  assert.equal(payload.context.is_control_plane, false);
  assert.equal(Object.hasOwn(payload, "detection_result"), false);
  assert.equal(Object.hasOwn(payload, "idempotency_token"), false);
});

test("dry-run payload includes minimal detection fields and validated hashes", () => {
  const actor = `sha256:${"a".repeat(64)}`;
  const payload = buildDryRunPayload(
    baseDryRunForm({
      include_detection: "true",
      bot_risk_score: "88.5",
      bot_classification: "automation_suspicious",
      bot_summary: "Neutral advisory summary",
      attribution_status: "verified_user",
      actor_key_hash: actor,
      idempotency_token: "run-1",
    })
  );
  assert.deepEqual(payload.detection_result, {
    bot_risk_score: 88.5,
    classification: "automation_suspicious",
    summary: "Neutral advisory summary",
  });
  assert.equal(payload.context.actor_key_hash, actor);
  assert.equal(payload.idempotency_token, "run-1");
});

test("dry-run validation rejects invalid hashes and missing required attribution hashes", () => {
  assert.throws(
    () => buildDryRunPayload(baseDryRunForm({ actor_key_hash: "raw-actor" })),
    /sha256/i
  );
  assert.throws(
    () => buildDryRunPayload(baseDryRunForm({ attribution_status: "verified_user" })),
    /actor key hash/i
  );
  assert.throws(
    () => buildDryRunPayload(baseDryRunForm({ bot_risk_score: "101", include_detection: true })),
    /Bot risk score/i
  );
});

test("decision and audit filters include only supported query parameters", () => {
  const decisionParams = buildDecisionParams({
    ...DEFAULT_DECISION_FILTERS,
    policy_version: "1.0.0",
    decision_ref: "ref-1",
    decision_type: "monitor",
    scope_type: "network_ip",
    from_time: "2026-11-22T10:00",
    to_time: "2026-11-22T11:00",
    limit: "10",
    offset: "20",
  });
  assert.deepEqual(decisionParams, {
    limit: 10,
    offset: 20,
    policy_version: "1.0.0",
    decision_ref: "ref-1",
    from_time: createdIso,
    to_time: new Date("2026-11-22T11:00").toISOString(),
    decision_type: "monitor",
    scope_type: "network_ip",
  });

  const auditParams = buildAuditParams({
    ...DEFAULT_AUDIT_FILTERS,
    event_type: "policy_activated",
    entity_type: "policy",
    decision_ref: "ref-1",
  });
  assert.equal(auditParams.event_type, "policy_activated");
  assert.equal(auditParams.entity_type, "policy");
  assert.equal(auditParams.decision_ref, "ref-1");
  assert.equal(Object.hasOwn(auditParams, "decision_type"), false);
});

test("list filter validation enforces documented bounds and time ordering", () => {
  assert.throws(() => buildDecisionParams({ ...DEFAULT_DECISION_FILTERS, limit: "201" }), /Limit/i);
  assert.throws(() => buildAuditParams({ ...DEFAULT_AUDIT_FILTERS, offset: "-1" }), /Offset/i);
  assert.throws(
    () => buildDecisionParams({ ...DEFAULT_DECISION_FILTERS, from_time: "2026-11-22T12:00", to_time: "2026-11-22T11:00" }),
    /earlier than or equal/i
  );
  assert.throws(
    () => buildAuditParams({ ...DEFAULT_AUDIT_FILTERS, event_type: "block_applied" }),
    /event type/i
  );
});

test("response parsers reject unexpected structures instead of returning empty success", () => {
  const policyList = parsePolicyList({ active_version: "1.0.0", versions: ["1.0.0"], policies: [{ policy_version: "1.0.0" }] });
  assert.equal(policyList.activeVersion, "1.0.0");
  assert.equal(policyList.policies.length, 1);
  assert.throws(() => parsePolicyList({ policies: [] }), /unexpected policy list/i);
  assert.throws(() => parsePolicyDetail({ ok: true }), /unexpected policy detail/i);

  const decisions = parseDecisionList({ items: [{ decision_uuid: "d1" }], total: 1, limit: 50, offset: 0 });
  assert.equal(decisions.items[0].decision_uuid, "d1");
  assert.equal(decisions.total, 1);
  assert.throws(() => parseDecisionList([]), /unexpected decision list/i);
  assert.throws(() => parseAuditList({ total: 0 }), /unexpected audit event list/i);
});

test("status and dry-run parsers preserve advisory semantics", () => {
  const status = parseEnforcementStatus({
    enforcement_active: false,
    advisory_only: true,
    active_version: "1.0.0",
    policy_available: true,
    policy_mode: "monitor",
    persisted_active_version: "0.9.0",
    activation_event_count: 2,
    latest_activation_event_type: "ACTIVATE",
  });
  assert.equal(status.enforcementActive, false);
  assert.equal(status.advisoryOnly, true);
  assert.equal(status.persistedActiveVersion, "0.9.0");

  const result = parseDryRunResult({
    ok: false,
    decision: null,
    error: { code: "evaluation_failed", message: "Evaluation could not complete", fields: [] },
    audit_event: null,
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "evaluation_failed");
  assert.throws(() => parseDryRunResult({ decision: {} }), /unexpected dry-run/i);
});

test("safe error messages map known statuses without leaking raw details", () => {
  assert.match(safeErrorMessage(new Error("HTTP 401: expired"), "fallback"), /session has expired/i);
  assert.match(safeErrorMessage(new Error("HTTP 403: forbidden"), "fallback"), /permission/i);
  assert.match(safeErrorMessage(new Error("HTTP 422: validation_error: Invalid threshold"), "fallback"), /Invalid threshold/);
  assert.match(safeErrorMessage(new Error("HTTP 422: password=hunter2"), "fallback"), /rejected/i);
  assert.match(safeErrorMessage(new TypeError("failed to fetch"), "fallback"), /Unable to reach the API/);
  assert.equal(safeErrorMessage(new Error("custom"), "fallback"), "fallback");
});

test("audit detail projection redacts sensitive keys and unsupported nested values", () => {
  const entries = safeDetailEntries({
    reason: "policy_activated",
    count: 3,
    nested: { secret: "hidden" },
    access_token: "should-not-appear",
    api_key: "should-not-appear",
  });
  const keys = entries.map(([key]) => key);
  assert.deepEqual(keys.sort(), ["count", "reason"]);
  assert.equal(entries.find(([key]) => key === "count")[1], "3");
});

test("confirmation copy and version helper are deterministic", () => {
  assert.match(confirmationMessage("activate", "1.0.0"), /Activate policy version "1.0.0"/);
  assert.match(confirmationMessage("activate", "1.0.0"), /no request enforcement/i);
  assert.equal(nextVersion("1.2.3"), "1.2.4");
  assert.equal(nextVersion("custom"), "custom-next");
});
