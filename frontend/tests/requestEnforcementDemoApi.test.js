import test from "node:test";
import assert from "node:assert/strict";

import { mitigationAdminApi } from "../src/services/api.js";
import {
  REQUEST_DEMO_CONFIRMATION,
  buildRequestEnforcementEnablePayload,
  parseRequestEnforcementEvidence,
  parseRequestEnforcementRun,
  parseRequestEnforcementStatus,
  requestEnforcementMode,
} from "../src/utils/mitigationAdminHelpers.js";

const TOKEN_KEY = "apisentry.access_token";

function installWindow(token = "test-token") {
  const store = new Map();
  if (token) store.set(TOKEN_KEY, token);
  const events = [];
  globalThis.window = {
    localStorage: {
      getItem: (key) => store.get(key) ?? null,
      setItem: (key, value) => store.set(key, value),
      removeItem: (key) => store.delete(key),
    },
    dispatchEvent: (event) => {
      events.push(event);
      return true;
    },
  };
  globalThis.CustomEvent = class CustomEvent {
    constructor(type, options) {
      this.type = type;
      this.detail = options?.detail;
    }
  };
  return { store, events };
}

function mockFetch({ status = 200, payload = { ok: true }, calls = [] } = {}) {
  globalThis.fetch = async (url, init) => {
    calls.push({ url: new URL(String(url)), init });
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? "OK" : "ERR",
      text: async () => JSON.stringify(payload),
    };
  };
  return calls;
}

const STATUS_PAYLOAD = {
  demo_enabled: true,
  enforcement_enabled: true,
  advisory_only: false,
  kill_switch_active: false,
  loopback_only: true,
  synthetic_only: true,
  production_middleware_registered: false,
  real_enforcement: false,
  demo_id: "wp9-ui",
  scenario: "block",
  policy_version: "wp9-ui-policy",
  max_requests: 12,
  requests_executed: 1,
  started_at: "2026-11-25T10:00:00Z",
  decision_count: 1,
  audit_event_count: 2,
  persistence_db: "isolated-temp-sqlite",
  status_reason: "active_isolated_enforcement",
  guards: { default_off: true },
};

test("isolated enforcement API methods use the dedicated routes with bearer auth", async () => {
  installWindow();
  const calls = mockFetch({ payload: STATUS_PAYLOAD });

  await mitigationAdminApi.getRequestEnforcementStatus();
  await mitigationAdminApi.enableRequestEnforcementDemo({ synthetic_only_ack: true });
  await mitigationAdminApi.runRequestEnforcementDemo({ synthetic: true, request_count: 3 });
  await mitigationAdminApi.requestEnforcementKillSwitch();
  await mitigationAdminApi.requestEnforcementFailClosed();
  await mitigationAdminApi.getRequestEnforcementEvidence();
  await mitigationAdminApi.disableRequestEnforcementDemo({ reason: "operator_disable" });

  const base = "/api/v1/security/mitigation/request-enforcement-demo";
  assert.deepEqual(calls.map(({ url }) => url.pathname), [
    `${base}/status`,
    `${base}/enable`,
    `${base}/run`,
    `${base}/kill-switch`,
    `${base}/fail-closed`,
    `${base}/evidence`,
    `${base}/disable`,
  ]);
  for (const { init } of calls) {
    assert.equal(init.headers.Authorization, "Bearer test-token");
    assert.equal(init.headers.Accept, "application/json");
  }
  assert.deepEqual(JSON.parse(calls[2].init.body), { synthetic: true, request_count: 3 });
  assert.deepEqual(JSON.parse(calls[6].init.body), { reason: "operator_disable" });
});

test("isolated enforcement API preserves 403 without retry or escalation", async () => {
  installWindow();
  mockFetch({
    status: 403,
    statusText: "Forbidden",
    payload: { detail: "Operation not permitted for role 'viewer'." },
  });
  await assert.rejects(
    () => mitigationAdminApi.getRequestEnforcementStatus(),
    /HTTP 403: Operation not permitted/
  );
});

test("status parser distinguishes demo enforcement from production enforcement", () => {
  const parsed = parseRequestEnforcementStatus(STATUS_PAYLOAD);
  assert.equal(parsed.enforcementEnabled, true);
  assert.equal(parsed.realEnforcement, false);
  assert.equal(parsed.productionMiddlewareRegistered, false);
  assert.equal(parsed.syntheticOnly, true);
  assert.equal(parsed.loopbackOnly, true);
  assert.equal(requestEnforcementMode(parsed).label, "ISOLATED ENFORCEMENT ON (DEMO)");

  const stopped = { ...STATUS_PAYLOAD, kill_switch_active: true, enforcement_enabled: false, advisory_only: true };
  assert.equal(requestEnforcementMode(parseRequestEnforcementStatus(stopped)).label, "KILL SWITCH ACTIVE (DEMO)");
  assert.throws(() => parseRequestEnforcementStatus({ demo_enabled: true }), /unexpected isolated enforcement status/i);
});

test("enable payload requires explicit acknowledgements and bounded synthetic inputs", () => {
  const rejected = buildRequestEnforcementEnablePayload({
    confirmation: "ENABLE_LOCAL_DEMO",
    demo_id: "bad id!",
    policy_version: "",
    scenario: "real-traffic",
    max_requests: "500",
    max_duration_seconds: "5",
  });
  assert.equal(rejected.payload, null);
  assert.deepEqual(Object.keys(rejected.errors).sort(), [
    "confirmation",
    "demo_id",
    "max_duration_seconds",
    "max_requests",
    "policy_version",
    "scenario",
  ]);

  const accepted = buildRequestEnforcementEnablePayload({
    confirmation: REQUEST_DEMO_CONFIRMATION,
    demo_id: "wp9-ui-1",
    policy_version: "wp9-ui-policy",
    scenario: "throttle",
    max_requests: "6",
    max_duration_seconds: "120",
  });
  assert.deepEqual(accepted.errors, {});
  assert.equal(accepted.payload.synthetic_only_ack, true);
  assert.equal(accepted.payload.loopback_only_ack, true);
  assert.equal(accepted.payload.isolated_db_ack, true);
  assert.equal(accepted.payload.max_requests, 6);
});

test("run and evidence parsers preserve outcomes and redact unsupported details", () => {
  const run = parseRequestEnforcementRun({
    demo_id: "wp9-ui",
    scenario: "block",
    status: STATUS_PAYLOAD,
    outcomes: [
      {
        status_code: 403,
        enforcement_action: "block",
        enforcement_outcome: "blocked",
        handler_reached: false,
        decision_ref: "decision-1",
        request_ref: "request-1",
      },
    ],
  });
  assert.equal(run.outcomes[0].statusCode, 403);
  assert.equal(run.outcomes[0].handlerReached, false);

  const evidence = parseRequestEnforcementEvidence({
    decision_count: 1,
    audit_event_count: 1,
    decisions: [{ decision_uuid: "d1", decision_type: "block", issued_at: "2026-11-25T10:00:00Z", advisory_only: false }],
    audit_events: [{
      event_uuid: "e1",
      event_type: "enforcement_applied_reserved",
      created_at: "2026-11-25T10:00:00Z",
      details: {
        selected_action: "block",
        enforcement_outcome: "blocked",
        api_key: "must-not-appear",
        nested: { secret: "must-not-appear" },
      },
    }],
  });
  assert.equal(evidence.decisions[0].decisionRef, "d1");
  const keys = evidence.auditEvents[0].details.map(([key]) => key);
  assert.deepEqual(keys.sort(), ["enforcement_outcome", "selected_action"]);
  assert.throws(() => parseRequestEnforcementEvidence({ decisions: [] }), /unexpected isolated enforcement evidence/i);
});
