import test from "node:test";
import assert from "node:assert/strict";

import { mitigationAdminApi } from "../src/services/api.js";

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

function mockFetch({ status = 200, statusText = "OK", payload = { ok: true }, calls = [] } = {}) {
  globalThis.fetch = async (url, init) => {
    calls.push({ url: new URL(String(url)), init });
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText,
      text: async () => JSON.stringify(payload),
    };
  };
  return calls;
}

test("all Gate C read routes use the shared base URL and bearer token", async () => {
  const { store } = installWindow();
  const calls = mockFetch();

  await mitigationAdminApi.listPolicies();
  await mitigationAdminApi.getActivePolicy();
  await mitigationAdminApi.getPolicy("1.0.0");
  await mitigationAdminApi.listDecisions({ limit: 10 });
  await mitigationAdminApi.getDecision("decision/with/slash");
  await mitigationAdminApi.listAuditEvents({ offset: 5 });
  await mitigationAdminApi.getAuditEvent("event-1");
  await mitigationAdminApi.getEnforcementStatus();

  const paths = calls.map(({ url }) => url.pathname);
  assert.deepEqual(paths, [
    "/api/v1/security/mitigation/policies",
    "/api/v1/security/mitigation/policies/active",
    "/api/v1/security/mitigation/policies/1.0.0",
    "/api/v1/security/mitigation/decisions",
    "/api/v1/security/mitigation/decisions/decision%2Fwith%2Fslash",
    "/api/v1/security/mitigation/audit-events",
    "/api/v1/security/mitigation/audit-events/event-1",
    "/api/v1/security/mitigation/enforcement/status",
  ]);
  for (const { url, init } of calls) {
    assert.equal(url.host, "127.0.0.1:8000");
    assert.equal(init.method, "GET");
    assert.equal(init.headers.Authorization, `Bearer ${store.get(TOKEN_KEY)}`);
    assert.equal(init.headers.Accept, "application/json");
    assert.equal(init.body, undefined);
  }
  assert.equal(calls[3].url.searchParams.get("limit"), "10");
  assert.equal(calls[5].url.searchParams.get("offset"), "5");
});

test("policy mutation routes and bodies match Gate C request contracts", async () => {
  installWindow();
  const calls = mockFetch();
  const at = "2026-11-22T10:00:00.000Z";
  const body = { at, expected_active_version: null };

  await mitigationAdminApi.createPolicy({ config: { policy_version: "1.0.0" }, created_at: at });
  await mitigationAdminApi.validatePolicy("1.0.0", { at });
  await mitigationAdminApi.activatePolicy("1.0.0", body);
  await mitigationAdminApi.deactivatePolicy({ ...body, version: "1.0.0", reason_code: "policy_deactivation" });
  await mitigationAdminApi.retirePolicy("1.0.0", { at });
  await mitigationAdminApi.rollbackPolicy("1.0.0", body);

  const paths = calls.map(({ url }) => url.pathname);
  assert.deepEqual(paths, [
    "/api/v1/security/mitigation/policies",
    "/api/v1/security/mitigation/policies/1.0.0/validate",
    "/api/v1/security/mitigation/policies/1.0.0/activate",
    "/api/v1/security/mitigation/policies/deactivate",
    "/api/v1/security/mitigation/policies/1.0.0/retire",
    "/api/v1/security/mitigation/policies/1.0.0/rollback",
  ]);
  for (const { init } of calls) {
    assert.equal(init.method, "POST");
    assert.equal(init.headers["Content-Type"], "application/json");
    assert.equal(typeof init.body, "string");
  }
  assert.deepEqual(JSON.parse(calls[2].init.body), body);
  assert.equal(JSON.parse(calls[3].init.body).version, "1.0.0");
  assert.equal(JSON.parse(calls[3].init.body).expected_active_version, null);
  assert.deepEqual(JSON.parse(calls[4].init.body), { at });
});

test("dry-run route sends advisory body with a single auth mechanism", async () => {
  installWindow();
  const calls = mockFetch();
  const body = {
    version: "1.0.0",
    at: "2026-11-22T10:00:00.000Z",
    dry_run: true,
    context: { evaluated_at: "2026-11-22T10:00:00.000Z", attribution_status: "missing" },
  };

  await mitigationAdminApi.dryRun(body);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.pathname, "/api/v1/security/mitigation/dry-run");
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].init.body), body);
  assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
  assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(calls[0].init.body), "token"), false);
});

test("query params omit empty values and preserve explicit zero and false", async () => {
  installWindow();
  const calls = mockFetch();

  await mitigationAdminApi.listDecisions({
    policy_version: "",
    decision_ref: "",
    decision_type: "monitor",
    limit: 0,
    offset: 0,
  });

  const params = calls[calls.length - 1].url.searchParams;
  assert.equal(params.has("policy_version"), false);
  assert.equal(params.has("decision_ref"), false);
  assert.equal(params.get("decision_type"), "monitor");
  assert.equal(params.get("limit"), "0");
  assert.equal(params.get("offset"), "0");
});

test("structured Gate C validation details are preserved in error messages", async () => {
  installWindow();
  mockFetch({
    status: 409,
    statusText: "Conflict",
    payload: { detail: { code: "version_conflict", message: "Expected version changed" } },
  });

  await assert.rejects(() => mitigationAdminApi.activatePolicy("1.0.0", { at: "2026-11-22T10:00:00Z" }), /version_conflict: Expected version changed/);
});

test("403 responses reject without elevating or retrying", async () => {
  installWindow();
  mockFetch({
    status: 403,
    statusText: "Forbidden",
    payload: { detail: "Operation not permitted for role 'viewer'. Required: admin" },
  });

  await assert.rejects(() => mitigationAdminApi.createPolicy({}), /HTTP 403: Operation not permitted/);
});

test("401 responses clear the stored token and dispatch the shared unauthorized event", async () => {
  const { store, events } = installWindow();
  mockFetch({
    status: 401,
    statusText: "Unauthorized",
    payload: { detail: "Missing authentication credentials" },
  });

  await assert.rejects(() => mitigationAdminApi.listPolicies(), /HTTP 401: Missing authentication credentials/);
  assert.equal(store.has(TOKEN_KEY), false);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, "apisentry:unauthorized");
});
