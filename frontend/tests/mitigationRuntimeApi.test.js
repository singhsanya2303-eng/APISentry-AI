import test from "node:test";
import assert from "node:assert/strict";

import { securityApis } from "../src/services/api.js";

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

test("mitigationRuntimeAnalyze calls runtime-analyze endpoint with bearer token and params", async () => {
  installWindow();
  const calls = mockFetch({
    payload: {
      detection: { results: [] },
      runtime_results: [],
      advisory_only: true,
      enforcement_executed: false,
    },
  });

  const data = await securityApis.mitigationRuntimeAnalyze({ page: 1, page_size: 50, include_behavioral_risk: false });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.pathname, "/api/v1/security/mitigation/runtime-analyze");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
  assert.equal(calls[0].url.searchParams.get("page"), "1");
  assert.equal(calls[0].url.searchParams.get("page_size"), "50");
  assert.equal(calls[0].url.searchParams.get("include_behavioral_risk"), "false");
  assert.equal(data.advisory_only, true);
  assert.equal(data.enforcement_executed, false);
});

test("mitigationRuntimeAnalyze preserves 403 without retrying", async () => {
  installWindow();
  mockFetch({ status: 403, payload: { detail: "Operation not permitted for role 'viewer'." } });
  await assert.rejects(() => securityApis.mitigationRuntimeAnalyze(), /HTTP 403/);
});
