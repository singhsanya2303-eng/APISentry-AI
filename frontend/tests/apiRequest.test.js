import test from "node:test";
import assert from "node:assert/strict";

import { apiRequest, readyApi } from "../src/services/api.js";

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

function mockSequence(responses, calls = []) {
  const queue = [...responses];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: new URL(String(url)), init });
    const next = queue.shift() || responses[responses.length - 1];
    return {
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      statusText: next.statusText || "Status",
      text: async () => JSON.stringify(next.payload ?? null),
    };
  };
  return calls;
}

function response(status, payload, statusText = "Status") {
  return { status, payload, statusText };
}

function hangingFetch(calls = []) {
  globalThis.fetch = (url, init) => {
    calls.push({ url: new URL(String(url)), init });
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener(
        "abort",
        () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        },
        { once: true }
      );
    });
  };
  return calls;
}

test("successful requests preserve bearer authentication and return parsed data", async () => {
  const { store } = installWindow();
  const calls = mockSequence([response(200, { ok: true }, "OK")]);

  const data = await apiRequest("/health", { params: { limit: 2 } });

  assert.deepEqual(data, { ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.pathname, "/health");
  assert.equal(calls[0].url.searchParams.get("limit"), "2");
  assert.equal(calls[0].init.headers.Authorization, `Bearer ${store.get(TOKEN_KEY)}`);
  assert.ok(calls[0].init.signal instanceof AbortSignal);
});

test("slow requests time out without clearing a valid session", async () => {
  const { store, events } = installWindow();
  const calls = hangingFetch();

  await assert.rejects(
    () => apiRequest("/health", { timeoutMs: 20 }),
    (error) => {
      assert.match(error.message, /Request timed out/);
      assert.equal(error.timedOut, true);
      assert.equal(error.aborted, false);
      return true;
    }
  );

  assert.equal(calls.length, 1);
  assert.equal(store.get(TOKEN_KEY), "test-token");
  assert.equal(events.length, 0);
});

test("caller abort is reported without logout", async () => {
  const { store, events } = installWindow();
  const controller = new AbortController();
  const calls = hangingFetch();
  const pending = apiRequest("/health", { signal: controller.signal });
  controller.abort();

  await assert.rejects(
    pending,
    (error) => {
      assert.match(error.message, /Request cancelled/);
      assert.equal(error.aborted, true);
      assert.equal(error.timedOut, false);
      return true;
    }
  );

  assert.equal(calls.length, 1);
  assert.equal(store.get(TOKEN_KEY), "test-token");
  assert.equal(events.length, 0);
});

test("eligible GET requests retry once on transient server errors", async () => {
  installWindow();
  const calls = mockSequence([
    response(503, { detail: "temporarily unavailable" }, "Service Unavailable"),
    response(200, { status: "ready" }, "OK"),
  ]);

  const data = await readyApi();

  assert.deepEqual(data, { status: "ready" });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url.pathname, "/ready");
  assert.equal(calls[1].url.pathname, "/ready");
});

test("mutating requests are never retried", async () => {
  installWindow();
  const calls = mockSequence([
    response(503, { detail: "temporarily unavailable" }, "Service Unavailable"),
    response(200, { ok: true }, "OK"),
  ]);

  await assert.rejects(
    () => apiRequest("/api/v1/auth/logout", { method: "POST" }),
    /HTTP 503: temporarily unavailable/
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.method, "POST");
});

test("401 responses clear the session once and are not retried", async () => {
  const { store, events } = installWindow();
  const calls = mockSequence([
    response(401, { detail: "Token revoked" }, "Unauthorized"),
  ]);

  await assert.rejects(() => apiRequest("/api/v1/auth/me"), /HTTP 401: Token revoked/);

  assert.equal(calls.length, 1);
  assert.equal(store.has(TOKEN_KEY), false);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, "apisentry:unauthorized");
  assert.equal(events[0].detail, "Token revoked");
});
