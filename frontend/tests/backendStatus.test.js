import test from "node:test";
import assert from "node:assert/strict";

import {
  BACKEND_STATES,
  READINESS_POLL_DELAYS_MS,
  READINESS_POLL_MAX_DURATION_MS,
  READINESS_REQUEST_TIMEOUT_MS,
  backendStateCopy,
  classifyBackendState,
  isReadinessCancelled,
  readinessAttemptCount,
  readinessRequestTimeout,
} from "../src/services/backendStatus.js";

test("readiness polling is bounded", () => {
  const totalDelay = READINESS_POLL_DELAYS_MS.reduce((sum, value) => sum + value, 0);
  assert.equal(READINESS_POLL_DELAYS_MS.length, 10);
  assert.equal(totalDelay, 80_000);
  assert.equal(READINESS_POLL_MAX_DURATION_MS, 90_000);
  assert.equal(READINESS_REQUEST_TIMEOUT_MS, 4_000);
  assert.ok(READINESS_POLL_DELAYS_MS.every((value) => value >= 2_000 && value <= 10_000));
});

test("readiness attempt count matches the bounded delay schedule", () => {
  assert.equal(readinessAttemptCount(), READINESS_POLL_DELAYS_MS.length + 1);
  assert.equal(readinessAttemptCount(), 11);
});

test("per-request timeout is clamped to the remaining deadline", () => {
  const now = 1_000_000;
  assert.equal(readinessRequestTimeout(now + 4_000, now), 4_000);
  assert.equal(readinessRequestTimeout(now + 1_000, now), 1_000);
  assert.equal(readinessRequestTimeout(now + 30_000, now), 4_000);
  assert.equal(readinessRequestTimeout(now - 5, now), 1);
});

test("readiness cancellation detects aborted signals and stale runs", () => {
  const controller = new AbortController();
  assert.equal(isReadinessCancelled(controller.signal, 3, 3), false);
  assert.equal(isReadinessCancelled(controller.signal, 2, 3), true);
  controller.abort();
  assert.equal(isReadinessCancelled(controller.signal, 3, 3), true);
});

test("backend state classification distinguishes all required states", () => {
  assert.equal(
    classifyBackendState({ healthOk: true, readyState: "ready", finalAttempt: false }),
    BACKEND_STATES.ONLINE
  );
  assert.equal(
    classifyBackendState({ healthOk: false, readyState: "network_error", finalAttempt: false }),
    BACKEND_STATES.WAKING
  );
  assert.equal(
    classifyBackendState({ healthOk: false, readyState: "network_error", finalAttempt: true }),
    BACKEND_STATES.OFFLINE
  );
  assert.equal(
    classifyBackendState({ healthOk: true, readyState: "not_ready", finalAttempt: true }),
    BACKEND_STATES.NOT_READY
  );
  assert.equal(
    classifyBackendState({ healthOk: true, readyState: "network_error", finalAttempt: true }),
    BACKEND_STATES.OFFLINE
  );
});

test("status copy covers every displayed state without inventing backend semantics", () => {
  for (const state of Object.values(BACKEND_STATES)) {
    const copy = backendStateCopy(state);
    assert.ok(copy.label);
    assert.ok(copy.banner);
    assert.ok(copy.message);
    assert.ok(copy.tag);
  }
  assert.match(backendStateCopy(BACKEND_STATES.WAKING).message, /bounded backoff/i);
  assert.match(backendStateCopy(BACKEND_STATES.NOT_READY).message, /health endpoint responded/i);
});
