// Bounded readiness model for the Render Free cold-start experience. The
// backend owns the meaning of /health and /ready; these values only classify
// the responses for display and stop polling at a documented deadline.
export const BACKEND_STATES = Object.freeze({
  CHECKING: "checking",
  ONLINE: "online",
  WAKING: "waking",
  NOT_READY: "not_ready",
  OFFLINE: "offline",
});

export const READINESS_POLL_DELAYS_MS = Object.freeze([
  2_000, 4_000, 6_000, 8_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000,
]);
export const READINESS_POLL_MAX_DURATION_MS = 90_000;
export const READINESS_REQUEST_TIMEOUT_MS = 4_000;

export function readinessAttemptCount(delays = READINESS_POLL_DELAYS_MS) {
  return delays.length + 1;
}

export function readinessRequestTimeout(deadline, now = Date.now()) {
  return Math.max(1, Math.min(READINESS_REQUEST_TIMEOUT_MS, deadline - now));
}

export function isReadinessCancelled(signal, runId, currentRunId) {
  return Boolean(signal?.aborted || runId !== currentRunId);
}

export function classifyBackendState({ healthOk, readyState, finalAttempt }) {
  if (healthOk && readyState === "ready") return BACKEND_STATES.ONLINE;
  if (healthOk && readyState === "not_ready") return BACKEND_STATES.NOT_READY;
  if (healthOk && readyState === "network_error") {
    return finalAttempt ? BACKEND_STATES.OFFLINE : BACKEND_STATES.WAKING;
  }
  return finalAttempt ? BACKEND_STATES.OFFLINE : BACKEND_STATES.WAKING;
}

export function backendStateCopy(state) {
  switch (state) {
    case BACKEND_STATES.ONLINE:
      return {
        label: "API Connected",
        banner: "Backend is ready",
        message: "Health and readiness checks both succeeded.",
        tag: "CONNECTED",
      };
    case BACKEND_STATES.WAKING:
      return {
        label: "Backend waking",
        banner: "Backend is waking up",
        message: "A free-tier service may need up to a minute to respond. Checking again with bounded backoff.",
        tag: "WAKING",
      };
    case BACKEND_STATES.NOT_READY:
      return {
        label: "Service not ready",
        banner: "Backend is healthy but not ready",
        message: "The health endpoint responded, but readiness reported dependencies as unavailable.",
        tag: "NOT READY",
      };
    case BACKEND_STATES.OFFLINE:
      return {
        label: "API Offline",
        banner: "Backend connection unavailable",
        message: "The bounded readiness window ended. Start the API and check its configuration.",
        tag: "NEEDS ATTENTION",
      };
    case BACKEND_STATES.CHECKING:
    default:
      return {
        label: "Checking API",
        banner: "Connecting to APISentry backend",
        message: "Checking the health and readiness endpoints. Please wait.",
        tag: "CHECKING",
      };
  }
}
