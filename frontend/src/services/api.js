/* global __APISENTRY_API_BASE__ */
import {
  clearAccessToken,
  getAccessToken,
  UNAUTHORIZED_EVENT,
} from "./tokenStorage.js";

// Vite injects import.meta.env at build time. The fallback keeps the shared
// client importable from the Node test runner without reading any local env
// files or introducing a second configuration mechanism. Production builds are
// validated by vite.config.js and must define VITE_API_BASE_URL explicitly, so
// no localhost fallback is emitted into a production bundle.
const runtimeEnv = import.meta.env || {};
const configuredApiBase =
  typeof __APISENTRY_API_BASE__ === "string"
    ? __APISENTRY_API_BASE__
    : runtimeEnv.VITE_API_BASE_URL;
const isProductionBuild = runtimeEnv.PROD === true;

if (isProductionBuild && !configuredApiBase) {
  throw new Error("VITE_API_BASE_URL is required for production builds");
}

export const API_BASE =
  configuredApiBase || (isProductionBuild ? "" : "http://127.0.0.1:8000");

function responseDetail(data, response) {
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) {
    return data.detail
      .map((item) => item?.msg || JSON.stringify(item))
      .join("; ");
  }
  // Gate C lifecycle failures return a structured object under `detail`.
  // Preserve its safe code/message so the dashboard can show server validation
  // feedback without echoing raw payloads or internals.
  if (data?.detail && typeof data.detail === "object") {
    const code = typeof data.detail.code === "string" ? data.detail.code : "";
    const message = typeof data.detail.message === "string" ? data.detail.message : "";
    if (message && code) return `${code}: ${message}`;
    if (message) return message;
    if (code) return code;
  }
  if (typeof data?.message === "string") return data.message;
  return response.statusText || `Request failed with HTTP ${response.status}`;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const MAX_IDEMPOTENT_GET_RETRIES = 1;
const RETRYABLE_STATUSES = new Set([502, 503, 504]);

export class ApiRequestError extends Error {
  constructor(
    message,
    {
      status = null,
      data = null,
      reason = "request_failed",
      aborted = false,
      timedOut = false,
      cause,
    } = {}
  ) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.data = data;
    this.reason = reason;
    this.aborted = aborted;
    this.timedOut = timedOut;
    if (cause !== undefined) this.cause = cause;
  }
}

export function isRequestCancelled(error) {
  return Boolean(error?.aborted || error?.name === "AbortError");
}

function normalizedMethod(method) {
  return String(method || "GET").toUpperCase();
}

function isRetryableGet(method, options) {
  return (
    normalizedMethod(method) === "GET" &&
    options.retry !== false &&
    options.maxRetries !== 0
  );
}

function shouldRetry(error, method, options) {
  if (!isRetryableGet(method, options)) return false;
  if (error?.timedOut || error?.aborted) return false;
  if (error?.status && RETRYABLE_STATUSES.has(error.status)) return true;
  return error?.reason === "network";
}

async function performRequest({
  url,
  method,
  headers,
  body,
  path,
  timeoutMs,
  externalSignal,
}) {
  const controller = new AbortController();
  let cancelledByCaller = false;
  let timedOut = false;

  const abortFromCaller = () => {
    cancelledByCaller = true;
    controller.abort();
  };
  if (externalSignal) {
    if (externalSignal.aborted) abortFromCaller();
    else externalSignal.addEventListener("abort", abortFromCaller, { once: true });
  }
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      method,
      headers,
      signal: controller.signal,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!response.ok) {
      // A rejected bearer token invalidates the local session. Login failures
      // are excluded so a bad password does not emit a global session-expired
      // event. Aborted requests never enter this branch.
      if (
        response.status === 401 &&
        getAccessToken() &&
        !path.startsWith("/api/v1/auth/login")
      ) {
        clearAccessToken();
        if (typeof window !== "undefined") {
          window.dispatchEvent(
            new CustomEvent(UNAUTHORIZED_EVENT, {
              detail: responseDetail(data, response),
            })
          );
        }
      }
      throw new ApiRequestError(
        `HTTP ${response.status}: ${responseDetail(data, response)}`,
        { status: response.status, data, reason: "http" }
      );
    }

    return data;
  } catch (error) {
    if (error instanceof ApiRequestError) throw error;
    if (cancelledByCaller || externalSignal?.aborted) {
      throw new ApiRequestError("Request cancelled", {
        reason: "aborted",
        aborted: true,
        cause: error,
      });
    }
    if (timedOut) {
      throw new ApiRequestError("Request timed out", {
        reason: "timeout",
        timedOut: true,
        cause: error,
      });
    }
    throw new ApiRequestError(
      error instanceof Error ? error.message : "Network request failed",
      { reason: "network", cause: error }
    );
  } finally {
    clearTimeout(timeoutId);
    if (externalSignal) {
      externalSignal.removeEventListener("abort", abortFromCaller);
    }
  }
}

export async function apiRequest(
  path,
  {
    method = "GET",
    params,
    body,
    signal,
    timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    retry = true,
    maxRetries = MAX_IDEMPOTENT_GET_RETRIES,
  } = {}
) {
  const url = new URL(`${API_BASE}${path}`);

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });
  }

  const headers = { Accept: "application/json" };
  const token = getAccessToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const boundedRetries = Number.isInteger(maxRetries)
    ? Math.max(0, Math.min(maxRetries, MAX_IDEMPOTENT_GET_RETRIES))
    : 0;
  const options = { retry, maxRetries: boundedRetries };

  for (let attempt = 0; attempt <= boundedRetries; attempt += 1) {
    try {
      return await performRequest({
        url,
        method,
        headers,
        body,
        path,
        timeoutMs,
        externalSignal: signal,
      });
    } catch (error) {
      const isFinalAttempt = attempt === boundedRetries;
      if (isFinalAttempt || !shouldRetry(error, method, options)) throw error;
    }
  }

  throw new ApiRequestError("Request failed");
}

export const healthApi = (options) => apiRequest("/health", options);
export const readyApi = (options) => apiRequest("/ready", options);

export const authApi = {
  register: (payload) =>
    apiRequest("/api/v1/auth/register", {
      method: "POST",
      body: payload,
    }),

  login: (payload) =>
    apiRequest("/api/v1/auth/login", {
      method: "POST",
      body: payload,
    }),

  me: () => apiRequest("/api/v1/auth/me"),

  logout: () =>
    apiRequest("/api/v1/auth/logout", {
      method: "POST",
    }),
};

export const adminApi = {
  listUsers: () => apiRequest("/api/v1/users"),
};

export const securityApis = {
  bola: (params = {}) =>
    apiRequest("/api/v1/security/bola/analyze", { params }),

  bruteForce: (params = {}) =>
    apiRequest("/api/v1/security/bruteforce/analyze", { params }),

  rateAnomaly: (params = {}) =>
    apiRequest("/api/v1/security/rate-anomaly/analyze", { params }),

  behavior: (params = {}) =>
    apiRequest("/api/v1/security/behavior/analyze", { params }),

  clustering: (body) =>
    apiRequest("/api/v1/security/clustering/analyze", {
      method: "POST",
      body,
    }),

  tokenClassifier: (body) =>
    apiRequest("/api/v1/security/token-classifier/predict", {
      method: "POST",
      body,
    }),

  trafficTrends: (params) =>
    apiRequest("/api/v1/security/traffic-trends/analyze", { params }),
  tokenClassifierFeatures: () =>
    apiRequest("/api/v1/security/token-classifier/features"),

  // Advisory-only, stored-traffic analyses. Both endpoints accept the same
  // optional filter contract; apiRequest already omits undefined/null/empty
  // values while preserving explicit false and zero values.
  botDetection: (params = {}) =>
    apiRequest("/api/v1/security/bot/analyze", { params }),

  mitigation: (params = {}) =>
    apiRequest("/api/v1/security/mitigation/analyze", { params }),

  // Additive MW4-A runtime composition endpoint (advisory-only): detection +
  // MW2 advanced advisory signals + MW1 unified risk assessment + Stage A
  // mitigation. No enforcement is executed by this endpoint.
  mitigationRuntimeAnalyze: (params = {}) =>
    apiRequest("/api/v1/security/mitigation/runtime-analyze", { params }),

  // Advisory-only HTTP payload classifier. No payload echo is requested here;
  // the backend default keeps raw parameter values out of the response.
  httpPayloadClassifierPredict: (body) =>
    apiRequest("/api/v1/security/payload-classifier/predict", {
      method: "POST",
      body,
    }),

  httpPayloadClassifierMetadata: () =>
    apiRequest("/api/v1/security/payload-classifier/metadata"),
};

// Gate C authenticated advisory mitigation APIs. These routes accept a bearer
// token only; the shared apiRequest remains the single auth/error boundary.
// Path segments are encoded here so opaque references cannot alter the route.
const MITIGATION_BASE = "/api/v1/security/mitigation";
const mitigationPath = (...segments) =>
  `${MITIGATION_BASE}/${segments.map((segment) => encodeURIComponent(segment)).join("/")}`;

export const mitigationAdminApi = {
  listPolicies: () => apiRequest(mitigationPath("policies")),
  getActivePolicy: () => apiRequest(mitigationPath("policies", "active")),
  getPolicy: (policyVersion) => apiRequest(mitigationPath("policies", policyVersion)),
  createPolicy: (body) =>
    apiRequest(mitigationPath("policies"), { method: "POST", body }),
  validatePolicy: (policyVersion, body) =>
    apiRequest(mitigationPath("policies", policyVersion, "validate"), {
      method: "POST",
      body,
    }),
  activatePolicy: (policyVersion, body) =>
    apiRequest(mitigationPath("policies", policyVersion, "activate"), {
      method: "POST",
      body,
    }),
  deactivatePolicy: (body) =>
    apiRequest(mitigationPath("policies", "deactivate"), {
      method: "POST",
      body,
    }),
  retirePolicy: (policyVersion, body) =>
    apiRequest(mitigationPath("policies", policyVersion, "retire"), {
      method: "POST",
      body,
    }),
  rollbackPolicy: (policyVersion, body) =>
    apiRequest(mitigationPath("policies", policyVersion, "rollback"), {
      method: "POST",
      body,
    }),
  listDecisions: (params = {}) =>
    apiRequest(mitigationPath("decisions"), { params }),
  getDecision: (decisionRef) =>
    apiRequest(mitigationPath("decisions", decisionRef)),
  listAuditEvents: (params = {}) =>
    apiRequest(mitigationPath("audit-events"), { params }),
  getAuditEvent: (eventUuid) =>
    apiRequest(mitigationPath("audit-events", eventUuid)),
  getEnforcementStatus: () => apiRequest(mitigationPath("enforcement", "status")),
  dryRun: (body) => apiRequest(mitigationPath("dry-run"), { method: "POST", body }),
  // Gate E isolated local demo-only enforcement harness (default OFF).
  getDemoStatus: () => apiRequest(mitigationPath("demo", "status")),
  enableDemo: (body) => apiRequest(mitigationPath("demo", "enable"), { method: "POST", body }),
  disableDemo: (body) => apiRequest(mitigationPath("demo", "disable"), { method: "POST", body }),
  demoKillSwitch: () => apiRequest(mitigationPath("demo", "kill-switch"), { method: "POST" }),
  runDemo: (body) => apiRequest(mitigationPath("demo", "run"), { method: "POST", body }),

  // WP9 dedicated isolated request-time enforcement demo. All calls are
  // synthetic, loopback-only and default OFF; no production middleware is
  // registered and no configured database is used by these endpoints.
  getRequestEnforcementStatus: () =>
    apiRequest(mitigationPath("request-enforcement-demo", "status")),
  enableRequestEnforcementDemo: (body) =>
    apiRequest(mitigationPath("request-enforcement-demo", "enable"), {
      method: "POST",
      body,
    }),
  runRequestEnforcementDemo: (body) =>
    apiRequest(mitigationPath("request-enforcement-demo", "run"), {
      method: "POST",
      body,
    }),
  requestEnforcementKillSwitch: () =>
    apiRequest(mitigationPath("request-enforcement-demo", "kill-switch"), {
      method: "POST",
    }),
  requestEnforcementFailClosed: () =>
    apiRequest(mitigationPath("request-enforcement-demo", "fail-closed"), {
      method: "POST",
    }),
  getRequestEnforcementEvidence: () =>
    apiRequest(mitigationPath("request-enforcement-demo", "evidence")),
  disableRequestEnforcementDemo: (body) =>
    apiRequest(mitigationPath("request-enforcement-demo", "disable"), {
      method: "POST",
      body,
    }),
};
