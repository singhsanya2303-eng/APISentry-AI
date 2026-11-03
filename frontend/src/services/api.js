
const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const API_KEY = import.meta.env.VITE_APISENTRY_API_KEY || "";

export async function apiRequest(
  path,
  { method = "GET", params, body } = {}
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

  if (API_KEY) headers["X-API-Key"] = API_KEY;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(url, {
    method,
    headers,
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
    throw new Error(
      `HTTP ${response.status}: ${
        data?.detail || response.statusText
      }`
    );
  }

  return data;
}

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
};
