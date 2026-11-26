// Pure helpers for the Gate D mitigation administration dashboard.
// No React, DOM, or network dependencies live here so these rules can be
// verified with the Node test runner without adding frontend dependencies.

export const MITIGATION_BASE_PATH = "/api/v1/security/mitigation";

export const POLICY_MODES = ["shadow", "monitor", "enforce"];
export const ACTIVATION_REASON_CODES = [
  "initial_activation",
  "policy_version_change",
  "operator_review",
  "configuration_review",
  "policy_deactivation",
];
export const BOT_CLASSIFICATIONS = [
  "human_like",
  "automation_benign_candidate",
  "automation_suspicious",
  "unknown",
];
export const ATTRIBUTION_STATUSES = [
  "verified_user",
  "api_key_principal",
  "network_ip",
  "inferred",
  "missing",
];
export const DECISION_TYPES = ["allow", "monitor", "throttle", "block"];
export const SCOPE_TYPES = [
  "verified_user",
  "api_key_principal",
  "network_ip",
  "unattributed",
];
export const AUDIT_EVENT_TYPES = [
  "policy_activated",
  "policy_deactivated",
  "policy_version_changed",
  "decision_issued",
  "decision_expired",
  "enforcement_applied_reserved",
  "enforcement_removed_reserved",
];
export const AUDIT_ENTITY_TYPES = ["policy", "decision"];

const LIFECYCLE_ERROR_CODES = new Set([
  "validation_error",
  "unsupported_action",
  "unauthorized",
  "policy_not_found",
  "version_conflict",
  "policy_already_active",
  "policy_not_active",
  "policy_disabled",
  "policy_configuration_invalid",
  "policy_expired",
  "policy_not_yet_valid",
  "invalid_transition",
  "evaluation_failed",
  "persistence_validation_error",
  "persistence_conflict",
]);

const SHA256_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const SENSITIVE_KEY_PATTERN = /token|secret|password|credential|cookie|authorization|api[_-]?key|dsn|connection/i;

export const DEFAULT_POLICY_FORM = {
  policy_version: "1.0.0",
  enabled: true,
  mode: "monitor",
  monitoring_score_threshold: "25",
  throttling_score_threshold: "75",
  blocking_score_threshold: "90",
  minimum_authentication_failures: "5",
  require_grouped_brute_force: true,
  throttle_enabled: false,
  throttle_limit: "60",
  throttle_window_seconds: "60",
  throttle_duration_seconds: "300",
  block_enabled: false,
  block_duration_seconds: "900",
  max_block_duration_seconds: "3600",
  admin_protection_enabled: true,
  max_evidence_references: "25",
  created_at: "",
  valid_from: "",
  valid_until: "",
  predecessor_version: "",
};

export const DEFAULT_ACTION_FORM = {
  at: "",
  expectedMode: "omit",
  expectedVersion: "",
  version: "",
  reason_code: "initial_activation",
};

export const DEFAULT_DRY_RUN_FORM = {
  version: "",
  at: "",
  context_evaluated_at: "",
  route_class: "general_api",
  attribution_status: "missing",
  actor_key_hash: "",
  api_key_principal_hash: "",
  network_key_hash: "",
  inferred_actor_key_hash: "",
  detection_available: true,
  evidence_complete: true,
  include_detection: false,
  bot_risk_score: "0",
  bot_classification: "unknown",
  bot_summary: "Advisory evaluation input supplied by the operator.",
  idempotency_token: "",
};

export const DEFAULT_DECISION_FILTERS = {
  policy_version: "",
  decision_ref: "",
  decision_type: "",
  scope_type: "",
  from_time: "",
  to_time: "",
  limit: "50",
  offset: "0",
};

export const DEFAULT_AUDIT_FILTERS = {
  policy_version: "",
  decision_ref: "",
  event_type: "",
  entity_type: "",
  from_time: "",
  to_time: "",
  limit: "50",
  offset: "0",
};

export function canUseMitigationDashboard(role) {
  return role === "admin" || role === "analyst";
}

export function canManagePolicies(role) {
  return role === "admin";
}

export function safeErrorMessage(error, fallback) {
  const match = error instanceof Error ? /^HTTP (\d{3}):(.*)$/.exec(error.message) : null;
  const status = match ? Number(match[1]) : null;
  const detail = match ? match[2].trim() : "";

  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return "Your account does not have permission for this operation.";
  if (status === 404) return "The requested policy, decision, or event was not found.";
  if (status === 409) return "The policy state changed. Refresh and review the current version before retrying.";
  if (status === 500) return "The server could not complete the request. Please try again later.";
  if (status !== null) {
    const lifecycleMatch = /^([a-z_]+):\s*(.+)$/.exec(detail);
    if (lifecycleMatch && LIFECYCLE_ERROR_CODES.has(lifecycleMatch[1])) {
      return truncate(lifecycleMatch[2], 240);
    }
    return "The request was rejected. Review your input and try again.";
  }
  if (error instanceof TypeError) return "Unable to reach the API. Check your connection and try again.";
  return fallback;
}

export function truncate(value, maxLength) {
  const text = String(value ?? "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 1)}…`;
}

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

export function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? String(number) : "—";
}

export function shortRef(value, length = 18) {
  if (typeof value !== "string" || !value) return "—";
  if (value.length <= length) return value;
  const head = Math.ceil((length - 1) / 2);
  const tail = Math.floor((length - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function labelize(value) {
  if (typeof value !== "string" || !value) return "—";
  return value.replace(/_/g, " ").replace(/^\w/, (char) => char.toUpperCase());
}

export function toIso(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Enter ${label}.`);
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`Enter a valid ${label}.`);
  return date.toISOString();
}

export function optionalIso(value, label) {
  if (value === undefined || value === null || value === "") return undefined;
  return toIso(value, label);
}

export function nowLocalInput() {
  const now = new Date();
  const offset = now.getTimezoneOffset() * 60000;
  return new Date(now.getTime() - offset).toISOString().slice(0, 16);
}

function requiredText(value, label, maxLength = 64) {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) throw new Error(`Enter ${label}.`);
  if (text.length > maxLength) throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  return text;
}

function boundedNumber(value, label, min, max, { integer = false } = {}) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`${label} must be a number.`);
  if (integer && !Number.isInteger(number)) throw new Error(`${label} must be a whole number.`);
  if (number < min || number > max) {
    throw new Error(`${label} must be between ${min} and ${max}.`);
  }
  return number;
}

function enumValue(value, allowed, label) {
  if (!allowed.includes(value)) throw new Error(`Choose a valid ${label}.`);
  return value;
}

function booleanValue(value) {
  return value === true || value === "true";
}

export function buildCreatePolicyPayload(form) {
  if (!form || typeof form !== "object") throw new Error("Complete the policy form.");

  const config = {
    enabled: booleanValue(form.enabled),
    mode: enumValue(form.mode, POLICY_MODES, "policy mode"),
    policy_version: requiredText(form.policy_version, "a policy version"),
    monitoring_score_threshold: boundedNumber(form.monitoring_score_threshold, "Monitoring threshold", 0, 100),
    throttling_score_threshold: boundedNumber(form.throttling_score_threshold, "Throttling threshold", 0, 100),
    blocking_score_threshold: boundedNumber(form.blocking_score_threshold, "Blocking threshold", 0, 100),
    minimum_authentication_failures: boundedNumber(
      form.minimum_authentication_failures,
      "Minimum authentication failures",
      1,
      1000,
      { integer: true }
    ),
    require_grouped_brute_force: booleanValue(form.require_grouped_brute_force),
    throttle_enabled: booleanValue(form.throttle_enabled),
    throttle_limit: boundedNumber(form.throttle_limit, "Throttle limit", 1, 100000, { integer: true }),
    throttle_window_seconds: boundedNumber(form.throttle_window_seconds, "Throttle window", 1, 86400, { integer: true }),
    throttle_duration_seconds: boundedNumber(form.throttle_duration_seconds, "Throttle duration", 1, 86400, { integer: true }),
    block_enabled: booleanValue(form.block_enabled),
    block_duration_seconds: boundedNumber(form.block_duration_seconds, "Block duration", 1, 86400, { integer: true }),
    max_block_duration_seconds: boundedNumber(form.max_block_duration_seconds, "Maximum block duration", 1, 604800, { integer: true }),
    admin_protection_enabled: booleanValue(form.admin_protection_enabled),
    max_evidence_references: boundedNumber(form.max_evidence_references, "Maximum evidence references", 0, 200, { integer: true }),
  };

  if (
    !(
      0 <= config.monitoring_score_threshold &&
      config.monitoring_score_threshold <= config.throttling_score_threshold &&
      config.throttling_score_threshold <= config.blocking_score_threshold &&
      config.blocking_score_threshold <= 100
    )
  ) {
    throw new Error("Thresholds must satisfy 0 ≤ monitoring ≤ throttling ≤ blocking ≤ 100.");
  }
  if (config.max_block_duration_seconds < config.block_duration_seconds) {
    throw new Error("Maximum block duration must be greater than or equal to block duration.");
  }

  const body = {
    config,
    created_at: toIso(form.created_at, "creation time"),
  };

  const validFrom = optionalIso(form.valid_from, "valid-from time");
  const validUntil = optionalIso(form.valid_until, "valid-until time");
  if (validFrom) body.valid_from = validFrom;
  if (validUntil) body.valid_until = validUntil;
  if (validFrom && validUntil && new Date(validFrom) > new Date(validUntil)) {
    throw new Error("Valid-from must be earlier than or equal to valid-until.");
  }
  if (form.predecessor_version) {
    body.predecessor_version = requiredText(form.predecessor_version, "a predecessor version");
  }
  return body;
}

export function buildPolicyActionPayload(form, action) {
  const allowed = ["validate", "activate", "deactivate", "retire", "rollback"];
  if (!allowed.includes(action)) throw new Error("Unsupported lifecycle action.");
  if (!form || typeof form !== "object") throw new Error("Complete the lifecycle form.");

  const body = { at: toIso(form.at, "action time") };

  if (action === "validate" || action === "retire") return body;

  if (action === "activate" || action === "deactivate" || action === "rollback") {
    if (form.expectedMode === "null") {
      // Explicit null asserts that no policy is active. Omit means no assertion.
      body.expected_active_version = null;
    } else if (form.expectedMode === "version") {
      body.expected_active_version = requiredText(form.expectedVersion, "an expected active version");
    }
  }

  if (action === "activate") {
    body.reason_code = enumValue(form.reason_code, ACTIVATION_REASON_CODES, "activation reason");
  }
  if (action === "deactivate") {
    body.version = requiredText(form.version, "a policy version to deactivate");
    body.reason_code = enumValue(form.reason_code, ACTIVATION_REASON_CODES, "deactivation reason");
  }
  return body;
}

function validateHash(value, label) {
  if (!value) return undefined;
  const hash = requiredText(value, label, 71);
  if (!SHA256_HASH_PATTERN.test(hash)) {
    throw new Error(`${label} must use sha256:<64 lowercase hex characters>.`);
  }
  return hash;
}

export function buildDryRunPayload(form) {
  if (!form || typeof form !== "object") throw new Error("Complete the dry-run form.");

  const body = {
    version: requiredText(form.version, "a policy version"),
    at: toIso(form.at, "evaluation time"),
    dry_run: true,
  };

  const attributionStatus = enumValue(form.attribution_status, ATTRIBUTION_STATUSES, "attribution status");
  const context = {
    evaluated_at: toIso(form.context_evaluated_at, "context evaluation time"),
    route_class: requiredText(form.route_class || "general_api", "a route class", 100),
    is_control_plane: false,
    is_admin: false,
    attribution_status: attributionStatus,
    detection_available: booleanValue(form.detection_available),
    evidence_complete: booleanValue(form.evidence_complete),
  };

  const actorKeyHash = validateHash(form.actor_key_hash, "Actor key hash");
  const apiKeyPrincipalHash = validateHash(form.api_key_principal_hash, "API key principal hash");
  const networkKeyHash = validateHash(form.network_key_hash, "Network key hash");
  const inferredActorKeyHash = validateHash(form.inferred_actor_key_hash, "Inferred actor key hash");

  if (attributionStatus === "verified_user" && !actorKeyHash) {
    throw new Error("Verified-user attribution requires an actor key hash.");
  }
  if (attributionStatus === "api_key_principal" && !apiKeyPrincipalHash) {
    throw new Error("API-key principal attribution requires a principal hash.");
  }
  if (attributionStatus === "network_ip" && !networkKeyHash) {
    throw new Error("Network-IP attribution requires a network key hash.");
  }

  if (actorKeyHash) context.actor_key_hash = actorKeyHash;
  if (apiKeyPrincipalHash) context.api_key_principal_hash = apiKeyPrincipalHash;
  if (networkKeyHash) context.network_key_hash = networkKeyHash;
  if (inferredActorKeyHash) context.inferred_actor_key_hash = inferredActorKeyHash;
  body.context = context;

  if (booleanValue(form.include_detection)) {
    body.detection_result = {
      bot_risk_score: boundedNumber(form.bot_risk_score, "Bot risk score", 0, 100),
      classification: enumValue(form.bot_classification, BOT_CLASSIFICATIONS, "bot classification"),
      summary: requiredText(form.bot_summary, "a detection summary", 2000),
    };
  }

  if (form.idempotency_token) {
    body.idempotency_token = requiredText(form.idempotency_token, "an idempotency token", 64);
  }
  return body;
}

function buildListParams(filters, kind) {
  if (!filters || typeof filters !== "object") throw new Error("Complete the filter form.");
  const params = {
    limit: boundedNumber(filters.limit, "Limit", 1, 200, { integer: true }),
    offset: boundedNumber(filters.offset, "Offset", 0, 1000000, { integer: true }),
  };

  const fromTime = optionalIso(filters.from_time, "start time");
  const toTime = optionalIso(filters.to_time, "end time");
  if (fromTime && toTime && new Date(fromTime) > new Date(toTime)) {
    throw new Error("Start time must be earlier than or equal to end time.");
  }

  const optionalText = (value, label, maxLength) => {
    if (!value) return undefined;
    return requiredText(value, label, maxLength);
  };

  const policyVersion = optionalText(filters.policy_version, "a policy version", 64);
  const decisionRef = optionalText(filters.decision_ref, "a decision reference", 128);
  if (policyVersion) params.policy_version = policyVersion;
  if (decisionRef) params.decision_ref = decisionRef;
  if (fromTime) params.from_time = fromTime;
  if (toTime) params.to_time = toTime;

  if (kind === "decisions") {
    if (filters.decision_type) params.decision_type = enumValue(filters.decision_type, DECISION_TYPES, "decision type");
    if (filters.scope_type) params.scope_type = enumValue(filters.scope_type, SCOPE_TYPES, "scope type");
  } else if (kind === "audit") {
    if (filters.event_type) params.event_type = enumValue(filters.event_type, AUDIT_EVENT_TYPES, "event type");
    if (filters.entity_type) params.entity_type = enumValue(filters.entity_type, AUDIT_ENTITY_TYPES, "entity type");
  }
  return params;
}

export function buildDecisionParams(filters) {
  return buildListParams(filters, "decisions");
}

export function buildAuditParams(filters) {
  return buildListParams(filters, "audit");
}

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function numberField(value, fallback = 0) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

export function parsePolicyList(data) {
  const object = asObject(data);
  if (!object || !Array.isArray(object.versions) || !Array.isArray(object.policies)) {
    throw new Error("The API returned an unexpected policy list.");
  }
  return {
    activeVersion: typeof object.active_version === "string" ? object.active_version : null,
    versions: object.versions.filter((item) => typeof item === "string"),
    policies: object.policies.filter(asObject),
  };
}

export function parseActivePolicy(data) {
  const object = asObject(data);
  if (!object || !("active_version" in object) || !("policy" in object)) {
    throw new Error("The API returned an unexpected active-policy response.");
  }
  return {
    activeVersion: typeof object.active_version === "string" ? object.active_version : null,
    policy: asObject(object.policy),
  };
}

export function parsePolicyDetail(data) {
  const object = asObject(data);
  if (!object || typeof object.policy_version !== "string") {
    throw new Error("The API returned an unexpected policy detail response.");
  }
  return object;
}

export function parseEnforcementStatus(data) {
  const object = asObject(data);
  if (!object || typeof object.enforcement_active !== "boolean") {
    throw new Error("The API returned an unexpected lifecycle status response.");
  }
  return {
    enforcementActive: object.enforcement_active,
    advisoryOnly: object.advisory_only === true,
    activeVersion: typeof object.active_version === "string" ? object.active_version : null,
    policyAvailable: object.policy_available === true,
    policyMode: typeof object.policy_mode === "string" ? object.policy_mode : null,
    persistedActiveVersion: typeof object.persisted_active_version === "string" ? object.persisted_active_version : null,
    activationEventCount: Number.isFinite(Number(object.activation_event_count)) ? Number(object.activation_event_count) : null,
    latestActivationEventType: typeof object.latest_activation_event_type === "string" ? object.latest_activation_event_type : null,
  };
}

export function parseDecisionDetail(data) {
  const object = asObject(data);
  if (!object || typeof object.decision_uuid !== "string") {
    throw new Error("The API returned an unexpected decision detail response.");
  }
  return object;
}

export function parseAuditDetail(data) {
  const object = asObject(data);
  if (!object || typeof object.event_uuid !== "string") {
    throw new Error("The API returned an unexpected audit event detail response.");
  }
  return object;
}

export function parseDecisionList(data) {
  const object = asObject(data);
  if (!object || !Array.isArray(object.items)) {
    throw new Error("The API returned an unexpected decision list.");
  }
  return {
    items: object.items.filter(asObject),
    total: numberField(object.total),
    limit: numberField(object.limit, 50),
    offset: numberField(object.offset),
  };
}

export function parseAuditList(data) {
  const object = asObject(data);
  if (!object || !Array.isArray(object.items)) {
    throw new Error("The API returned an unexpected audit event list.");
  }
  return {
    items: object.items.filter(asObject),
    total: numberField(object.total),
    limit: numberField(object.limit, 50),
    offset: numberField(object.offset),
  };
}

export function parseDryRunResult(data) {
  const object = asObject(data);
  if (!object || typeof object.ok !== "boolean") {
    throw new Error("The API returned an unexpected dry-run response.");
  }
  return {
    ok: object.ok,
    decision: asObject(object.decision),
    error: asObject(object.error),
    auditEvent: asObject(object.audit_event),
  };
}

export function lifecycleTone(state) {
  const tones = {
    ACTIVE: "ok",
    VALIDATED: "info",
    PROPOSED: "neutral",
    INACTIVE: "warn",
    RETIRED: "warn",
    ROLLED_BACK: "warn",
  };
  return tones[state] || "neutral";
}

export function decisionTone(value) {
  const tones = { allow: "calm", monitor: "info", throttle: "warn", block: "critical" };
  return tones[value] || "neutral";
}

export function safeDetailEntries(details) {
  const object = asObject(details);
  if (!object) return [];
  return Object.entries(object)
    .filter(([key, value]) => {
      if (SENSITIVE_KEY_PATTERN.test(key)) return false;
      return value === null || ["string", "number", "boolean"].includes(typeof value);
    })
    .slice(0, 12)
    .map(([key, value]) => [key, truncate(value === null ? "—" : String(value), 160)]);
}

export function nextVersion(value) {
  const text = typeof value === "string" ? value.trim() : "";
  const parts = text.split(".");
  if (parts.length === 3 && parts.every((part) => /^\d+$/.test(part))) {
    const [major, minor, patch] = parts.map(Number);
    return `${major}.${minor}.${patch + 1}`;
  }
  return truncate(`${text || "policy"}-next`, 64);
}

export function policyFormFrom(policy) {
  const config = asObject(policy?.config) || {};
  return {
    ...DEFAULT_POLICY_FORM,
    policy_version: nextVersion(config.policy_version || policy?.policy_version),
    enabled: config.enabled !== false,
    mode: POLICY_MODES.includes(config.mode) ? config.mode : "monitor",
    monitoring_score_threshold: String(config.monitoring_score_threshold ?? 25),
    throttling_score_threshold: String(config.throttling_score_threshold ?? 75),
    blocking_score_threshold: String(config.blocking_score_threshold ?? 90),
    minimum_authentication_failures: String(config.minimum_authentication_failures ?? 5),
    require_grouped_brute_force: config.require_grouped_brute_force !== false,
    throttle_enabled: config.throttle_enabled === true,
    throttle_limit: String(config.throttle_limit ?? 60),
    throttle_window_seconds: String(config.throttle_window_seconds ?? 60),
    throttle_duration_seconds: String(config.throttle_duration_seconds ?? 300),
    block_enabled: config.block_enabled === true,
    block_duration_seconds: String(config.block_duration_seconds ?? 900),
    max_block_duration_seconds: String(config.max_block_duration_seconds ?? 3600),
    admin_protection_enabled: config.admin_protection_enabled !== false,
    max_evidence_references: String(config.max_evidence_references ?? 25),
    created_at: nowLocalInput(),
    valid_from: "",
    valid_until: "",
    predecessor_version: typeof policy?.policy_version === "string" ? policy.policy_version : "",
  };
}

export function confirmationMessage(action, version) {
  const target = version ? ` "${version}"` : "";
  const messages = {
    activate: `Activate policy version${target}? This changes advisory lifecycle state only; no request enforcement is enabled.`,
    deactivate: `Deactivate policy version${target}? This changes advisory lifecycle state only; no request enforcement is disabled.`,
    retire: `Retire policy version${target}? The lifecycle state will change; no request enforcement is affected.`,
    rollback: `Roll back to policy version${target}? This changes advisory lifecycle state only; no request enforcement is enabled.`,
  };
  return messages[action] || "Confirm this lifecycle action?";
}

export const REQUEST_DEMO_CONFIRMATION = "ENABLE_ISOLATED_REQUEST_ENFORCEMENT_DEMO";

export const REQUEST_DEMO_SCENARIOS = ["allow", "block", "throttle"];

export const REQUEST_DEMO_AUDIT_KEYS = [
  "decision_ref",
  "selected_action",
  "enforcement_outcome",
  "advisory_only",
  "risk_score",
  "risk_severity",
  "risk_coverage_ratio",
  "mw1_status",
  "mw2_signal_count",
  "mw2_high_severity_count",
];

export function parseRequestEnforcementStatus(data) {
  const object = asObject(data);
  if (
    !object ||
    typeof object.demo_enabled !== "boolean" ||
    typeof object.enforcement_enabled !== "boolean" ||
    typeof object.production_middleware_registered !== "boolean"
  ) {
    throw new Error("The API returned an unexpected isolated enforcement status response.");
  }
  return {
    demoEnabled: object.demo_enabled,
    enforcementEnabled: object.enforcement_enabled,
    advisoryOnly: object.advisory_only === true,
    killSwitchActive: object.kill_switch_active === true,
    loopbackOnly: object.loopback_only === true,
    syntheticOnly: object.synthetic_only === true,
    productionMiddlewareRegistered: object.production_middleware_registered,
    realEnforcement: object.real_enforcement === true,
    demoId: typeof object.demo_id === "string" ? object.demo_id : null,
    scenario: typeof object.scenario === "string" ? object.scenario : null,
    policyVersion: typeof object.policy_version === "string" ? object.policy_version : null,
    maxRequests: numberField(object.max_requests),
    requestsExecuted: numberField(object.requests_executed),
    startedAt: typeof object.started_at === "string" ? object.started_at : null,
    decisionCount: numberField(object.decision_count),
    auditEventCount: numberField(object.audit_event_count),
    persistenceDb: typeof object.persistence_db === "string" ? object.persistence_db : "none",
    statusReason: typeof object.status_reason === "string" ? object.status_reason : "unknown",
    guards: asObject(object.guards) || {},
  };
}

export function requestEnforcementMode(status) {
  const s = asObject(status) || {};
  if (s.demoEnabled === false && s.enforcementEnabled === false) {
    return { label: "DISABLED / ADVISORY ONLY", tone: "success" };
  }
  if (s.killSwitchActive === true) {
    return { label: "KILL SWITCH ACTIVE (DEMO)", tone: "warn" };
  }
  if (s.enforcementEnabled === true && s.realEnforcement === false) {
    return { label: "ISOLATED ENFORCEMENT ON (DEMO)", tone: "warn" };
  }
  if (s.advisoryOnly === true) {
    return { label: "ADVISORY ONLY (DEMO)", tone: "success" };
  }
  return { label: "STATUS UNKNOWN", tone: "neutral" };
}

export function buildRequestEnforcementEnablePayload(form) {
  const f = asObject(form) || {};
  const confirmation = typeof f.confirmation === "string" ? f.confirmation.trim() : "";
  const demoId = typeof f.demo_id === "string" ? f.demo_id.trim() : "";
  const policyVersion = typeof f.policy_version === "string" ? f.policy_version.trim() : "";
  const scenario = typeof f.scenario === "string" ? f.scenario.trim() : "";
  const errors = {};
  const maxRequests = Number(f.max_requests);
  const maxDuration = Number(f.max_duration_seconds);

  if (confirmation !== REQUEST_DEMO_CONFIRMATION) errors.confirmation = `Confirmation must be ${REQUEST_DEMO_CONFIRMATION}.`;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(demoId)) errors.demo_id = "Demo ID must use 1-64 letters, numbers, hyphens or underscores.";
  if (!policyVersion) errors.policy_version = "Policy version is required.";
  if (!REQUEST_DEMO_SCENARIOS.includes(scenario)) errors.scenario = "Choose a supported synthetic scenario.";
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 50) errors.max_requests = "Max requests must be a whole number between 1 and 50.";
  if (!Number.isInteger(maxDuration) || maxDuration < 10 || maxDuration > 900) errors.max_duration_seconds = "Max duration must be a whole number between 10 and 900 seconds.";

  if (Object.keys(errors).length > 0) return { errors, payload: null };
  return {
    errors,
    payload: {
      confirmation,
      demo_id: demoId,
      policy_version: policyVersion,
      scenario,
      max_requests: maxRequests,
      max_duration_seconds: maxDuration,
      synthetic_only_ack: true,
      loopback_only_ack: true,
      isolated_db_ack: true,
    },
  };
}

export function parseRequestEnforcementRun(data) {
  const object = asObject(data);
  if (!object || !Array.isArray(object.outcomes) || !asObject(object.status)) {
    throw new Error("The API returned an unexpected isolated enforcement run response.");
  }
  return {
    demoId: typeof object.demo_id === "string" ? object.demo_id : "",
    scenario: typeof object.scenario === "string" ? object.scenario : "unknown",
    status: parseRequestEnforcementStatus(object.status),
    outcomes: object.outcomes.filter(asObject).map((item) => ({
      statusCode: numberField(item.status_code),
      action: typeof item.enforcement_action === "string" ? item.enforcement_action : "—",
      outcome: typeof item.enforcement_outcome === "string" ? item.enforcement_outcome : "—",
      handlerReached: item.handler_reached === true,
      decisionRef: typeof item.decision_ref === "string" ? item.decision_ref : null,
      requestRef: typeof item.request_ref === "string" ? item.request_ref : null,
    })),
  };
}

export function parseRequestEnforcementEvidence(data) {
  const object = asObject(data);
  if (!object || !Array.isArray(object.decisions) || !Array.isArray(object.audit_events)) {
    throw new Error("The API returned an unexpected isolated enforcement evidence response.");
  }
  return {
    decisionCount: numberField(object.decision_count),
    auditEventCount: numberField(object.audit_event_count),
    decisions: object.decisions.filter(asObject).map((item) => ({
      decisionRef: typeof item.decision_uuid === "string" ? item.decision_uuid : "—",
      decisionType: typeof item.decision_type === "string" ? item.decision_type : "—",
      issuedAt: typeof item.issued_at === "string" ? item.issued_at : null,
      advisoryOnly: item.advisory_only === true,
    })),
    auditEvents: object.audit_events.filter(asObject).map((item) => {
      const details = asObject(item.details) || {};
      return {
        eventRef: typeof item.event_uuid === "string" ? item.event_uuid : "—",
        eventType: typeof item.event_type === "string" ? item.event_type : "—",
        createdAt: typeof item.created_at === "string" ? item.created_at : null,
        details: REQUEST_DEMO_AUDIT_KEYS.filter((key) => Object.hasOwn(details, key))
          .map((key) => [key, details[key]])
          .map(([key, value]) => [key, typeof value === "object" ? "—" : truncate(String(value), 120)]),
      };
    }),
  };
}
