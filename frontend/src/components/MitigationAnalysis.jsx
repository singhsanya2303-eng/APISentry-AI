import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  FileWarning,
  LoaderCircle,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldOff,
  SlidersHorizontal,
} from "lucide-react";
import { securityApis } from "../services/api";
import "./MitigationAnalysis.css";

// Fixed enforcement-safety statements. The endpoint never returns enforcement
// results, so these statements are unconditional and never replaced by a run.
const ADVISORY_BANNER = "ADVISORY ONLY — ENFORCEMENT IS DISABLED.";
const ADVISORY_DETAIL =
  "No request is blocked, throttled, banned, or challenged by this analysis.";
const NO_POLICY_MESSAGE =
  "No active mitigation policy is configured. Mitigation decisions are currently unavailable.";

const STATUS_LABELS = {
  persisted: "Persisted",
  idempotent_reuse: "Idempotent reuse",
  policy_unavailable: "Policy unavailable",
  decision_not_persisted: "Decision not persisted",
  conflict: "Conflict",
};

const STATUS_TONES = {
  persisted: "ok",
  idempotent_reuse: "ok",
  policy_unavailable: "warn",
  decision_not_persisted: "warn",
  conflict: "warn",
};

// Recommendations only. These labels never describe an executed action.
const DECISION_LABELS = {
  allow: "Allow (recommendation)",
  monitor: "Monitor (recommendation)",
  throttle: "Throttle (recommendation)",
  block: "Block (recommendation)",
};

const DECISION_TONES = {
  allow: "calm",
  monitor: "info",
  throttle: "warn",
  block: "critical",
};

const CLASSIFICATION_LABELS = {
  human_like: "Human-like",
  automation_benign_candidate: "Benign automation candidate",
  automation_suspicious: "Suspicious automation",
  unknown: "Unknown",
};

const DEFAULT_FILTERS = {
  start_time: "",
  end_time: "",
  method: "",
  path: "",
  status_code: "",
  client_ip: "",
  include_behavioral_risk: false,
  page: "1",
  page_size: "200",
  max_records: "1000",
};

function safeMessage(error, fallback) {
  const match = error instanceof Error ? /^HTTP (\d{3}):/.exec(error.message) : null;
  const status = match ? Number(match[1]) : null;

  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return "Your account does not have permission to use this module.";
  if (status === 422) return "One or more filters are invalid. Review them and try again.";
  if (status === 500) return "The server could not complete the analysis. Please try again later.";
  if (status !== null) return "The request could not be completed. Please try again later.";
  if (error instanceof TypeError) return "Unable to reach the API. Check your connection and try again.";
  return fallback;
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? String(number) : "—";
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function isoBound(value, label) {
  if (!value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`Enter a valid ${label}.`);
  return date.toISOString();
}

function boundedInteger(value, label, min, max) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new Error(`${label} must be a whole number between ${min} and ${max}.`);
  }
  return number;
}

function buildParams(filters) {
  const params = {};
  const start = isoBound(filters.start_time, "start time");
  const end = isoBound(filters.end_time, "end time");
  if (start && end && new Date(start) > new Date(end)) {
    throw new Error("Start time must be earlier than or equal to end time.");
  }
  if (start) params.start_time = start;
  if (end) params.end_time = end;

  if (filters.method.trim()) params.method = filters.method.trim().toUpperCase();
  if (filters.path.trim()) params.path = filters.path.trim();
  if (filters.client_ip.trim()) params.client_ip = filters.client_ip.trim();

  if (filters.status_code !== "") {
    const code = Number(filters.status_code);
    if (!Number.isInteger(code) || code < 100 || code > 599) {
      throw new Error("Status code must be a whole number between 100 and 599.");
    }
    params.status_code = code;
  }

  // Explicit booleans are intentional; apiRequest preserves false values.
  params.include_behavioral_risk = filters.include_behavioral_risk;
  params.page = boundedInteger(filters.page, "Page", 1, 100000);
  params.page_size = boundedInteger(filters.page_size, "Page size", 1, 500);
  params.max_records = boundedInteger(filters.max_records, "Maximum records", 1, 5000);
  return params;
}

function Stat({ label, value, hint, tone }) {
  return (
    <div className={`mit-stat${tone ? ` ${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </div>
  );
}

export default function MitigationAnalysis() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const [runtimeResult, setRuntimeResult] = useState(null);
  const [runtimeError, setRuntimeError] = useState("");
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [runtimeHasRun, setRuntimeHasRun] = useState(false);

  const detection =
    result?.detection && typeof result.detection === "object" ? result.detection : {};
  const mitigation =
    result?.mitigation && typeof result.mitigation === "object" ? result.mitigation : {};
  const outcomes = Array.isArray(mitigation.outcomes) ? mitigation.outcomes : [];
  const detectionResults = Array.isArray(detection.results) ? detection.results : [];
  const policyVersion =
    typeof mitigation.policy_version === "string" && mitigation.policy_version.trim()
      ? mitigation.policy_version
      : null;

  const counts = {
    persisted: 0,
    idempotent_reuse: 0,
    policy_unavailable: 0,
    decision_not_persisted: 0,
    conflict: 0,
  };
  outcomes.forEach((outcome) => {
    if (outcome && Object.prototype.hasOwnProperty.call(counts, outcome.status)) {
      counts[outcome.status] += 1;
    }
  });

  const policyUnavailable =
    policyVersion === null || counts.policy_unavailable > 0;
  const persistenceIssues = counts.decision_not_persisted + counts.conflict;
  const isEmptyTraffic =
    Number(detection.total_events_analyzed ?? 0) === 0 &&
    detectionResults.length === 0 &&
    outcomes.length === 0;

  const runtimeItems = Array.isArray(runtimeResult?.runtime_results) ? runtimeResult.runtime_results : [];
  const runtimeDetection = runtimeResult?.detection && typeof runtimeResult.detection === "object" ? runtimeResult.detection : null;
  const runtimeEmpty =
    runtimeHasRun &&
    !runtimeLoading &&
    !runtimeError &&
    Number(runtimeDetection?.total_events_analyzed ?? 0) === 0 &&
    runtimeItems.length === 0;

  function updateFilter(key, value) {
    setFilters((previous) => ({ ...previous, [key]: value }));
  }

  async function runAnalysis(event) {
    event.preventDefault();
    let params;
    try {
      params = buildParams(filters);
    } catch (validationError) {
      setError(validationError.message);
      setHasRun(true);
      return;
    }

    setLoading(true);
    setError("");
    try {
      const data = await securityApis.mitigation(params);
      setResult(data && typeof data === "object" ? data : null);
    } catch (requestError) {
      setResult(null);
      setError(safeMessage(requestError, "Mitigation analysis could not be completed."));
    } finally {
      setHasRun(true);
      setLoading(false);
    }
  }

  async function runRuntimeAnalysis() {
    let params;
    try {
      params = buildParams(filters);
    } catch (validationError) {
      setRuntimeError(validationError.message);
      setRuntimeHasRun(true);
      return;
    }

    setRuntimeLoading(true);
    setRuntimeError("");
    try {
      const data = await securityApis.mitigationRuntimeAnalyze(params);
      setRuntimeResult(data && typeof data === "object" ? data : null);
    } catch (requestError) {
      setRuntimeResult(null);
      setRuntimeError(safeMessage(requestError, "MW4 runtime analysis could not be completed."));
    } finally {
      setRuntimeHasRun(true);
      setRuntimeLoading(false);
    }
  }

  function resetAnalysis() {
    setFilters(DEFAULT_FILTERS);
    setResult(null);
    setError("");
    setHasRun(false);
    setLoading(false);
    setRuntimeResult(null);
    setRuntimeError("");
    setRuntimeHasRun(false);
    setRuntimeLoading(false);
  }

  return (
    <section className="mit-v2">
      <header className="mit-hero">
        <div className="mit-hero-top">
          <span className="mit-kicker"><ShieldOff size={13} /> BOT MITIGATION</span>
          <span className="mit-method">GET REQUEST</span>
        </div>
        <div className="mit-hero-main">
          <div className="mit-hero-icon"><ShieldOff size={24} /></div>
          <div>
            <h2>Bot Mitigation Analysis</h2>
            <p>Advisory policy decisions for stored bot-detection results. Nothing is enforced.</p>
          </div>
        </div>
        <div className="mit-route"><span /> <span>ENDPOINT</span> <code>/api/v1/security/mitigation/analyze</code></div>
      </header>

      <div className="mit-enforcement-banner" role="note">
        <ShieldAlert size={19} />
        <div>
          <strong>{ADVISORY_BANNER}</strong>
          <span>{ADVISORY_DETAIL}</span>
        </div>
      </div>

      <form className="mit-card mit-filter-card" onSubmit={runAnalysis}>
        <div className="mit-card-head">
          <div>
            <span className="mit-step">01 / FILTER</span>
            <h3>Traffic selection</h3>
            <p>The same optional filters are passed to detection and advisory mitigation.</p>
          </div>
          <SlidersHorizontal size={18} />
        </div>

        <div className="mit-filter-grid">
          <label>Start time<input type="datetime-local" value={filters.start_time} onChange={(event) => updateFilter("start_time", event.target.value)} /></label>
          <label>End time<input type="datetime-local" value={filters.end_time} onChange={(event) => updateFilter("end_time", event.target.value)} /></label>
          <label>HTTP method
            <select value={filters.method} onChange={(event) => updateFilter("method", event.target.value)}>
              <option value="">Any method</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
            </select>
          </label>
          <label>Status code<input type="number" min="100" max="599" placeholder="e.g. 401" value={filters.status_code} onChange={(event) => updateFilter("status_code", event.target.value)} /></label>
          <label>Path<input type="text" placeholder="/api/v1/orders" value={filters.path} onChange={(event) => updateFilter("path", event.target.value)} /></label>
          <label>Client IP<input type="text" placeholder="198.51.100.10" value={filters.client_ip} onChange={(event) => updateFilter("client_ip", event.target.value)} /></label>
          <label>Page<input type="number" min="1" value={filters.page} onChange={(event) => updateFilter("page", event.target.value)} /></label>
          <label>Page size <small>1–500</small><input type="number" min="1" max="500" value={filters.page_size} onChange={(event) => updateFilter("page_size", event.target.value)} /></label>
          <label>Max records <small>1–5000</small><input type="number" min="1" max="5000" value={filters.max_records} onChange={(event) => updateFilter("max_records", event.target.value)} /></label>
          <label className="mit-check"><input type="checkbox" checked={filters.include_behavioral_risk} onChange={(event) => updateFilter("include_behavioral_risk", event.target.checked)} /> Include behavioural context</label>
        </div>

        <div className="mit-actions">
          <button className="mit-run" type="submit" disabled={loading || runtimeLoading}>
            {loading ? <LoaderCircle className="mit-spin" size={16} /> : <Play size={15} fill="currentColor" />}
            {loading ? (hasRun ? "Refreshing…" : "Analyzing…") : "Apply filters"}
          </button>
          <button className="mit-run" type="button" onClick={runRuntimeAnalysis} disabled={loading || runtimeLoading}>
            {runtimeLoading ? <LoaderCircle className="mit-spin" size={16} /> : <Activity size={15} />}
            {runtimeLoading ? "Running MW4 runtime…" : "Run MW4 runtime analysis"}
          </button>
          <button className="mit-reset" type="button" onClick={resetAnalysis} disabled={loading || runtimeLoading}>
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </form>

      {loading ? (
        <div className="mit-card mit-placeholder">
          <LoaderCircle className="mit-spin" size={26} />
          <strong>{hasRun ? "Refreshing advisory analysis" : "Analyzing stored traffic"}</strong>
          <p>Waiting for detection and advisory mitigation results.</p>
        </div>
      ) : error ? (
        <div className="mit-card mit-error" role="alert">
          <AlertTriangle size={20} />
          <div>
            <strong>Analysis could not complete</strong>
            <p>{error}</p>
          </div>
        </div>
      ) : !hasRun ? (
        <div className="mit-card mit-placeholder">
          <Database size={24} />
          <strong>No analysis run yet</strong>
          <p>Apply the filters above to produce advisory mitigation decisions for stored traffic.</p>
        </div>
      ) : isEmptyTraffic ? (
        <div className="mit-card mit-empty">
          <Database size={24} />
          <strong>No stored traffic available</strong>
          <p>No stored traffic matched the selected filters, so no advisory decisions were produced. This is not an application failure — widen the filters or generate traffic first.</p>
        </div>
      ) : (
        <>
          {policyUnavailable && (
            <div className="mit-card mit-policy-state" role="status">
              <FileWarning size={19} />
              <div>
                <strong>Degraded state</strong>
                <p>{NO_POLICY_MESSAGE}</p>
                <small>Detection results may still be available below. No enforcement is affected.</small>
              </div>
            </div>
          )}

          {persistenceIssues > 0 && (
            <div className="mit-card mit-persistence-state" role="status">
              <AlertTriangle size={18} />
              <div>
                <strong>Decision persistence issue</strong>
                <p>
                  {formatNumber(counts.decision_not_persisted)} decision(s) were not persisted and {formatNumber(counts.conflict)} conflict(s) occurred. These outcomes are advisory only and were not saved as enforcement actions.
                </p>
              </div>
            </div>
          )}

          <div className="mit-card">
            <div className="mit-card-head">
              <div>
                <span className="mit-step">02 / OVERVIEW</span>
                <h3>Advisory outcome overview</h3>
                <p>Counts are derived only from outcomes returned by the API.</p>
              </div>
              <Activity size={18} />
            </div>
            <div className="mit-stats">
              <Stat label="Policy version" value={policyVersion || "Unavailable"} tone={policyVersion ? "" : "warn"} />
              <Stat label="Detection clients" value={formatNumber(detection.total_clients)} />
              <Stat label="Traffic events" value={formatNumber(detection.total_events_analyzed)} />
              <Stat label="Persisted" value={formatNumber(counts.persisted)} tone="ok" />
              <Stat label="Idempotent reuse" value={formatNumber(counts.idempotent_reuse)} tone="ok" />
              <Stat label="Policy unavailable" value={formatNumber(counts.policy_unavailable)} tone={counts.policy_unavailable ? "warn" : ""} />
              <Stat label="Not persisted" value={formatNumber(counts.decision_not_persisted)} tone={counts.decision_not_persisted ? "warn" : ""} />
              <Stat label="Conflicts" value={formatNumber(counts.conflict)} tone={counts.conflict ? "warn" : ""} />
            </div>
            <div className="mit-limit-note">
              <Ban size={13} />
              <span>Recommendations such as allow, monitor, throttle, and block are policy outputs only. No request is acted upon by this analysis.</span>
            </div>
          </div>

          <details className="mit-card mit-detection-summary">
            <summary>
              <ChevronRight size={14} />
              <span>Detection summary (from the nested response)</span>
              <small>{formatNumber(detectionResults.length)} client(s)</small>
            </summary>
            <div className="mit-detection-body">
              <div className="mit-detection-facts">
                <div><span>Clients analyzed</span><strong>{formatNumber(detection.total_clients)}</strong></div>
                <div><span>Traffic events</span><strong>{formatNumber(detection.total_events_analyzed)}</strong></div>
                <div><span>Records analyzed</span><strong>{formatNumber(detection.limits?.records_analyzed)}</strong></div>
                <div><span>Truncated</span><strong>{detection.limits?.truncated ? "Yes" : "No"}</strong></div>
                <div><span>Window start</span><strong>{formatTime(detection.analysis_window_start)}</strong></div>
                <div><span>Window end</span><strong>{formatTime(detection.analysis_window_end)}</strong></div>
              </div>
              {detectionResults.length ? (
                <div className="mit-detection-list">
                  {detectionResults.map((client, index) => {
                    const classification =
                      typeof client?.classification === "string" ? client.classification : "unknown";
                    return (
                      <div className="mit-detection-row" key={`${index}-${client?.client_ip || "client"}`}>
                        <span>{client?.client_ip || "Unattributed client"}</span>
                        <span>{CLASSIFICATION_LABELS[classification] || classification}</span>
                        <strong>{formatNumber(client?.bot_risk_score)}<small>/100</small></strong>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="mit-muted">No per-client detection results were returned.</p>
              )}
              <p className="mit-muted">This summary mirrors detection fields only. Scores are independent of any mitigation recommendation.</p>
            </div>
          </details>

          <div className="mit-card">
            <div className="mit-card-head">
              <div>
                <span className="mit-step">03 / DECISIONS</span>
                <h3>Advisory outcomes</h3>
                <p>Outcome status and recommended decision are shown separately. No decision is executed.</p>
              </div>
              <span className="mit-count">{outcomes.length} outcome{outcomes.length === 1 ? "" : "s"}</span>
            </div>

            {outcomes.length ? (
              <div className="mit-outcomes">
                {outcomes.map((outcome, index) => {
                  const status =
                    typeof outcome?.status === "string" ? outcome.status : "unknown";
                  const statusTone = STATUS_TONES[status] || "warn";
                  const decision = outcome?.decision && typeof outcome.decision === "object"
                    ? outcome.decision
                    : null;
                  const decisionType = decision && typeof decision.decision === "string"
                    ? decision.decision
                    : null;
                  const decisionTone = DECISION_TONES[decisionType] || "neutral";
                  const reasonCodes = Array.isArray(decision?.reason_codes)
                    ? decision.reason_codes
                    : [];
                  const evidenceReferences = Array.isArray(decision?.evidence_references)
                    ? decision.evidence_references
                    : [];

                  return (
                    <article className="mit-outcome" key={`${outcome?.result_index ?? index}-${index}`}>
                      <div className="mit-outcome-top">
                        <div className="mit-outcome-title">
                          <span className="mit-index">Result #{formatNumber(outcome?.result_index)}</span>
                          <span className={`mit-status ${statusTone}`}>{STATUS_LABELS[status] || status}</span>
                        </div>
                        <span className="mit-persist-note">
                          {status === "persisted"
                            ? "Decision record persisted"
                            : status === "idempotent_reuse"
                              ? "Existing decision record reused"
                              : "No new decision record persisted"}
                        </span>
                      </div>

                      {decision ? (
                        <>
                          <div className="mit-decision-line">
                            <span className="mit-decision-label">Recommended decision</span>
                            <span className={`mit-decision ${decisionTone}`}>
                              {DECISION_LABELS[decisionType] || decisionType || "Unspecified"}
                            </span>
                          </div>

                          <div className="mit-outcome-grid">
                            <div><span>Attribution status</span><strong>{decision.attribution_status || "—"}</strong></div>
                            <div><span>Verified attribution</span><strong>{decision.verified_attribution ? "Yes" : "No"}</strong></div>
                            <div><span>Scope type</span><strong>{decision.scope_type || "—"}</strong></div>
                            <div><span>Scope key</span><strong className="mit-hash">{decision.scope_key_hash || "Not attributed"}</strong></div>
                            <div><span>Issued at</span><strong>{formatTime(decision.issued_at)}</strong></div>
                            <div><span>Expires at</span><strong>{formatTime(decision.expires_at)}</strong></div>
                            {decision.rate_limit != null && (
                              <div><span>Advisory rate limit</span><strong>{formatNumber(decision.rate_limit)} req / {formatNumber(decision.rate_limit_window_seconds)} s</strong></div>
                            )}
                            {decision.policy_version && (
                              <div><span>Decision policy version</span><strong>{decision.policy_version}</strong></div>
                            )}
                          </div>

                          {decision.explanation && (
                            <p className="mit-explanation">{decision.explanation}</p>
                          )}

                          {reasonCodes.length > 0 && (
                            <div className="mit-code-block">
                              <span>Reason codes</span>
                              <div>{reasonCodes.map((code, codeIndex) => <code key={`${code}-${codeIndex}`}>{code}</code>)}</div>
                            </div>
                          )}

                          {evidenceReferences.length > 0 && (
                            <p className="mit-evidence-note">
                              {evidenceReferences.length} opaque evidence reference(s) returned. These are correlation values, not raw request IDs.
                            </p>
                          )}
                        </>
                      ) : (
                        <p className="mit-no-decision">
                          {status === "policy_unavailable"
                            ? "No advisory decision was produced because a policy was unavailable."
                            : "No decision was returned for this outcome."}
                        </p>
                      )}

                      {outcome?.decision_uuid && (
                        <p className="mit-uuid">Decision UUID: <code>{outcome.decision_uuid}</code></p>
                      )}
                    </article>
                  );
                })}
              </div>
            ) : (
              <p className="mit-muted">No advisory outcomes were returned for this request.</p>
            )}
          </div>
        </>
      )}

      <div className="mit-card">
        <div className="mit-card-head">
          <div>
            <span className="mit-step">04 / MW4 RUNTIME</span>
            <h3>MW4 Runtime Advisory Composition</h3>
            <p>Additive runtime endpoint: existing bot detection + MW2 advanced advisory signals + MW1 unified risk assessment. No combined score. No enforcement.</p>
          </div>
          <Activity size={18} />
        </div>
        <div className="mit-route"><span /> <span>ENDPOINT</span> <code>/api/v1/security/mitigation/runtime-analyze</code></div>

        {runtimeLoading ? (
          <div className="mit-placeholder" style={{ padding: "24px 0" }}>
            <LoaderCircle className="mit-spin" size={24} />
            <strong>Running MW4 runtime analysis</strong>
            <p>Composing MW2 advisory signals and MW1 unified risk assessment.</p>
          </div>
        ) : runtimeError ? (
          <div className="mit-error" role="alert" style={{ marginTop: 12 }}>
            <AlertTriangle size={20} />
            <div>
              <strong>Runtime analysis could not complete</strong>
              <p>{runtimeError}</p>
            </div>
          </div>
        ) : !runtimeHasRun ? (
          <div className="mit-placeholder" style={{ padding: "24px 0" }}>
            <Database size={22} />
            <strong>No runtime analysis run yet</strong>
            <p>Use "Run MW4 runtime analysis" to compose MW2 and MW1 advisory outputs for the selected traffic window.</p>
          </div>
        ) : runtimeEmpty ? (
          <div className="mit-empty" style={{ padding: "24px 0" }}>
            <Database size={22} />
            <strong>No stored traffic available for runtime analysis</strong>
            <p>No stored traffic matched the selected filters. This is not an application failure.</p>
          </div>
        ) : (
          <>
            <div className="mit-limit-note" style={{ marginTop: 12 }}>
              <ShieldAlert size={13} />
              <span>Advisory-only runtime composition. MW1 owns the 0-100 unified risk score; MW2 remains a separate advisory envelope. Missing/error/uncertain signals are shown explicitly. No request is blocked, throttled, or enforced here; request-time enforcement remains disabled outside the isolated harness.</span>
            </div>
            <div className="mit-stats" style={{ marginTop: 12 }}>
              <Stat label="Runtime results" value={formatNumber(runtimeItems.length)} />
              <Stat label="MW1 assessed" value={formatNumber(runtimeItems.filter((r) => r?.mw1_status === "assessed").length)} tone="ok" />
              <Stat label="MW1 errors" value={formatNumber(runtimeItems.filter((r) => r?.mw1_status === "error").length)} tone={runtimeItems.some((r) => r?.mw1_status === "error") ? "warn" : ""} />
              <Stat label="Advisory only" value={runtimeResult?.advisory_only ? "Yes" : "Unknown"} tone={runtimeResult?.advisory_only ? "ok" : "warn"} />
              <Stat label="Enforcement executed" value={runtimeResult?.enforcement_executed ? "Yes" : "No"} tone={runtimeResult?.enforcement_executed ? "warn" : "ok"} />
            </div>

            <div className="mit-outcomes" style={{ marginTop: 14 }}>
              {runtimeItems.map((item, index) => {
                const mw1 = item?.mw1_unified_assessment;
                const mw2 = item?.mw2_advanced_detection;
                const mw2Signals = Array.isArray(mw2?.signals) ? mw2.signals : [];
                const mw1Statuses = Array.isArray(mw1?.signal_statuses) ? mw1.signal_statuses : [];
                const mw1Coverage = mw1?.coverage && typeof mw1.coverage === "object" ? mw1.coverage : null;
                const mw1Contribs = Array.isArray(mw1?.contributions) ? mw1.contributions : [];
                const mw1Reasons = Array.isArray(mw1?.reasons) ? mw1.reasons : [];
                const mw1Uncertainty = Array.isArray(mw1?.uncertainty_notes) ? mw1.uncertainty_notes : [];
                return (
                  <article className="mit-outcome" key={`runtime-${item?.result_index ?? index}-${index}`}>
                    <div className="mit-outcome-top">
                      <div className="mit-outcome-title">
                        <span className="mit-index">Runtime #{formatNumber(item?.result_index ?? index)}</span>
                        <span className={`mit-status ${item?.mw1_status === "assessed" ? "ok" : "warn"}`}>MW1 {item?.mw1_status || "unknown"}</span>
                        <span className="mit-status ok">MW2 {mw2Signals.length} signal(s)</span>
                      </div>
                      <span className="mit-persist-note">Advisory only — no enforcement action</span>
                    </div>

                    <div className="mit-decision-line">
                      <span className="mit-decision-label">MW1 Unified Risk (owner of 0-100 score)</span>
                      <span className={`mit-decision ${mw1 ? (Number(mw1.risk_score) >= 70 ? "critical" : Number(mw1.risk_score) >= 40 ? "warn" : Number(mw1.risk_score) >= 20 ? "info" : "calm") : "neutral"}`}>
                        {mw1 ? `${formatNumber(mw1.risk_score)} / 100 (${mw1.severity || "unknown"})` : "Assessment unavailable"}
                      </span>
                    </div>

                    {item?.mw1_error && <p className="mit-no-decision">{item.mw1_error}</p>}

                    {mw1 && (
                      <>
                        <div className="mit-outcome-grid">
                          <div><span>Schema</span><strong>{mw1.schema_version || "—"}</strong></div>
                          <div><span>Advisory only</span><strong>{String(mw1.advisory_only)}</strong></div>
                          <div><span>Coverage</span><strong>{mw1Coverage ? `${formatNumber(mw1Coverage.signals_available)}/${formatNumber(mw1Coverage.signals_expected)} (${formatNumber(mw1Coverage.coverage_ratio)})` : "—"}</strong></div>
                          <div><span>Uncertainty notes</span><strong>{formatNumber(mw1Uncertainty.length)}</strong></div>
                        </div>
                        {mw1.advisory_notice && <p className="mit-explanation">{mw1.advisory_notice}</p>}
                        {mw1Statuses.length > 0 && (
                          <div className="mit-code-block">
                            <span>MW1 signal statuses</span>
                            <div>{mw1Statuses.map((s, si) => <code key={`${s?.signal}-${si}`}>{s?.signal}: {s?.status}{s?.reason_code ? ` (${s.reason_code})` : ""}</code>)}</div>
                          </div>
                        )}
                        {mw1Contribs.length > 0 && (
                          <div className="mit-code-block">
                            <span>MW1 contributions</span>
                            <div>{mw1Contribs.map((c, ci) => <code key={`${c?.signal}-${ci}`}>{c?.signal}: +{formatNumber(c?.points)} [{c?.category || "—"}] ({c?.status || "unknown"})</code>)}</div>
                          </div>
                        )}
                        {mw1Reasons.length > 0 && (
                          <div className="mit-code-block">
                            <span>MW1 reasons</span>
                            <div>{mw1Reasons.map((r, ri) => <code key={`${r?.code}-${ri}`}>{r?.code}</code>)}</div>
                          </div>
                        )}
                        {mw1Uncertainty.length > 0 && (
                          <div className="mit-code-block">
                            <span>MW1 uncertainty</span>
                            <div>{mw1Uncertainty.map((u, ui) => <code key={ui}>{u}</code>)}</div>
                          </div>
                        )}
                      </>
                    )}

                    <div className="mit-decision-line" style={{ marginTop: 14 }}>
                      <span className="mit-decision-label">MW2 Advanced Advisory Signals (separate envelope; no combined score)</span>
                      <span className="mit-decision info">{formatNumber(mw2Signals.length)} signal(s)</span>
                    </div>
                    {mw2Signals.length > 0 ? (
                      <div className="mit-outcomes" style={{ marginTop: 10 }}>
                        {mw2Signals.map((sig, si) => {
                          const refs = Array.isArray(sig?.evidence_refs) ? sig.evidence_refs : [];
                          return (
                            <div className="mit-outcome" key={`${sig?.signal_name || "sig"}-${si}`} style={{ padding: 12 }}>
                              <div className="mit-outcome-top">
                                <div className="mit-outcome-title">
                                  <span className="mit-index">{sig?.signal || "unknown_signal"}</span>
                                  <span className={`mit-status ${sig?.status === "AVAILABLE" || sig?.status === "available" ? "ok" : "warn"}`}>{sig?.status || "unknown"}</span>
                                </div>
                                <span className="mit-persist-note">{sig?.advisory_only ? "Advisory only" : "Advisory"}</span>
                              </div>
                              <div className="mit-outcome-grid">
                                <div><span>Severity</span><strong>{sig?.severity || "—"}</strong></div>
                                <div><span>Bounded contribution</span><strong>{formatNumber(sig?.points)}</strong></div>
                                <div><span>Source confidence</span><strong>{formatNumber(sig?.source_confidence)}</strong></div>
                                <div><span>Coverage note</span><strong>{sig?.coverage_note || "—"}</strong></div>
                                <div><span>Evidence refs</span><strong>{formatNumber(refs.length)} (opaque)</strong></div>
                              </div>
                              {sig?.explanation && <p className="mit-explanation">{sig.explanation}</p>}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="mit-no-decision">No MW2 signals returned for this result.</p>
                    )}
                  </article>
                );
              })}
            </div>
            {runtimeResult?.uncertainty && (
              <div className="mit-code-block" style={{ marginTop: 12 }}>
                <span>Runtime uncertainty/provenance (non-sensitive)</span>
                <div>
                  <code>coverage: {String(runtimeResult.uncertainty.coverage_note || "—")}</code>
                  <code>mw1_statuses: {Array.isArray(runtimeResult.uncertainty.mw1_result_statuses) ? runtimeResult.uncertainty.mw1_result_statuses.join(", ") : "—"}</code>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <footer className="mit-footer">
        <CheckCircle2 size={14} />
        <div>
          <strong>{ADVISORY_BANNER}</strong>
          <span>{ADVISORY_DETAIL}</span>
        </div>
        <span className="mit-footer-time"><Clock3 size={12} /> Results reflect the latest completed analysis</span>
      </footer>
    </section>
  );
}
