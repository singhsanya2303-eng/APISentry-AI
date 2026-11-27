import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  LoaderCircle,
  Play,
  RotateCcw,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import { securityApis } from "../services/api";
import "./BotDetection.css";

// The API returns a 0-100 deterministic risk score. It is deliberately never
// described as a probability, confidence, or likelihood.
const ADVISORY =
  "Bot detection is advisory only. Detection scores and classifications do not automatically block or restrict requests.";

const CLASSIFICATION_LABELS = {
  human_like: "Human-like",
  automation_benign_candidate: "Benign automation candidate",
  automation_suspicious: "Suspicious automation",
  unknown: "Unknown",
};

const CLASSIFICATION_TONES = {
  human_like: "calm",
  automation_benign_candidate: "info",
  automation_suspicious: "warn",
  unknown: "neutral",
};

const SEVERITY_TONES = {
  info: "info",
  low: "calm",
  medium: "warn",
  high: "critical",
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

function formatWindow(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${number.toFixed(0)} s` : "—";
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

function Stat({ label, value, hint }) {
  return (
    <div className="bot-stat">
      <span>{label}</span>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </div>
  );
}

export default function BotDetection() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);

  const results = Array.isArray(result?.results) ? result.results : [];
  const summary =
    result?.summary && typeof result.summary === "object" ? result.summary : {};
  const limits =
    result?.limits && typeof result.limits === "object" ? result.limits : {};
  const isEmptyTraffic =
    results.length === 0 && Number(result?.total_events_analyzed ?? 0) === 0;

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
      const data = await securityApis.botDetection(params);
      setResult(data && typeof data === "object" ? data : null);
    } catch (requestError) {
      setResult(null);
      setError(safeMessage(requestError, "Bot detection could not be completed."));
    } finally {
      setHasRun(true);
      setLoading(false);
    }
  }

  function resetAnalysis() {
    setFilters(DEFAULT_FILTERS);
    setResult(null);
    setError("");
    setHasRun(false);
    setLoading(false);
  }

  return (
    <section className="bot-v2">
      <header className="bot-hero">
        <div className="bot-hero-top">
          <span className="bot-kicker"><Bot size={13} /> BOT DETECTION</span>
          <span className="bot-method">GET REQUEST</span>
        </div>
        <div className="bot-hero-main">
          <div className="bot-hero-icon"><Bot size={24} /></div>
          <div>
            <h2>Bot Detection</h2>
            <p>Evidence-based bot assessment of stored traffic. Scores are deterministic signals, not probabilities.</p>
          </div>
        </div>
        <div className="bot-route"><span /> <span>ENDPOINT</span> <code>/api/v1/security/bot/analyze</code></div>
      </header>

      <div className="bot-advisory" role="note">
        <ShieldAlert size={17} />
        <p>{ADVISORY}</p>
      </div>

      <form className="bot-card bot-filter-card" onSubmit={runAnalysis}>
        <div className="bot-card-head">
          <div>
            <span className="bot-step">01 / FILTER</span>
            <h3>Traffic selection</h3>
            <p>All filters are optional. Leave them blank to analyze recent stored traffic.</p>
          </div>
          <SlidersHorizontal size={18} />
        </div>

        <div className="bot-filter-grid">
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
          <label className="bot-check"><input type="checkbox" checked={filters.include_behavioral_risk} onChange={(event) => updateFilter("include_behavioral_risk", event.target.checked)} /> Include behavioural context</label>
        </div>
        <p className="bot-filter-note">Behavioural context is separately labelled and never contributes to the bot risk score.</p>

        <div className="bot-actions">
          <button className="bot-run" type="submit" disabled={loading}>
            {loading ? <LoaderCircle className="bot-spin" size={16} /> : <Play size={15} fill="currentColor" />}
            {loading ? (hasRun ? "Refreshing…" : "Analyzing…") : "Apply filters"}
          </button>
          <button className="bot-reset" type="button" onClick={resetAnalysis} disabled={loading}>
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </form>

      {loading ? (
        <div className="bot-card bot-placeholder">
          <LoaderCircle className="bot-spin" size={26} />
          <strong>{hasRun ? "Refreshing analysis" : "Analyzing stored traffic"}</strong>
          <p>Waiting for the backend to evaluate the selected traffic window.</p>
        </div>
      ) : error ? (
        <div className="bot-card bot-error" role="alert">
          <AlertTriangle size={20} />
          <div>
            <strong>Analysis could not complete</strong>
            <p>{error}</p>
          </div>
        </div>
      ) : !hasRun ? (
        <div className="bot-card bot-placeholder">
          <Database size={24} />
          <strong>No analysis run yet</strong>
          <p>Apply the filters above to analyze stored traffic with the bot detection engine.</p>
        </div>
      ) : isEmptyTraffic ? (
        <div className="bot-card bot-empty">
          <Database size={24} />
          <strong>No stored traffic available</strong>
          <p>No stored traffic matched the selected filters, so there was nothing to analyze. This is not an application failure — widen the filters or generate traffic first.</p>
        </div>
      ) : (
        <>
          <div className="bot-card">
            <div className="bot-card-head">
              <div>
                <span className="bot-step">02 / OVERVIEW</span>
                <h3>Analysis overview</h3>
                <p>
                  {result?.analysis_window_start || result?.analysis_window_end
                    ? `${formatTime(result?.analysis_window_start)} → ${formatTime(result?.analysis_window_end)}`
                    : "Derived from the returned analysis window"}
                </p>
              </div>
              <Activity size={18} />
            </div>
            <div className="bot-stats">
              <Stat label="Clients analyzed" value={formatNumber(result?.total_clients)} />
              <Stat label="Traffic events" value={formatNumber(result?.total_events_analyzed)} />
              <Stat label="Suspicious automation" value={formatNumber(summary.suspicious_automation_candidates)} />
              <Stat label="Benign automation" value={formatNumber(summary.benign_automation_candidates)} />
              <Stat label="Human-like" value={formatNumber(summary.human_like_clients)} />
              <Stat label="Unknown" value={formatNumber(summary.unknown_clients)} />
              <Stat label="Records analyzed" value={formatNumber(limits.records_analyzed)} hint={limits.truncated ? "Results truncated at max records" : "Complete within limits"} />
              {typeof summary.brute_force_override_count === "number" && (
                <Stat label="Brute-force overrides" value={formatNumber(summary.brute_force_override_count)} />
              )}
            </div>
            {typeof summary.malformed_records_skipped === "number" && summary.malformed_records_skipped > 0 && (
              <p className="bot-note"><AlertTriangle size={13} /> {summary.malformed_records_skipped} malformed record(s) were skipped during analysis.</p>
            )}
            {summary.summary && <p className="bot-summary-text">{summary.summary}</p>}
          </div>

          <div className="bot-card">
            <div className="bot-card-head">
              <div>
                <span className="bot-step">03 / RESULTS</span>
                <h3>Client assessments</h3>
                <p>Expand a client to inspect the supporting evidence and score factors.</p>
              </div>
              <span className="bot-count">{results.length} client{results.length === 1 ? "" : "s"}</span>
            </div>

            <div className="bot-clients">
              {results.map((client, index) => {
                const classification = typeof client?.classification === "string" ? client.classification : "unknown";
                const tone = CLASSIFICATION_TONES[classification] || "neutral";
                const score = Number(client?.bot_risk_score);
                const safeScore = Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0;
                const reasons = Array.isArray(client?.reasons) ? client.reasons : [];
                const factors = Array.isArray(client?.score_factors) ? client.score_factors : [];
                const references = Array.isArray(client?.evidence_references) ? client.evidence_references : [];

                return (
                  <article className="bot-client" key={`${index}-${client?.client_ip || "client"}`}>
                    <div className="bot-client-top">
                      <div className="bot-client-identity">
                        <strong>{client?.client_ip || "Unattributed client"}</strong>
                        <span className={`bot-badge ${tone}`}>{CLASSIFICATION_LABELS[classification] || classification}</span>
                      </div>
                      <div className="bot-score-block">
                        <div className="bot-score-track"><span className={tone} style={{ width: `${safeScore}%` }} /></div>
                        <span className="bot-score-value">{formatNumber(client?.bot_risk_score)}<small>/100</small></span>
                      </div>
                    </div>
                    <p className="bot-score-note">Risk score is a 0–100 signal, not a probability.</p>

                    <dl className="bot-facts">
                      <div><dt>Requests</dt><dd>{formatNumber(client?.request_count)}</dd></div>
                      <div><dt>First seen</dt><dd>{formatTime(client?.first_seen)}</dd></div>
                      <div><dt>Last seen</dt><dd>{formatTime(client?.last_seen)}</dd></div>
                      <div><dt>Observation window</dt><dd>{formatWindow(client?.observation_window_seconds)}</dd></div>
                      {client?.actor_id && <div><dt>Actor context</dt><dd>{client.actor_id}</dd></div>}
                    </dl>
                    {client?.summary && <p className="bot-client-summary">{client.summary}</p>}

                    <details className="bot-evidence">
                      <summary><ChevronRight size={14} /> Explain this result <span>{reasons.length + factors.length} signal(s)</span></summary>
                      <div className="bot-evidence-body">
                        <h4>Reasons</h4>
                        {reasons.length ? (
                          <div className="bot-reasons">
                            {reasons.map((reason, reasonIndex) => (
                              <div className="bot-reason" key={`${reason?.code || "reason"}-${reasonIndex}`}>
                                <div className="bot-reason-head">
                                  <span className={`bot-severity ${SEVERITY_TONES[reason?.severity] || "neutral"}`}>{reason?.severity || "info"}</span>
                                  <code>{reason?.code || "—"}</code>
                                  <span className="bot-category">{reason?.category || "—"}</span>
                                </div>
                                <p>{reason?.description || "—"}</p>
                                <div className="bot-reason-metrics">
                                  <span>Contribution: {formatNumber(reason?.score_contribution)} pts</span>
                                  <span>Evidence count: {formatNumber(reason?.evidence_count)}</span>
                                </div>
                                {Array.isArray(reason?.request_ids) && reason.request_ids.length > 0 && (
                                  <p className="bot-opaque">Opaque correlation references (not raw request IDs): {reason.request_ids.join(", ")}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="bot-muted">No structured reasons were returned for this client.</p>
                        )}

                        <h4>Score factors</h4>
                        {factors.length ? (
                          <ul className="bot-factors">
                            {factors.map((factor, factorIndex) => (
                              <li key={`${factor?.factor_name || "factor"}-${factorIndex}`}>
                                <strong>{factor?.factor_name || "—"}</strong>
                                <span>{formatNumber(factor?.contribution)} pts · {formatNumber(factor?.evidence_count)} observation(s)</span>
                                <p>{factor?.description || "—"}</p>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="bot-muted">No score factors were returned for this client.</p>
                        )}

                        <h4>Evidence references</h4>
                        {references.length ? (
                          <ul className="bot-references">
                            {references.map((reference, referenceIndex) => (
                              <li key={`${reference?.request_id || "ref"}-${referenceIndex}`}>
                                <code>{reference?.request_id || "—"}</code>
                                <span>{reference?.source || "—"}</span>
                                <span>{formatTime(reference?.observed_at)}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="bot-muted">No request-level evidence references were returned.</p>
                        )}
                        <p className="bot-muted">References are opaque correlation values. Raw request bodies, cookies, tokens, and client data are never returned by this endpoint.</p>
                      </div>
                    </details>
                  </article>
                );
              })}
            </div>
          </div>
        </>
      )}

      <footer className="bot-footer">
        <CheckCircle2 size={14} />
        <span>{ADVISORY}</span>
        <span className="bot-footer-time"><Clock3 size={12} /> Results reflect the latest completed analysis</span>
      </footer>
    </section>
  );
}
