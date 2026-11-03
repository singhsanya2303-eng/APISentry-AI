import { useMemo, useState } from "react";
import {
  Activity, AlertTriangle, CheckCircle2, CircleHelp, Code2,
  Fingerprint, Gauge, LoaderCircle, LockKeyhole, Play, RotateCcw,
  ShieldAlert, ShieldCheck, Sparkles, Network, Clock3, Braces,
} from "lucide-react";
import "./AnalysisPanel.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const API_KEY = import.meta.env.VITE_APISENTRY_API_KEY || "";

const MODULES = {
  Clustering: { path: "/api/v1/security/clustering/analyze", method: "POST", description: "Compare traffic behavior and surface outlier patterns.", hint: "Use numeric feature rows with matching dimensions.", icon: Network },
  "Token Classification": { path: "/api/v1/security/token-classifier/predict", method: "POST", description: "Classify token usage from a set of behavioral signals.", hint: "Supply numeric features expected by the trained model.", icon: Fingerprint },
  "Traffic Trend": { path: "/api/v1/security/traffic-trends/analyze", method: "GET", description: "Compare a baseline traffic window against a target window.", hint: "The baseline must precede the target period.", icon: Activity },
  "Behavioral Risk": { path: "/api/v1/security/behavior/analyze", method: "GET", description: "Review traffic for suspicious behavioral patterns.", hint: "Uses the backend's current default analysis filters.", icon: ShieldCheck },
  "BOLA Detection": { path: "/api/v1/security/bola/analyze", method: "GET", description: "Inspect traffic for possible broken object-level authorization.", hint: "A finding is a signal for investigation, not proof of an attack.", icon: LockKeyhole },
  "Brute-Force": { path: "/api/v1/security/bruteforce/analyze", method: "GET", description: "Identify repeated authentication attempts and related signals.", hint: "Uses the backend's current default analysis filters.", icon: ShieldAlert },
  "Rate Anomaly": { path: "/api/v1/security/rate-anomaly/analyze", method: "GET", description: "Look for unusually high request-rate behavior.", hint: "Uses the backend's current default analysis filters.", icon: Gauge },
};

const DEFAULT_FEATURES = { requests_per_minute: 10, unique_ips: 2, failed_requests_ratio: 0.1, token_reuse_count: 1, geo_distance_km: 0 };
const DEFAULT_VECTORS = [[10, 2], [12, 2], [11, 3], [100, 20], [9, 2]];
const prettyJson = (value) => JSON.stringify(value, null, 2);
const localInput = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

function defaultWindows() {
  const targetEnd = new Date();
  const targetStart = new Date(targetEnd.getTime() - 60 * 60 * 1000);
  const baselineEnd = new Date(targetStart.getTime() - 1000);
  const baselineStart = new Date(baselineEnd.getTime() - 24 * 60 * 60 * 1000);
  return { baselineStart: localInput(baselineStart), baselineEnd: localInput(baselineEnd), targetStart: localInput(targetStart), targetEnd: localInput(targetEnd) };
}

export default function AnalysisPanel({ moduleName, onResult }) {
  const module = MODULES[moduleName];
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [windows, setWindows] = useState(defaultWindows);
  const [thresholdPercentile, setThresholdPercentile] = useState(95);
  const [featuresText, setFeaturesText] = useState(prettyJson(DEFAULT_FEATURES));
  const [vectorsText, setVectorsText] = useState(prettyJson(DEFAULT_VECTORS));
  const [contamination, setContamination] = useState(0.1);
  const [showRequest, setShowRequest] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  const isTrafficTrend = moduleName === "Traffic Trend";
  const isTokenClassifier = moduleName === "Token Classification";
  const isClustering = moduleName === "Clustering";
  const isSimpleGet = module?.method === "GET" && !isTrafficTrend;
  const requestPreview = useMemo(() => {
    if (!module) return "";
    if (isTokenClassifier) return prettyJson({ features: parseOrFallback(featuresText, DEFAULT_FEATURES) });
    if (isClustering) return prettyJson({ feature_vectors: parseOrFallback(vectorsText, DEFAULT_VECTORS), contamination: Number(contamination), random_state: 42 });
    if (isTrafficTrend) return prettyJson({ baseline_start: windows.baselineStart, baseline_end: windows.baselineEnd, target_start: windows.targetStart, target_end: windows.targetEnd, threshold_percentile: Number(thresholdPercentile) });
    return "GET request · no request body · default query filters";
  }, [module, isTokenClassifier, isClustering, isTrafficTrend, featuresText, vectorsText, contamination, windows, thresholdPercentile]);

  if (!module) return <section className="analysis-v2"><div className="av-empty"><CircleHelp /><span>Module not found: {moduleName}</span></div></section>;
  const ModuleIcon = module.icon;
  const updateWindow = (key, value) => setWindows((previous) => ({ ...previous, [key]: value }));

  async function runAnalysis(event) {
    event.preventDefault(); setLoading(true); setError(""); setResult(null); setShowRaw(false);
    try {
      const headers = { Accept: "application/json", ...(API_KEY ? { "X-API-Key": API_KEY } : {}) };
      let url = `${API_BASE}${module.path}`;
      const options = { method: module.method, headers };
      if (isTrafficTrend) {
        const dates = [windows.baselineStart, windows.baselineEnd, windows.targetStart, windows.targetEnd].map((v) => new Date(v));
        if (dates.some((date) => Number.isNaN(date.getTime()))) throw new Error("Enter valid dates for every traffic window.");
        if (!(dates[0] < dates[1] && dates[1] < dates[2] && dates[2] < dates[3])) throw new Error("Date order must be: baseline start < baseline end < target start < target end.");
        if (!(Number(thresholdPercentile) >= 1 && Number(thresholdPercentile) <= 100)) throw new Error("Threshold percentile must be between 1 and 100.");
        url += `?${new URLSearchParams({ baseline_start: dates[0].toISOString(), baseline_end: dates[1].toISOString(), target_start: dates[2].toISOString(), target_end: dates[3].toISOString(), threshold_percentile: String(Number(thresholdPercentile)) })}`;
      } else if (isTokenClassifier) {
        let features;
        try { features = JSON.parse(featuresText); } catch { throw new Error("Features must be valid JSON."); }
        if (!features || Array.isArray(features) || typeof features !== "object") throw new Error("Features must be a JSON object.");
        if (Object.values(features).some((v) => typeof v !== "number" || !Number.isFinite(v))) throw new Error("Every feature value must be a finite number.");
        headers["Content-Type"] = "application/json"; options.body = JSON.stringify({ features });
      } else if (isClustering) {
        let featureVectors;
        try { featureVectors = JSON.parse(vectorsText); } catch { throw new Error("Feature vectors must be valid JSON."); }
        if (!Array.isArray(featureVectors) || featureVectors.length < 3 || !featureVectors.every((row) => Array.isArray(row) && row.length > 0 && row.every((v) => typeof v === "number" && Number.isFinite(v)))) throw new Error("Enter at least three rows of numeric feature vectors.");
        if (!featureVectors.every((row) => row.length === featureVectors[0].length)) throw new Error("Every feature vector must have the same number of values.");
        if (!(Number(contamination) > 0 && Number(contamination) <= 0.5)) throw new Error("Contamination must be greater than 0 and at most 0.5.");
        headers["Content-Type"] = "application/json"; options.body = JSON.stringify({ feature_vectors: featureVectors, contamination: Number(contamination), random_state: 42 });
      }
      const response = await fetch(url, options);
      const responseText = await response.text();
      let data;
      try { data = responseText ? JSON.parse(responseText) : {}; } catch { data = { detail: responseText || "Empty server response" }; }
      if (!response.ok) {
        const detail = typeof data?.detail === "string" ? data.detail : Array.isArray(data?.detail) ? data.detail.map((item) => item.msg || JSON.stringify(item)).join("; ") : data?.message || `Request failed with HTTP ${response.status}`;
        throw new Error(detail);
      }
      setResult(data); setLastRun(new Date()); onResult?.(moduleName, data);
    } catch (runError) { setError(runError instanceof Error ? runError.message : "Unexpected error while running analysis."); }
    finally { setLoading(false); }
  }

  function resetForm() {
    setError(""); setResult(null); setLastRun(null); setWindows(defaultWindows()); setThresholdPercentile(95);
    setFeaturesText(prettyJson(DEFAULT_FEATURES)); setVectorsText(prettyJson(DEFAULT_VECTORS)); setContamination(0.1); setShowRaw(false);
  }

  const summaryItems = result ? getSummaryItems(result) : [];
  const anomalyCount = result && typeof result.anomaly_count === "number" ? result.anomaly_count : null;
  const hasFindings = result && [result.findings, result.alerts, result.incidents, result.anomalies, result.results, result.evidences].some((v) => Array.isArray(v) && v.length > 0);

  return (
    <section className="analysis-v2">
      <header className="av-hero">
        <div className="av-hero-orb av-orb-one" /><div className="av-hero-orb av-orb-two" />
        <div className="av-hero-top"><span className="av-kicker"><Sparkles size={13} /> SECURITY WORKBENCH</span><span className={`av-method ${module.method.toLowerCase()}`}>{module.method} REQUEST</span></div>
        <div className="av-hero-main"><div className="av-module-icon"><ModuleIcon size={25} /></div><div className="av-hero-copy"><h2>{moduleName}</h2><p>{module.description}</p></div></div>
        <div className="av-route"><span className="av-route-dot" /><span>ENDPOINT</span><code>{module.path}</code></div>
      </header>

      <div className="av-workspace">
        <form className="av-form-card" onSubmit={runAnalysis}>
          <div className="av-card-head"><div><span className="av-step">01 / CONFIGURE</span><h3>Analysis parameters</h3><p>Set the input values and run this detector.</p></div><div className="av-head-icon"><Braces size={19} /></div></div>

          {isClustering && <>
            <div className="av-field-block"><div className="av-label-row"><label htmlFor="av-vectors">Feature vectors</label><span className="av-mini-tag">JSON ARRAY</span></div><p className="av-field-help">Each row represents one observation. All rows must have the same dimensions.</p><textarea id="av-vectors" className="av-code-input" value={vectorsText} onChange={(e) => setVectorsText(e.target.value)} rows={7} spellCheck="false" /></div>
            <div className="av-field-block av-contamination"><div className="av-label-row"><label htmlFor="av-contamination">Expected outlier ratio</label><strong>{Math.round(Number(contamination) * 100)}%</strong></div><input id="av-contamination" type="range" min="0.01" max="0.5" step="0.01" value={contamination} onChange={(e) => setContamination(e.target.value)} /><div className="av-range-labels"><span>1% · Fewer outliers</span><span>50% · More outliers</span></div></div>
          </>}

          {isTokenClassifier && <div className="av-field-block"><div className="av-label-row"><label htmlFor="av-features">Token behavior features</label><span className="av-mini-tag">JSON OBJECT</span></div><p className="av-field-help">Edit the numeric signals sent to the trained classifier.</p><textarea id="av-features" className="av-code-input" value={featuresText} onChange={(e) => setFeaturesText(e.target.value)} rows={8} spellCheck="false" /><div className="av-helper-chips"><span>requests/min</span><span>unique IPs</span><span>failed ratio</span><span>token reuse</span></div></div>}

          {isTrafficTrend && <><div className="av-window-note"><Activity size={17} /><div><strong>Compare two traffic periods</strong><span>Choose a clean baseline, then the period you want to inspect.</span></div></div><div className="av-period-label"><span className="av-period-dot baseline" /> Baseline period <span className="av-period-caption">Known / reference traffic</span></div><div className="av-date-grid"><label>Start<input type="datetime-local" value={windows.baselineStart} onChange={(e) => updateWindow("baselineStart", e.target.value)} required /></label><label>End<input type="datetime-local" value={windows.baselineEnd} onChange={(e) => updateWindow("baselineEnd", e.target.value)} required /></label></div><div className="av-period-label"><span className="av-period-dot target" /> Target period <span className="av-period-caption">Traffic under review</span></div><div className="av-date-grid"><label>Start<input type="datetime-local" value={windows.targetStart} onChange={(e) => updateWindow("targetStart", e.target.value)} required /></label><label>End<input type="datetime-local" value={windows.targetEnd} onChange={(e) => updateWindow("targetEnd", e.target.value)} required /></label></div><div className="av-field-block av-threshold"><div className="av-label-row"><label htmlFor="av-threshold">Anomaly threshold percentile</label><strong>{thresholdPercentile}th</strong></div><input id="av-threshold" type="range" min="70" max="99" step="1" value={thresholdPercentile} onChange={(e) => setThresholdPercentile(e.target.value)} /><div className="av-range-labels"><span>70 · Sensitive</span><span>99 · Strict</span></div></div></>}

          {isSimpleGet && <div className="av-default-card"><div className="av-default-icon"><ShieldCheck size={19} /></div><div><strong>Default detector settings</strong><p>{module.hint}</p><span>GET · No request body</span></div></div>}

          <details className={`av-request-details ${showRequest ? "is-open" : ""}`} open={showRequest} onToggle={(e) => setShowRequest(e.currentTarget.open)}><summary><Code2 size={15} /> Inspect request payload <span>Optional</span></summary><pre>{requestPreview}</pre></details>
          {error && <div className="av-error" role="alert"><AlertTriangle size={19} /><div><strong>Analysis could not complete</strong><p>{error}</p></div></div>}
          <div className="av-form-footer"><button className="av-run" type="submit" disabled={loading}>{loading ? <LoaderCircle className="av-spin" size={17} /> : <Play size={16} fill="currentColor" />}{loading ? "Analyzing traffic…" : "Run analysis"}</button><button className="av-reset" type="button" onClick={resetForm} disabled={loading}><RotateCcw size={15} /> Reset</button><span className="av-secure-note"><ShieldCheck size={13} /> Local API request</span></div>
        </form>

        <section className="av-result-card">
          <div className="av-card-head"><div><span className="av-step">02 / INSPECT</span><h3>Detection output</h3><p>{lastRun ? `Completed at ${lastRun.toLocaleTimeString()}` : "Your API response will appear here."}</p></div><div className={`av-result-state ${result ? "success" : error ? "failed" : "idle"}`}><span />{result ? "COMPLETE" : error ? "FAILED" : loading ? "RUNNING" : "STANDBY"}</div></div>
          {loading ? <div className="av-output-empty av-loading-state"><LoaderCircle className="av-spin" size={29} /><strong>Analyzing request</strong><p>Waiting for the detector response from your backend.</p><div className="av-loading-track"><span /></div></div> : result ? <>
            <div className="av-result-summary"><div className="av-summary-top"><div className="av-summary-mark"><CheckCircle2 size={19} /></div><div><strong>Response received</strong><span>HTTP request completed successfully</span></div></div>
              {summaryItems.length ? <div className="av-summary-grid">{summaryItems.map((item) => <div className="av-summary-item" key={item.label}><span>{item.label}</span><strong>{String(item.value)}</strong></div>)}</div> : <div className="av-response-note"><Activity size={16} /><span>Response data received. Expand the raw response below to inspect all fields.</span></div>}
              {result.summary && <div className="av-findings-hint" style={{ marginTop: "0.5rem" }}><ShieldAlert size={14} /> {result.summary}</div>}
              {anomalyCount !== null && <div className={`av-finding-banner ${anomalyCount > 0 ? "warning" : "clear"}`}><span className="av-finding-icon">{anomalyCount > 0 ? <AlertTriangle size={17} /> : <CheckCircle2 size={17} />}</span><div><strong>{anomalyCount > 0 ? `${anomalyCount} anomal${anomalyCount === 1 ? "y" : "ies"} flagged` : "No anomalies flagged"}</strong><span>{anomalyCount > 0 ? "Review the affected windows and supporting evidence." : "No anomaly was flagged in this response window."}</span></div></div>}
              {hasFindings && <div className="av-findings-hint"><AlertTriangle size={14} /> Findings are indicators for review, not proof of malicious activity.</div>}
            </div>
            <details className="av-raw-details" open={showRaw} onToggle={(e) => setShowRaw(e.currentTarget.open)}><summary><span><Code2 size={15} /> Raw JSON response</span><span>{showRaw ? "Hide response" : "Inspect response"}</span></summary><pre>{prettyJson(result)}</pre></details>
          </> : <div className="av-output-empty"><div className="av-empty-art"><div className="av-art-ring ring-a" /><div className="av-art-ring ring-b" /><div className="av-art-center"><Activity size={25} /></div><span className="av-art-pulse pulse-a" /><span className="av-art-pulse pulse-b" /></div><span className="av-empty-kicker">READY FOR ANALYSIS</span><strong>Nothing to investigate yet</strong><p>Configure the detector and run an analysis. Results and response details will show up here.</p><div className="av-empty-checks"><span><CheckCircle2 size={14} /> Input validation</span><span><CheckCircle2 size={14} /> API response parsing</span><span><CheckCircle2 size={14} /> Result summary</span></div></div>}
          <div className="av-result-bottom"><span><span className="av-bottom-dot" /> {API_BASE}</span><span><Clock3 size={12} /> {lastRun ? "Latest run shown" : "No run in this session"}</span></div>
        </section>
      </div>
      <p className="av-disclaimer"><ShieldAlert size={13} /> Detection results are risk signals for human review. Classifier outputs depend on the configured model and its training data.</p>
    </section>
  );
}

function parseOrFallback(text, fallback) { try { return JSON.parse(text); } catch { return fallback; } }
function getSummaryItems(data) {
  const preferred = ["verdict", "failed_attempt_count", "distinct_client_count", "analyzed_event_count", "status", "risk_level", "predicted_label", "label", "confidence", "anomaly_count", "target_window_count", "baseline_window_count", "total_requests", "finding_count", "count"];
  const labels = { verdict: "Verdict", failed_attempt_count: "Failed attempts", distinct_client_count: "Client IPs", analyzed_event_count: "Events analyzed", risk_level: "Risk level", predicted_label: "Predicted class", label: "Classification", confidence: "Confidence", anomaly_count: "Anomalies", target_window_count: "Target windows", baseline_window_count: "Baseline windows", total_requests: "Requests analyzed", finding_count: "Findings", count: "Result count" };
  const items = [];
  for (const key of preferred) {
    const value = data?.[key];
    if ((typeof value === "string" || typeof value === "number" || typeof value === "boolean") && value !== "") {
      items.push({ label: labels[key] || key.replaceAll("_", " "), value: typeof value === "number" && key === "confidence" && value <= 1 ? `${(value * 100).toFixed(1)}%` : String(value) });
    }
    if (items.length === 4) break;
  }
  return items;
}
