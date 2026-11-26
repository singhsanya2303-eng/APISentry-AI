import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Braces,
  CheckCircle2,
  LoaderCircle,
  Play,
  Plus,
  RotateCcw,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { securityApis } from "../services/api";
import "./HttpPayloadClassifier.css";

const MAX_VALUES = 50;
const MAX_VALUE_CHARS = 10_000;
const MAX_TOTAL_CHARS = 100_000;

// Persistent, exact advisory statement. It is never removed after a run.
const EXPLANATION =
  "This tool classifies individual HTTP parameter values using a research-only ML model. Results are advisory and are not production-grade security decisions.";

// Shown unconditionally (not behind a tooltip) so evaluation limits stay visible
// even when the metadata endpoint is unavailable.
const LIMITATIONS = [
  "Parameter-value-only classification: this model does not analyze complete HTTP requests, sessions, or actors.",
  "The SVM decision score is an uncalibrated margin, not a probability, confidence, or risk score.",
  "Approximately 21.43% of held-out test rows were near the decision boundary (absolute decision score below 1.0).",
  "URL-encoded attacks can evade classification.",
  "Repeated benign characters can cause false positives.",
  "The research dataset and benchmark results do not establish production-grade detection accuracy.",
  "Advisory only: no blocking, throttling, banning, or other enforcement is performed.",
];

function safeMessage(error, fallback) {
  const match = error instanceof Error ? /^HTTP (\d{3}):/.exec(error.message) : null;
  const status = match ? Number(match[1]) : null;

  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return "Your account does not have permission to use this module.";
  if (status === 422) return "The submitted values could not be accepted. Check the batch limits and try again.";
  if (status === 503) return "The payload classifier model is currently unavailable. Please try again later.";
  if (status === 500) return "The server could not complete the request. Please try again later.";
  if (status !== null) return "The request could not be completed. Please try again later.";
  if (error instanceof TypeError) return "Unable to reach the API. Check your connection and try again.";
  return fallback;
}

function formatScore(score) {
  const number = Number(score);
  if (!Number.isFinite(number)) return "—";
  return `${number > 0 ? "+" : ""}${number.toFixed(4)}`;
}

function formatThreshold(threshold) {
  const number = Number(threshold);
  return Number.isFinite(number) ? number.toFixed(1) : "—";
}

export default function HttpPayloadClassifier() {
  const [rows, setRows] = useState([{ id: 0, value: "" }]);
  const [nextId, setNextId] = useState(1);
  const [validationError, setValidationError] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [metadata, setMetadata] = useState(null);
  const [metadataError, setMetadataError] = useState("");

  useEffect(() => {
    let active = true;
    securityApis
      .httpPayloadClassifierMetadata()
      .then((data) => {
        if (active) setMetadata(data);
      })
      .catch((loadError) => {
        if (active) {
          setMetadataError(
            safeMessage(loadError, "Model metadata is currently unavailable.")
          );
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const totalChars = useMemo(
    () => rows.reduce((total, row) => total + row.value.length, 0),
    [rows]
  );
  const predictions = Array.isArray(result?.results) ? result.results : [];

  function updateRow(id, value) {
    setRows((previous) =>
      previous.map((row) => (row.id === id ? { ...row, value } : row))
    );
    if (validationError) setValidationError("");
  }

  function addRow() {
    if (rows.length >= MAX_VALUES) {
      setValidationError(`At most ${MAX_VALUES} values can be classified at once.`);
      return;
    }
    setValidationError("");
    setRows((previous) => [...previous, { id: nextId, value: "" }]);
    setNextId((previous) => previous + 1);
  }

  function removeRow(id) {
    setRows((previous) => previous.filter((row) => row.id !== id));
    setValidationError("");
  }

  function validate() {
    if (rows.length === 0) return "Add at least one parameter value.";
    if (rows.length > MAX_VALUES) return `At most ${MAX_VALUES} values are allowed.`;
    for (const row of rows) {
      if (!row.value.trim()) return "Enter a value for every row, or remove empty rows.";
      if (row.value.length > MAX_VALUE_CHARS) {
        return `Each value must be ${MAX_VALUE_CHARS.toLocaleString()} characters or fewer.`;
      }
    }
    if (totalChars > MAX_TOTAL_CHARS) {
      return `The combined length must be ${MAX_TOTAL_CHARS.toLocaleString()} characters or fewer.`;
    }
    return "";
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const problem = validate();
    if (problem) {
      setValidationError(problem);
      setError("");
      return;
    }

    setValidationError("");
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const data = await securityApis.httpPayloadClassifierPredict({
        payloads: rows.map((row) => row.value),
      });
      setResult(data);
      setLastRun(new Date());
      // Raw parameter values are not retained after a successful submission.
      setRows([{ id: nextId, value: "" }]);
      setNextId((previous) => previous + 1);
    } catch (submitError) {
      setError(
        safeMessage(
          submitError,
          "An unexpected error occurred. Please try again later."
        )
      );
    } finally {
      setLoading(false);
    }
  }

  function resetForm() {
    setRows([{ id: nextId, value: "" }]);
    setNextId((previous) => previous + 1);
    setValidationError("");
    setError("");
    setResult(null);
    setLastRun(null);
  }

  return (
    <section className="payload-v2">
      <header className="payload-hero">
        <div className="payload-hero-top">
          <span className="payload-kicker"><Braces size={13} /> RESEARCH WORKSPACE</span>
          <span className="payload-flag">ADVISORY ONLY · NO ENFORCEMENT</span>
        </div>
        <div className="payload-hero-main">
          <div className="payload-hero-icon"><Braces size={24} /></div>
          <div>
            <h2>HTTP Payload Classifier</h2>
            <p>Classify individual HTTP parameter values. Every value is scored independently.</p>
          </div>
        </div>
        <div className="payload-explanation" role="note">
          <ShieldAlert size={18} />
          <p>{EXPLANATION}</p>
        </div>
      </header>

      <div className="payload-grid">
        <form className="payload-card payload-form" onSubmit={handleSubmit}>
          <div className="payload-card-head">
            <div>
              <span className="payload-step">01 / ENTER VALUES</span>
              <h3>Parameter values</h3>
              <p>Add up to 50 plain-text parameter values.</p>
            </div>
            <div className="payload-head-icon"><Braces size={18} /></div>
          </div>

          <div className="payload-rows">
            {rows.map((row, index) => (
              <div className="payload-row" key={row.id}>
                <div className="payload-row-label">
                  <label htmlFor={`payload-value-${row.id}`}>Value {index + 1}</label>
                  <span>{row.value.length.toLocaleString()} / {MAX_VALUE_CHARS.toLocaleString()} characters</span>
                </div>
                <div className="payload-row-input">
                  <textarea
                    id={`payload-value-${row.id}`}
                    value={row.value}
                    onChange={(event) => updateRow(row.id, event.target.value)}
                    maxLength={MAX_VALUE_CHARS}
                    rows={2}
                    spellCheck="false"
                    autoComplete="off"
                    placeholder="Enter one HTTP parameter value"
                  />
                  <button
                    type="button"
                    className="payload-remove"
                    onClick={() => removeRow(row.id)}
                    aria-label={`Remove value ${index + 1}`}
                    title="Remove this value"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))}
            {rows.length === 0 && (
              <p className="payload-no-rows">No values yet. Add a value to begin.</p>
            )}
          </div>

          <button
            type="button"
            className="payload-add"
            onClick={addRow}
            disabled={rows.length >= MAX_VALUES || loading}
          >
            <Plus size={16} /> Add another value
          </button>

          <div className="payload-limit-bar" aria-live="polite">
            <span>Values <strong>{rows.length} / {MAX_VALUES}</strong></span>
            <span>Total characters <strong>{totalChars.toLocaleString()} / {MAX_TOTAL_CHARS.toLocaleString()}</strong></span>
          </div>
          <p className="payload-privacy">
            Values are submitted only when you select “Classify values”. Nothing is captured from traffic automatically, and raw values are cleared after a successful run.
          </p>

          {validationError && (
            <div className="payload-alert" role="alert"><AlertTriangle size={17} /><span>{validationError}</span></div>
          )}
          {error && (
            <div className="payload-alert" role="alert"><AlertTriangle size={17} /><span>{error}</span></div>
          )}

          <div className="payload-actions">
            <button type="submit" className="payload-run" disabled={loading || rows.length === 0}>
              {loading ? <LoaderCircle className="payload-spin" size={16} /> : <Play size={15} fill="currentColor" />}
              {loading ? "Classifying…" : "Classify values"}
            </button>
            <button type="button" className="payload-reset" onClick={resetForm} disabled={loading}>
              <RotateCcw size={15} /> Reset
            </button>
          </div>
        </form>

        <section className="payload-card payload-output">
          <div className="payload-card-head">
            <div>
              <span className="payload-step">02 / INSPECT RESULTS</span>
              <h3>Independent predictions</h3>
              <p>
                {lastRun
                  ? `Completed at ${lastRun.toLocaleTimeString()}`
                  : "One advisory prediction per value, in the original order."}
              </p>
            </div>
            <div className={`payload-state ${result ? "done" : error ? "failed" : "idle"}`}>
              <span />{result ? "COMPLETE" : error ? "FAILED" : loading ? "RUNNING" : "STANDBY"}
            </div>
          </div>

          <div className="payload-semantics">
            <strong>Decision margin — not a probability</strong>
            <p>
              The score is an uncalibrated SVM decision margin with a threshold of 0.0.
              Positive values indicate an anomalous prediction; negative values indicate a
              benign prediction. It is never a probability, confidence, or risk score.
            </p>
          </div>

          {loading ? (
            <div className="payload-empty"><LoaderCircle className="payload-spin" size={26} /><strong>Classifying values…</strong></div>
          ) : result ? (
            <>
              <div className="payload-result-meta">
                <span>Model <code>{result.model_name || "—"}</code></span>
                <span>Features <code>{result.feature_mode || "—"}</code></span>
                <span>Values <strong>{predictions.length}</strong></span>
                {result.advisory_only === true && <span className="payload-advisory-tag">ADVISORY ONLY</span>}
              </div>
              {result.artifact_sha256 && (
                <p className="payload-hash">Verified artifact <code>{result.artifact_sha256}</code></p>
              )}
              <ol className="payload-predictions">
                {predictions.map((prediction) => (
                  <li className="payload-prediction" key={prediction.index}>
                    <div className="payload-prediction-head">
                      <span className="payload-index">VALUE {prediction.index + 1}</span>
                      <strong className={`payload-label ${prediction.label === "anomalous" ? "anomalous" : "benign"}`}>
                        {prediction.label}
                      </strong>
                    </div>
                    <dl className="payload-facts">
                      <div>
                        <dt>Decision margin — not a probability</dt>
                        <dd className={prediction.label === "anomalous" ? "anomalous" : "benign"}>
                          {formatScore(prediction.decision_score)}
                        </dd>
                      </div>
                      <div>
                        <dt>Decision threshold</dt>
                        <dd>{formatThreshold(prediction.decision_threshold)}</dd>
                      </div>
                      <div>
                        <dt>Payload length</dt>
                        <dd>{Number(prediction.payload_length ?? 0).toLocaleString()} chars</dd>
                      </div>
                      <div>
                        <dt>Low-margin review flag</dt>
                        <dd>{prediction.low_margin ? "Yes" : "No"}</dd>
                      </div>
                    </dl>
                    {prediction.low_margin && (
                      <p className="payload-review">
                        <AlertTriangle size={15} />
                        <span>
                          Human review recommended: this value is close to the decision boundary.
                          low_margin means |decision score| &lt; 1.0; it is descriptive, not a
                          calibrated risk category, and it does not change the label.
                        </span>
                      </p>
                    )}
                  </li>
                ))}
              </ol>
              {result.interpretation && <p className="payload-interpretation">{result.interpretation}</p>}
            </>
          ) : (
            <div className="payload-empty">
              <CheckCircle2 size={26} />
              <strong>No predictions yet</strong>
              <p>Enter one or more parameter values, then select “Classify values”.</p>
            </div>
          )}
        </section>
      </div>

      <section className="payload-card payload-info">
        <div className="payload-info-column">
          <h3>Model metadata</h3>
          {metadata ? (
            <dl className="payload-meta-list">
              <div><dt>Model name</dt><dd>{metadata.model_name}</dd></div>
              <div><dt>Feature mode</dt><dd>{metadata.feature_mode}</dd></div>
              <div><dt>Dataset</dt><dd>{metadata.dataset}</dd></div>
              <div><dt>Advisory only</dt><dd>{String(metadata.advisory_only)}</dd></div>
              <div><dt>Artifact SHA-256</dt><dd><code>{metadata.artifact_sha256}</code></dd></div>
            </dl>
          ) : (
            <p className="payload-muted">{metadataError || "Loading model metadata…"}</p>
          )}
        </div>
        <div className="payload-info-column">
          <h3>Known limitations</h3>
          <ul className="payload-limitations">
            {LIMITATIONS.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul>
          {Array.isArray(metadata?.limitations) && metadata.limitations.length > 0 && (
            <>
              <h4>Model-reported limitations</h4>
              <ul className="payload-limitations">
                {metadata.limitations.map((limitation, index) => (
                  <li key={`${index}-${limitation}`}>{limitation}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      </section>
    </section>
  );
}
