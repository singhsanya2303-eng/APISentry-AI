import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ban,
  Beaker,
  ChevronRight,
  CircleHelp,
  Clock3,
  FlaskConical,
  LoaderCircle,
  Play,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import {
  ATTRIBUTION_STATUSES,
  BOT_CLASSIFICATIONS,
  DEFAULT_DRY_RUN_FORM,
  buildDryRunPayload,
  decisionTone,
  formatTime,
  labelize,
  nowLocalInput,
  parseDryRunResult,
  parsePolicyList,
  safeErrorMessage,
  shortRef,
} from "../utils/mitigationAdminHelpers";
import {
  AdminHero,
  AdvisoryNote,
  EmptyPanel,
  ErrorPanel,
  KeyValueGrid,
  LoadingPanel,
  StatusBadge,
} from "./MitigationAdminCommon";

function listField(items) {
  return Array.isArray(items) && items.length > 0 ? items.join(", ") : "—";
}

export default function MitigationDryRun() {
  const [policyData, setPolicyData] = useState(null);
  const [policyError, setPolicyError] = useState("");
  const [policyLoading, setPolicyLoading] = useState(true);
  const [form, setForm] = useState(() => ({
    ...DEFAULT_DRY_RUN_FORM,
    at: nowLocalInput(),
    context_evaluated_at: nowLocalInput(),
  }));
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const submitLock = useRef(false);

  const loadPolicies = useCallback(async () => {
    setPolicyLoading(true);
    setPolicyError("");
    try {
      const data = await mitigationAdminApi.listPolicies();
      const parsed = parsePolicyList(data);
      setPolicyData(parsed);
      setForm((previous) => {
        if (previous.version) return previous;
        const version = parsed.activeVersion || parsed.versions[0] || "";
        return version ? { ...previous, version } : previous;
      });
    } catch (requestError) {
      setPolicyData(null);
      setPolicyError(safeErrorMessage(requestError, "Available policies could not be loaded."));
    } finally {
      setPolicyLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer external synchronization so the first render is not forced to
    // re-render synchronously from the effect body.
    Promise.resolve().then(() => loadPolicies());
  }, [loadPolicies]);

  function update(key, value) {
    setForm((previous) => ({ ...previous, [key]: value }));
  }

  async function runDryRun(event) {
    event.preventDefault();
    if (submitLock.current) return;

    let body;
    try {
      body = buildDryRunPayload(form);
    } catch (validationError) {
      setError(validationError instanceof Error ? validationError.message : "Review the dry-run input.");
      setResult(null);
      setHasRun(true);
      return;
    }

    submitLock.current = true;
    setLoading(true);
    setError("");
    setResult(null);
    setHasRun(true);
    try {
      const data = await mitigationAdminApi.dryRun(body);
      const parsed = parseDryRunResult(data);
      if (!parsed.ok || !parsed.decision) {
        const code = parsed.error?.code ? `${parsed.error.code}: ` : "";
        const message = parsed.error?.message || "The advisory evaluation did not produce a decision.";
        throw new Error(`${code}${message}`);
      }
      setResult(parsed);
    } catch (requestError) {
      setResult(null);
      setError(safeErrorMessage(requestError, "The advisory evaluation could not be completed."));
    } finally {
      submitLock.current = false;
      setLoading(false);
    }
  }

  function reset() {
    setForm({
      ...DEFAULT_DRY_RUN_FORM,
      at: nowLocalInput(),
      context_evaluated_at: nowLocalInput(),
      version: policyData?.activeVersion || policyData?.versions[0] || "",
    });
    setResult(null);
    setError("");
    setHasRun(false);
    setLoading(false);
  }

  const versions = policyData?.versions || [];
  const decision = result?.decision;
  const nested = decision?.decision && typeof decision.decision === "object" ? decision.decision : {};
  const auditEvent = result?.auditEvent;

  return (
    <section className="mad-v2">
      <AdminHero
        title="Advisory policy evaluation"
        description="Evaluate a selected policy version against supplied signals. The result is a recommendation, never an executed action."
        endpoint="/api/v1/security/mitigation/dry-run"
        icon={Beaker}
      />

      <AdvisoryNote title="Advisory / dry-run only — enforcement is disabled">
        The dashboard sends dry_run=true and only displays the intended action. No block, deny, throttle, challenge, middleware, or network action is requested.
      </AdvisoryNote>

      <div className="mad-card">
        <div className="mad-card-head">
          <div>
            <span className="mad-step">01 / POLICY REFERENCE</span>
            <h3>Available policy versions</h3>
            <p>Select an available version or reference one directly.</p>
          </div>
          <FlaskConical size={18} />
        </div>
        {policyLoading ? (
          <LoadingPanel label="Loading policy versions…" />
        ) : policyError ? (
          <ErrorPanel message={policyError} onRetry={loadPolicies} />
        ) : versions.length === 0 ? (
          <EmptyPanel title="No policy versions available">
            Propose a policy version in the Policies tab first. Gate C does not create policies during dry-run evaluation.
          </EmptyPanel>
        ) : (
          <div className="mad-chips">
            {versions.map((version) => (
              <button
                key={version}
                type="button"
                className={`mad-chip ${version === form.version ? "selected" : ""}`}
                onClick={() => update("version", version)}
              >
                {version}
                {version === policyData?.activeVersion && <StatusBadge label="Active" tone="ok" />}
              </button>
            ))}
          </div>
        )}
      </div>

      <form className="mad-card mad-form" onSubmit={runDryRun} noValidate>
        <div className="mad-card-head">
          <div>
            <span className="mad-step">02 / EVALUATION INPUT</span>
            <h3>Supply only documented fields</h3>
            <p>Unavailable signals remain explicit instead of being invented.</p>
          </div>
          <Play size={18} />
        </div>
        <div className="mad-form-grid">
          <label><span>Policy version</span><input value={form.version} onChange={(e) => update("version", e.target.value)} list="mad-dry-run-versions" /></label>
          <datalist id="mad-dry-run-versions">
            {versions.map((version) => <option key={version} value={version} />)}
          </datalist>
          <label><span>Evaluation time</span><input type="datetime-local" value={form.at} onChange={(e) => update("at", e.target.value)} /></label>
          <label><span>Context evaluated at</span><input type="datetime-local" value={form.context_evaluated_at} onChange={(e) => update("context_evaluated_at", e.target.value)} /></label>
          <label><span>Route class</span><input value={form.route_class} onChange={(e) => update("route_class", e.target.value)} /></label>
          <label>
            <span>Attribution status</span>
            <select value={form.attribution_status} onChange={(e) => update("attribution_status", e.target.value)}>
              {ATTRIBUTION_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
            </select>
          </label>
          <label><span>Actor key hash (optional)</span><input value={form.actor_key_hash} onChange={(e) => update("actor_key_hash", e.target.value)} placeholder="sha256:…" /></label>
          <label><span>API-key principal hash (optional)</span><input value={form.api_key_principal_hash} onChange={(e) => update("api_key_principal_hash", e.target.value)} placeholder="sha256:…" /></label>
          <label><span>Network key hash (optional)</span><input value={form.network_key_hash} onChange={(e) => update("network_key_hash", e.target.value)} placeholder="sha256:…" /></label>
          <label><span>Inferred actor hash (optional)</span><input value={form.inferred_actor_key_hash} onChange={(e) => update("inferred_actor_key_hash", e.target.value)} placeholder="sha256:…" /></label>
          <label><span>Idempotency token (optional)</span><input value={form.idempotency_token} onChange={(e) => update("idempotency_token", e.target.value)} /></label>
        </div>
        <div className="mad-checks">
          <label><input type="checkbox" checked={form.detection_available} onChange={(e) => update("detection_available", e.target.checked)} /> Detection available</label>
          <label><input type="checkbox" checked={form.evidence_complete} onChange={(e) => update("evidence_complete", e.target.checked)} /> Evidence complete</label>
          <label><input type="checkbox" checked={form.include_detection} onChange={(e) => update("include_detection", e.target.checked)} /> Include detection result</label>
        </div>
        {form.include_detection && (
          <div className="mad-form-grid">
            <label><span>Bot risk score (0–100)</span><input type="number" min="0" max="100" step="0.1" value={form.bot_risk_score} onChange={(e) => update("bot_risk_score", e.target.value)} /></label>
            <label>
              <span>Classification</span>
              <select value={form.bot_classification} onChange={(e) => update("bot_classification", e.target.value)}>
                {BOT_CLASSIFICATIONS.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label><span>Neutral summary</span><input value={form.bot_summary} onChange={(e) => update("bot_summary", e.target.value)} /></label>
          </div>
        )}
        <p className="mad-footnote">
          Hashes must use sha256:&lt;64 lowercase hex characters&gt;. Risk-assessment and advanced-envelope inputs are intentionally not collected; omitted signals are shown as missing in the result.
        </p>
        <div className="mad-actions">
          <button className="mad-button mad-button-primary" type="submit" disabled={loading}>
            {loading ? <LoaderCircle className="mad-spin" size={14} /> : <Play size={14} />}
            {loading ? "Evaluating…" : "Run advisory evaluation"}
          </button>
          <button className="mad-button" type="button" onClick={reset} disabled={loading}>
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </form>

      {loading ? (
        <div className="mad-card"><LoadingPanel label="Running advisory evaluation…" /></div>
      ) : error ? (
        <div className="mad-card"><ErrorPanel message={error} /></div>
      ) : !hasRun || !result ? (
        <div className="mad-card">
          <EmptyPanel icon={CircleHelp} title="No advisory evaluation yet">
            Supply the documented inputs and run the dry-run to see an intended action. Nothing will be executed.
          </EmptyPanel>
        </div>
      ) : (
        <>
          <div className="mad-card">
            <div className="mad-card-head">
              <div>
                <span className="mad-step">03 / ADVISORY RESULT</span>
                <h3>Intended action (not executed)</h3>
                <p>Every field below is advisory output from the authenticated API.</p>
              </div>
              <StatusBadge label={decision?.advisory_only ? "Advisory only" : "Review"} tone={decision?.advisory_only ? "ok" : "warn"} />
            </div>
            <div className="mad-decision-line">
              <span>Recommendation</span>
              <StatusBadge label={labelize(nested.decision || decision?.intended_action)} tone={decisionTone(nested.decision)} />
            </div>
            <p className="mad-explanation">{nested.explanation || "No explanation was returned for this advisory decision."}</p>
            <KeyValueGrid
              entries={[
                ["Decision reference", shortRef(decision?.decision_ref, 24)],
                ["Policy version", decision?.policy_version || "—"],
                ["Policy state", decision?.policy_state || "—"],
                ["Intended action", decision?.intended_action || "—"],
                ["Decision status", decision?.decision_status || "—"],
                ["Scope type", nested.scope_type || "—"],
                ["Scope key", shortRef(nested.scope_key_hash, 24)],
                ["Attribution", nested.attribution_status || "—"],
                ["Issued at", formatTime(nested.issued_at || decision?.evaluated_at)],
                ["Expires at", formatTime(nested.expires_at)],
                ["Config digest", shortRef(decision?.config_digest, 24)],
                ["Correlation ref", shortRef(decision?.correlation_ref, 24)],
              ]}
            />
            {nested.rate_limit != null && (
              <p className="mad-footnote">Advisory rate limit: {String(nested.rate_limit)} requests per {String(nested.rate_limit_window_seconds)} seconds. This is a recommendation only.</p>
            )}
          </div>

          <div className="mad-grid">
            <div className="mad-card">
              <div className="mad-card-head">
                <div><span className="mad-step">04 / REASONS</span><h3>Reasons and provenance</h3></div>
                <ChevronRight size={18} />
              </div>
              <div className="mad-code-groups">
                <div><span>Workflow reasons</span><div>{listField(decision?.workflow_reason_codes).split(", ").map((code) => <code key={code}>{code}</code>)}</div></div>
                <div><span>Decision reasons</span><div>{listField(nested.reason_codes).split(", ").map((code) => <code key={code}>{code}</code>)}</div></div>
                <div><span>Detection references</span><div>{listField(decision?.advisory_detection_refs).split(", ").map((ref) => <code key={ref}>{shortRef(ref, 20)}</code>)}</div></div>
                <div><span>Evidence references</span><div>{listField(nested.evidence_references).split(", ").map((ref) => <code key={ref}>{shortRef(ref, 20)}</code>)}</div></div>
              </div>
            </div>

            <div className="mad-card">
              <div className="mad-card-head">
                <div><span className="mad-step">05 / SIGNAL COVERAGE</span><h3>Missing and uncertain signals</h3></div>
                <ShieldAlert size={18} />
              </div>
              <KeyValueGrid
                entries={[
                  ["Missing signals", listField(decision?.missing_signals)],
                  ["Uncertain signals", listField(decision?.uncertain_signals)],
                  ["Detection available", form.detection_available ? "Yes" : "No"],
                  ["Evidence complete", form.evidence_complete ? "Yes" : "No"],
                  ["Risk assessment", decision?.risk_assessment_ref ? shortRef(decision.risk_assessment_ref, 20) : "Not supplied"],
                  ["Audit event plan", auditEvent?.event_type || "—"],
                  ["Event digest", shortRef(auditEvent?.content_digest, 20)],
                ]}
              />
              <p className="mad-footnote"><Ban size={13} /> A content digest is not a tamper-proof audit guarantee. No decision or audit row is written by this dry-run endpoint.</p>
            </div>
          </div>
        </>
      )}

      <div className="mad-footer">
        <Clock3 size={14} />
        <span>Results reflect only the latest completed advisory evaluation. No enforcement action has been taken.</span>
      </div>
    </section>
  );
}
