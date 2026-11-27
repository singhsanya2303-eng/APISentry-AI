import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Play, Power, ShieldAlert, Siren, Square } from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import { safeErrorMessage } from "../utils/mitigationAdminHelpers";
import { AdminHero, AdvisoryNote, EmptyPanel, ErrorPanel, KeyValueGrid, LoadingPanel, MessageStrip, StatusBadge } from "./MitigationAdminCommon";

const DEFAULT_ENABLE = {
  confirmation: "",
  policy_version: "",
  max_requests: "25",
  max_duration_seconds: "300",
};

const ENABLE_CONFIRMATION = "ENABLE_LOCAL_DEMO";

const DEFAULT_SCENARIOS = `[
  {"request_id":"req-benign-1","client_ip":"127.0.0.1","method":"GET","path":"/api/v1/demo/health","status_code":200,"scenario":"benign","bot_risk_score":5,"auth_failures":0,"authenticated":false,"attribution_status":"missing","scope_type":"unattributed"},
  {"request_id":"req-suspicious-1","client_ip":"127.0.0.1","method":"POST","path":"/api/v1/demo/login","status_code":401,"scenario":"suspicious","bot_risk_score":55,"auth_failures":6,"authenticated":false,"attribution_status":"network_ip","scope_type":"network_ip"}
]`;

export default function MitigationDemoPanel({ role }) {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState(null);
  const [enableForm, setEnableForm] = useState(DEFAULT_ENABLE);
  const [enableErrors, setEnableErrors] = useState({});
  const [demoId, setDemoId] = useState("");
  const [requestsJson, setRequestsJson] = useState(DEFAULT_SCENARIOS);
  const [runResult, setRunResult] = useState(null);
  const [busy, setBusy] = useState("");
  const isAdmin = role === "admin";

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await mitigationAdminApi.getDemoStatus();
      setStatus(data);
      if (data?.active_demo_id) setDemoId(data.active_demo_id);
    } catch (err) {
      setError(safeErrorMessage(err, "Unable to load demo status."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await mitigationAdminApi.getDemoStatus();
        if (cancelled) return;
        setStatus(data);
        if (data?.active_demo_id) setDemoId(data.active_demo_id);
      } catch (err) {
        if (!cancelled) setError(safeErrorMessage(err, "Unable to load demo status."));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const withBusy = async (key, fn) => {
    setBusy(key);
    setMessage(null);
    try { await fn(); }
    catch (err) { setMessage({ tone: "error", text: safeErrorMessage(err, "Demo operation failed.") }); }
    finally { setBusy(""); }
  };

  const setEnableField = (field, value) => {
    setEnableForm((f) => ({ ...f, [field]: value }));
    setEnableErrors((prev) => (prev[field] ? { ...prev, [field]: "" } : prev));
  };

  const validateEnableForm = () => {
    const errors = {};
    const policyVersion = enableForm.policy_version.trim();
    const confirmation = enableForm.confirmation.trim();
    const maxRequestsRaw = String(enableForm.max_requests).trim();
    const maxDurationRaw = String(enableForm.max_duration_seconds).trim();
    const maxRequests = Number(maxRequestsRaw);
    const maxDuration = Number(maxDurationRaw);

    if (!policyVersion) errors.policy_version = "Policy version is required. Enter the active policy version before enabling demo mode.";
    if (!maxRequestsRaw) errors.max_requests = "Max requests is required.";
    else if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 100) errors.max_requests = "Max requests must be a whole number between 1 and 100.";
    if (!maxDurationRaw) errors.max_duration_seconds = "Max duration is required.";
    else if (!Number.isInteger(maxDuration) || maxDuration < 10 || maxDuration > 900) errors.max_duration_seconds = "Max duration must be a whole number between 10 and 900 seconds.";
    if (!confirmation) errors.confirmation = `Confirmation is required. Type ${ENABLE_CONFIRMATION}.`;
    else if (confirmation !== ENABLE_CONFIRMATION) errors.confirmation = `Confirmation must exactly match ${ENABLE_CONFIRMATION}.`;

    return {
      errors,
      payload: {
        confirmation,
        policy_version: policyVersion,
        max_requests: maxRequests,
        max_duration_seconds: maxDuration,
        synthetic_only_ack: true,
        loopback_only_ack: true,
      },
    };
  };

  const onEnable = () => {
    const { errors, payload } = validateEnableForm();
    setEnableErrors(errors);
    if (Object.keys(errors).length > 0) {
      setMessage({ tone: "error", text: "Please fix the highlighted demo enable fields before submitting." });
      return;
    }
    return withBusy("enable", async () => {
      const data = await mitigationAdminApi.enableDemo(payload);
      setStatus(data);
      setDemoId(data.active_demo_id || "");
      setEnableErrors({});
      setMessage({ tone: "success", text: "Isolated local demo enabled. Enforcement remains demo-only and loopback-only." });
    });
  };

  const onDisable = () => withBusy("disable", async () => {
    const data = await mitigationAdminApi.disableDemo({ reason: "operator_disable" });
    setStatus(data);
    setMessage({ tone: "success", text: "Demo enforcement disabled. System returned to advisory-only behavior." });
  });

  const onKill = () => withBusy("kill", async () => {
    const data = await mitigationAdminApi.demoKillSwitch();
    setStatus(data);
    setMessage({ tone: "success", text: "Kill switch activated. Subsequent demo requests are advisory-only." });
  });

  const onRun = () => withBusy("run", async () => {
    let requests;
    try { requests = JSON.parse(requestsJson); } catch { throw new Error("Requests JSON is invalid."); }
    if (!Array.isArray(requests) || requests.length === 0) throw new Error("Provide at least one synthetic request.");
    const result = await mitigationAdminApi.runDemo({ demo_id: demoId.trim(), synthetic: true, requests });
    setRunResult(result);
    setStatus(await mitigationAdminApi.getDemoStatus());
    setMessage({ tone: "success", text: `Demo run completed: ${result.outcomes.length} outcome(s).` });
  });

  if (loading) return <LoadingPanel label="Loading demo status..." />;
  if (error) return <ErrorPanel message={error} onRetry={load} />;
  const s = status || {};

  return (
    <section className="mad-v2">
      <AdminHero
        title="Isolated Local Enforcement Demo"
        description="Default-off, loopback-only, synthetic-request demo harness. This does not enable production enforcement."
        endpoint="/api/v1/security/mitigation/demo"
        icon={Siren}
      />
      <AdvisoryNote title="Safety boundary" tone="warn">
        Demo mode is loopback-only, synthetic-only, bounded, and default OFF. It uses a dedicated temporary SQLite database and never contacts preserved PostgreSQL databases. Enforcement affects only demo harness outcomes.
      </AdvisoryNote>

      {message && <MessageStrip message={message.text} tone={message.tone} onDismiss={() => setMessage(null)} />}

      <div className="mad-grid two">
        <div className="mad-card">
          <div className="mad-card-head">
            <div><span className="mad-step">STATUS</span><h3>Demo state</h3></div>
            <StatusBadge
              label={
                !s.demo_mode ? "DISABLED / ADVISORY ONLY"
                : s.kill_switch_active ? "KILL SWITCH ACTIVE (ADVISORY)"
                : s.expired ? "EXPIRED (ADVISORY)"
                : s.enforcement_enabled ? "ENFORCEMENT ON (DEMO)"
                : "ADVISORY ONLY"
              }
              tone={!s.demo_mode ? "success" : s.enforcement_enabled ? "warn" : "success"}
            />
          </div>
          <KeyValueGrid entries={[
            ["Status reason", s.status_reason || "-"],
            ["Demo mode", String(!!s.demo_mode)],
            ["Enforcement enabled", String(!!s.enforcement_enabled)],
            ["Real enforcement", String(!!s.real_enforcement)],
            ["Kill switch active", String(!!s.kill_switch_active)],
            ["Expired", String(!!s.expired)],
            ["Advisory only", String(!!s.advisory_only)],
            ["Loopback only", String(!!s.loopback_only)],
            ["Synthetic only", String(!!s.synthetic_only)],
            ["Active demo ID", s.active_demo_id || "-"],
            ["Policy version", s.policy_version || "-"],
            ["Requests executed", String(s.requests_executed ?? 0)],
            ["Max requests", String(s.max_requests ?? 0)],
            ["Max duration (s)", String(s.max_duration_seconds ?? 0)],
            ["Started at", s.started_at || "-"],
            ["Expires at", s.expires_at || "-"],
            ["Last outcome", s.last_decision_outcome || "-"],
            ["Last decision", s.last_decision_uuid || "-"],
            ["Persistence", s.persistence_db || "-"],
          ]} />
          <div className="mad-actions">
            <button className="mad-button" type="button" onClick={load} disabled={!!busy}><ShieldAlert size={14} /> Refresh</button>
            {isAdmin && <button className="mad-button danger" type="button" onClick={onDisable} disabled={!!busy || !s.demo_mode}><Square size={14} /> Disable demo</button>}
            {isAdmin && <button className="mad-button danger" type="button" onClick={onKill} disabled={!!busy}><Power size={14} /> Kill switch</button>}
          </div>
          {!isAdmin && <p className="mad-footnote">Admin role required for enable/disable/kill-switch/run actions.</p>}
        </div>

        <div className="mad-card">
          <div className="mad-card-head"><div><span className="mad-step">ACTIVATE</span><h3>Enable isolated demo</h3></div></div>
          <p className="mad-footnote">Requires explicit confirmation, active policy version, loopback source, and bounded limits. Activation does not affect production enforcement.</p>
          <label className="mad-field" htmlFor="demo-enable-policy-version">
            <span>Policy version (ACTIVE) <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input
              id="demo-enable-policy-version"
              value={enableForm.policy_version}
              onChange={e => setEnableField("policy_version", e.target.value)}
              placeholder="e.g. 1.0.0"
              disabled={!isAdmin || !!busy}
              aria-invalid={enableErrors.policy_version ? "true" : "false"}
              aria-describedby={enableErrors.policy_version ? "demo-enable-policy-version-error" : undefined}
              required
            />
            {enableErrors.policy_version ? <span id="demo-enable-policy-version-error" className="mad-field-error" role="alert">{enableErrors.policy_version}</span> : null}
          </label>
          <label className="mad-field" htmlFor="demo-enable-max-requests">
            <span>Max requests (1-100) <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input
              id="demo-enable-max-requests"
              type="number"
              min="1"
              max="100"
              value={enableForm.max_requests}
              onChange={e => setEnableField("max_requests", e.target.value)}
              disabled={!isAdmin || !!busy}
              aria-invalid={enableErrors.max_requests ? "true" : "false"}
              aria-describedby={enableErrors.max_requests ? "demo-enable-max-requests-error" : undefined}
              required
            />
            {enableErrors.max_requests ? <span id="demo-enable-max-requests-error" className="mad-field-error" role="alert">{enableErrors.max_requests}</span> : null}
          </label>
          <label className="mad-field" htmlFor="demo-enable-max-duration">
            <span>Max duration seconds (10-900) <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input
              id="demo-enable-max-duration"
              type="number"
              min="10"
              max="900"
              value={enableForm.max_duration_seconds}
              onChange={e => setEnableField("max_duration_seconds", e.target.value)}
              disabled={!isAdmin || !!busy}
              aria-invalid={enableErrors.max_duration_seconds ? "true" : "false"}
              aria-describedby={enableErrors.max_duration_seconds ? "demo-enable-max-duration-error" : undefined}
              required
            />
            {enableErrors.max_duration_seconds ? <span id="demo-enable-max-duration-error" className="mad-field-error" role="alert">{enableErrors.max_duration_seconds}</span> : null}
          </label>
          <label className="mad-field" htmlFor="demo-enable-confirmation">
            <span>Type {ENABLE_CONFIRMATION} to confirm <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input
              id="demo-enable-confirmation"
              value={enableForm.confirmation}
              onChange={e => setEnableField("confirmation", e.target.value)}
              placeholder={ENABLE_CONFIRMATION}
              disabled={!isAdmin || !!busy}
              aria-invalid={enableErrors.confirmation ? "true" : "false"}
              aria-describedby={enableErrors.confirmation ? "demo-enable-confirmation-error" : undefined}
              required
            />
            {enableErrors.confirmation ? <span id="demo-enable-confirmation-error" className="mad-field-error" role="alert">{enableErrors.confirmation}</span> : null}
          </label>
          <div className="mad-actions"><button className="mad-button primary" type="button" onClick={onEnable} disabled={!isAdmin || !!busy}><Play size={14} /> Enable demo</button></div>
        </div>
      </div>

      <div className="mad-card">
        <div className="mad-card-head"><div><span className="mad-step">RUN</span><h3>Synthetic request harness</h3></div></div>
        <AdvisoryNote title="Synthetic only">All requests must be synthetic and loopback-targeted. No real user payloads, no external targets, no uncontrolled traffic generation.</AdvisoryNote>
        <label className="mad-field"><span>Demo ID</span><input value={demoId} onChange={e => setDemoId(e.target.value)} placeholder="demo-..." disabled={!isAdmin || !!busy} /></label>
        <label className="mad-field"><span>Synthetic requests JSON</span><textarea rows={10} value={requestsJson} onChange={e => setRequestsJson(e.target.value)} disabled={!isAdmin || !!busy} /></label>
        <div className="mad-actions"><button className="mad-button primary" type="button" onClick={onRun} disabled={!isAdmin || !!busy || !s.demo_mode}><Play size={14} /> Run synthetic demo</button></div>
      </div>

      <div className="mad-card">
        <div className="mad-card-head"><div><span className="mad-step">RESULTS</span><h3>Last demo outcomes</h3></div></div>
        {!runResult ? <EmptyPanel title="No demo run yet" icon={AlertTriangle}>Enable the demo and run synthetic requests to see outcomes.</EmptyPanel> : (
          <>
            <KeyValueGrid entries={[
              ["Demo ID", runResult.demo_id],
              ["Executed", String(runResult.executed_requests)],
              ["Stopped reason", runResult.stopped_reason || "-"],
              ["Enforcement enabled", String(runResult.enforcement_enabled)],
              ["Advisory only", String(runResult.advisory_only)],
            ]} />
            <div className="mad-table-wrap">
              <table className="mad-table">
                <thead><tr><th>Request</th><th>Scenario</th><th>Intended</th><th>Actual</th><th>Allowed</th><th>Decision</th><th>Audit</th></tr></thead>
                <tbody>
                  {runResult.outcomes.map((o, i) => (
                    <tr key={`${o.request_id}-${i}`}>
                      <td>{o.request_id}</td>
                      <td>{o.scenario}</td>
                      <td>{o.intended_action || "-"}</td>
                      <td>{o.actual_outcome}</td>
                      <td>{String(o.allowed)}</td>
                      <td className="mad-mono">{o.decision_uuid || "-"}</td>
                      <td className="mad-mono">{o.audit_event_uuid || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
