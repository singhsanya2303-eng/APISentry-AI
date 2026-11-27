import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Activity,
  Play,
  Power,
  ShieldAlert,
  Square,
  Siren,
} from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import {
  REQUEST_DEMO_CONFIRMATION,
  REQUEST_DEMO_SCENARIOS,
  buildRequestEnforcementEnablePayload,
  formatTime,
  parseRequestEnforcementEvidence,
  parseRequestEnforcementRun,
  parseRequestEnforcementStatus,
  requestEnforcementMode,
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
  MessageStrip,
  StatusBadge,
} from "./MitigationAdminCommon";

const DEFAULT_ENABLE = {
  confirmation: "",
  demo_id: "",
  policy_version: "",
  scenario: "allow",
  max_requests: "6",
  max_duration_seconds: "300",
};

export default function RequestEnforcementDemoPanel({ role }) {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState(null);
  const [form, setForm] = useState(DEFAULT_ENABLE);
  const [formErrors, setFormErrors] = useState({});
  const [requestCount, setRequestCount] = useState("3");
  const [runResult, setRunResult] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [busy, setBusy] = useState("");
  const isAdmin = role === "admin";

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = parseRequestEnforcementStatus(
        await mitigationAdminApi.getRequestEnforcementStatus()
      );
      setStatus(data);
      setForm((previous) => ({ ...previous, demo_id: data.demoId || previous.demo_id }));
    } catch (err) {
      setError(safeErrorMessage(err, "Unable to load isolated enforcement status."));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvidence = useCallback(async () => {
    try {
      setEvidence(
        parseRequestEnforcementEvidence(
          await mitigationAdminApi.getRequestEnforcementEvidence()
        )
      );
    } catch (err) {
      setMessage({
        tone: "error",
        text: safeErrorMessage(err, "Unable to load isolated enforcement evidence."),
      });
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = parseRequestEnforcementStatus(
          await mitigationAdminApi.getRequestEnforcementStatus()
        );
        if (cancelled) return;
        setStatus(data);
        setForm((previous) => ({ ...previous, demo_id: data.demoId || previous.demo_id }));
      } catch (err) {
        if (!cancelled) {
          setError(safeErrorMessage(err, "Unable to load isolated enforcement status."));
        }
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
    try {
      await fn();
    } catch (err) {
      setMessage({ tone: "error", text: safeErrorMessage(err, "Isolated demo operation failed.") });
    } finally {
      setBusy("");
    }
  };

  const setField = (field, value) => {
    setForm((previous) => ({ ...previous, [field]: value }));
    setFormErrors((previous) => (previous[field] ? { ...previous, [field]: "" } : previous));
  };

  const onEnable = () => {
    const { errors, payload } = buildRequestEnforcementEnablePayload(form);
    setFormErrors(errors);
    if (!payload) {
      setMessage({ tone: "error", text: "Fix the highlighted fields before enabling the isolated demo." });
      return;
    }
    return withBusy("enable", async () => {
      setStatus(
        parseRequestEnforcementStatus(
          await mitigationAdminApi.enableRequestEnforcementDemo(payload)
        )
      );
      setRunResult(null);
      setEvidence(null);
      setMessage({
        tone: "success",
        text: "Isolated request-time demo enabled. Production middleware is still unregistered.",
      });
    });
  };

  const onRun = () => {
    const count = Number(requestCount);
    if (!Number.isInteger(count) || count < 1 || count > 10) {
      setMessage({ tone: "error", text: "Request count must be a whole number between 1 and 10." });
      return;
    }
    return withBusy("run", async () => {
      const parsed = parseRequestEnforcementRun(
        await mitigationAdminApi.runRequestEnforcementDemo({
          demo_id: status?.demoId || form.demo_id.trim(),
          synthetic: true,
          request_count: count,
        })
      );
      setRunResult(parsed);
      setStatus(parsed.status);
      await loadEvidence();
      setMessage({ tone: "success", text: `Synthetic run completed: ${parsed.outcomes.length} outcome(s).` });
    });
  };

  const onKillSwitch = () => withBusy("kill", async () => {
    setStatus(
      parseRequestEnforcementStatus(
        await mitigationAdminApi.requestEnforcementKillSwitch()
      )
    );
    setMessage({ tone: "success", text: "Isolated kill switch active. Later demo requests are advisory-only." });
  });

  const onFailClosed = () => withBusy("fail-closed", async () => {
    const result = await mitigationAdminApi.requestEnforcementFailClosed();
    setMessage({
      tone: result.handler_reached ? "error" : "info",
      text: `Dependency outage simulated: HTTP ${result.status_code}, ${result.enforcement_outcome || "unknown"}; handler reached: ${String(result.handler_reached)}.`,
    });
  });

  const onDisable = () => withBusy("disable", async () => {
    setStatus(
      parseRequestEnforcementStatus(
        await mitigationAdminApi.disableRequestEnforcementDemo({ reason: "operator_disable" })
      )
    );
    setRunResult(null);
    setEvidence(null);
    setMessage({ tone: "success", text: "Isolated demo disabled and its temporary database cleaned up." });
  });

  if (loading) return <LoadingPanel label="Loading isolated enforcement status..." />;
  if (error) return <ErrorPanel message={error} onRetry={load} />;

  const s = status || {};
  const mode = requestEnforcementMode(s);

  return (
    <section className="mad-v2">
      <AdminHero
        title="Isolated request-time enforcement"
        description="Dedicated synthetic harness for the real middleware: ALLOW, BLOCK, THROTTLE, kill switch and fail-closed behavior."
        endpoint="/api/v1/security/mitigation/request-enforcement-demo"
        icon={Siren}
      />
      <AdvisoryNote title="Synthetic demo — not production" tone="warn">
        Every result below comes from a loopback-only, explicitly enabled, injected-database harness. No production traffic is blocked or throttled, and RequestEnforcementMiddleware is not registered on the production application.
      </AdvisoryNote>

      {message && <MessageStrip message={message.text} tone={message.tone} onDismiss={() => setMessage(null)} />}

      <div className="mad-grid two">
        <div className="mad-card">
          <div className="mad-card-head">
            <div><span className="mad-step">STATUS</span><h3>Isolated enforcement state</h3></div>
            <StatusBadge label={mode.label} tone={mode.tone} />
          </div>
          <KeyValueGrid entries={[
            ["Demo enabled", String(!!s.demoEnabled)],
            ["Enforcement enabled", String(!!s.enforcementEnabled)],
            ["Advisory only", String(!!s.advisoryOnly)],
            ["Kill switch active", String(!!s.killSwitchActive)],
            ["Real production enforcement", String(!!s.realEnforcement)],
            ["Production middleware registered", String(!!s.productionMiddlewareRegistered)],
            ["Loopback only", String(!!s.loopbackOnly)],
            ["Synthetic only", String(!!s.syntheticOnly)],
            ["Demo ID", s.demoId || "—"],
            ["Scenario", s.scenario || "—"],
            ["Policy version", s.policyVersion || "—"],
            ["Requests executed", String(s.requestsExecuted ?? 0)],
            ["Persisted decisions", String(s.decisionCount ?? 0)],
            ["Persisted audit events", String(s.auditEventCount ?? 0)],
            ["Persistence", s.persistenceDb || "none"],
            ["Status reason", s.statusReason || "—"],
          ]} />
          <div className="mad-actions">
            <button className="mad-button" type="button" onClick={load} disabled={!!busy}><Activity size={14} /> Refresh</button>
            {isAdmin && (
              <button className="mad-button danger" type="button" onClick={onKillSwitch} disabled={!!busy || !s.demoEnabled}>
                <Power size={14} /> Kill switch
              </button>
            )}
            {isAdmin && (
              <button className="mad-button danger" type="button" onClick={onDisable} disabled={!!busy || !s.demoEnabled}>
                <Square size={14} /> Disable demo
              </button>
            )}
          </div>
          {!isAdmin && <p className="mad-footnote">Analysts can inspect status and evidence. Admin role is required for enable, run, kill switch and disable actions.</p>}
        </div>

        <div className="mad-card">
          <div className="mad-card-head"><div><span className="mad-step">ENABLE</span><h3>Activate isolated demo</h3></div></div>
          <p className="mad-footnote">Requires explicit confirmation, a bounded loopback harness and an injected isolated database.</p>
          <label className="mad-field" htmlFor="wp9-confirmation">
            <span>Confirmation phrase <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input
              id="wp9-confirmation"
              value={form.confirmation}
              onChange={(e) => setField("confirmation", e.target.value)}
              placeholder={REQUEST_DEMO_CONFIRMATION}
              disabled={!isAdmin || !!busy || !!s.demoEnabled}
              aria-invalid={formErrors.confirmation ? "true" : "false"}
              required
            />
            {formErrors.confirmation ? <span className="mad-field-error" role="alert">{formErrors.confirmation}</span> : null}
          </label>
          <label className="mad-field" htmlFor="wp9-demo-id">
            <span>Demo ID <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input id="wp9-demo-id" value={form.demo_id} onChange={(e) => setField("demo_id", e.target.value)} disabled={!isAdmin || !!busy || !!s.demoEnabled} required />
            {formErrors.demo_id ? <span className="mad-field-error" role="alert">{formErrors.demo_id}</span> : null}
          </label>
          <label className="mad-field" htmlFor="wp9-policy-version">
            <span>Policy version <span className="mad-field-required" aria-hidden="true">*</span></span>
            <input id="wp9-policy-version" value={form.policy_version} onChange={(e) => setField("policy_version", e.target.value)} disabled={!isAdmin || !!busy || !!s.demoEnabled} required />
            {formErrors.policy_version ? <span className="mad-field-error" role="alert">{formErrors.policy_version}</span> : null}
          </label>
          <label className="mad-field" htmlFor="wp9-scenario">
            <span>Synthetic scenario</span>
            <select id="wp9-scenario" value={form.scenario} onChange={(e) => setField("scenario", e.target.value)} disabled={!isAdmin || !!busy || !!s.demoEnabled}>
              {REQUEST_DEMO_SCENARIOS.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            {formErrors.scenario ? <span className="mad-field-error" role="alert">{formErrors.scenario}</span> : null}
          </label>
          <label className="mad-field" htmlFor="wp9-max-requests">
            <span>Max requests (1–50)</span>
            <input id="wp9-max-requests" type="number" min="1" max="50" value={form.max_requests} onChange={(e) => setField("max_requests", e.target.value)} disabled={!isAdmin || !!busy || !!s.demoEnabled} />
            {formErrors.max_requests ? <span className="mad-field-error" role="alert">{formErrors.max_requests}</span> : null}
          </label>
          <label className="mad-field" htmlFor="wp9-max-duration">
            <span>Max duration seconds (10–900)</span>
            <input id="wp9-max-duration" type="number" min="10" max="900" value={form.max_duration_seconds} onChange={(e) => setField("max_duration_seconds", e.target.value)} disabled={!isAdmin || !!busy || !!s.demoEnabled} />
            {formErrors.max_duration_seconds ? <span className="mad-field-error" role="alert">{formErrors.max_duration_seconds}</span> : null}
          </label>
          <div className="mad-actions">
            <button className="mad-button mad-button-primary" type="button" onClick={onEnable} disabled={!isAdmin || !!busy || !!s.demoEnabled}><Play size={14} /> Enable isolated demo</button>
          </div>
        </div>
      </div>

      <div className="mad-card">
        <div className="mad-card-head"><div><span className="mad-step">RUN</span><h3>Synthetic enforcement probes</h3></div></div>
        <label className="mad-field" htmlFor="wp9-request-count">
          <span>Synthetic requests (1–10)</span>
          <input id="wp9-request-count" type="number" min="1" max="10" value={requestCount} onChange={(e) => setRequestCount(e.target.value)} disabled={!isAdmin || !!busy || !s.demoEnabled} />
        </label>
        <div className="mad-actions">
          <button className="mad-button mad-button-primary" type="button" onClick={onRun} disabled={!isAdmin || !!busy || !s.demoEnabled}><Play size={14} /> Run synthetic probes</button>
          <button className="mad-button" type="button" onClick={onFailClosed} disabled={!isAdmin || !!busy || !s.demoEnabled}><ShieldAlert size={14} /> Simulate dependency outage</button>
        </div>
      </div>

      <div className="mad-card">
        <div className="mad-card-head">
          <div><span className="mad-step">RESULTS</span><h3>Synthetic outcomes</h3></div>
          <StatusBadge label="DEMO DATA ONLY" tone="warn" />
        </div>
        {!runResult ? (
          <EmptyPanel icon={AlertTriangle} title="No synthetic run yet">
            Enable the isolated demo and run bounded probes to see ALLOW, BLOCK or THROTTLE outcomes.
          </EmptyPanel>
        ) : (
          <div className="mad-table-wrap">
            <table className="mad-table">
              <thead>
                <tr><th>Status</th><th>Action</th><th>Outcome</th><th>Handler reached</th><th>Decision</th><th>Request ref</th></tr>
              </thead>
              <tbody>
                {runResult.outcomes.map((item, index) => (
                  <tr key={`${item.requestRef || index}-${index}`}>
                    <td>{item.statusCode}</td>
                    <td>{item.action}</td>
                    <td>{item.outcome}</td>
                    <td>{String(item.handlerReached)}</td>
                    <td className="mad-mono">{item.decisionRef ? shortRef(item.decisionRef, 14) : "—"}</td>
                    <td className="mad-mono">{item.requestRef ? shortRef(item.requestRef, 14) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mad-card">
        <div className="mad-card-head">
          <div><span className="mad-step">PERSISTENCE</span><h3>Isolated decision and audit evidence</h3></div>
          <button className="mad-button mad-button-small" type="button" onClick={loadEvidence} disabled={!!busy}><Activity size={13} /> Refresh evidence</button>
        </div>
        {!evidence ? (
          <EmptyPanel icon={AlertTriangle} title="No evidence loaded">
            Run a synthetic probe, then refresh evidence to inspect persisted demo records.
          </EmptyPanel>
        ) : evidence.decisionCount === 0 && evidence.auditEventCount === 0 ? (
          <EmptyPanel icon={AlertTriangle} title="No persisted demo records">
            The isolated database contains no decision or audit rows for this demo.
          </EmptyPanel>
        ) : (
          <>
            <KeyValueGrid entries={[
              ["Decision rows", String(evidence.decisionCount)],
              ["Audit event rows", String(evidence.auditEventCount)],
            ]} />
            <div className="mad-table-wrap">
              <table className="mad-table">
                <thead><tr><th>Time</th><th>Event</th><th>Safe details</th></tr></thead>
                <tbody>
                  {evidence.auditEvents.slice(0, 12).map((item) => (
                    <tr key={item.eventRef}>
                      <td>{formatTime(item.createdAt)}</td>
                      <td>{item.eventType}</td>
                      <td className="mad-mono">
                        {item.details.length === 0 ? "—" : item.details.map(([key, value]) => `${key}: ${value}`).join(" · ")}
                      </td>
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
