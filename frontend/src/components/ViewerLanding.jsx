import { Activity, Clock3, RefreshCw, ShieldOff } from "lucide-react";
import { backendStateCopy } from "../services/backendStatus.js";

function displayValue(value, fallback) {
  if (typeof value === "string" && value.trim()) return value;
  return fallback;
}

export default function ViewerLanding({
  profile,
  health,
  readiness,
  apiStatus,
  lastChecked,
  loading,
  onRefreshHealth,
}) {
  const state = backendStateCopy(apiStatus);
  const readinessStatus =
    readiness?.status === "ready" || readiness?.status === "not_ready"
      ? readiness.status
      : apiStatus === "online"
        ? "ready"
        : "unknown";
  const checks = readiness?.checks || {};

  return (
    <section className="viewer-landing" aria-label="Viewer read-only access">
      <div className="panel viewer-intro">
        <div className="panel-header">
          <div>
            <h3>Viewer access</h3>
            <p>Read-only workspace for owner-provisioned accounts.</p>
          </div>
          <ShieldOff size={20} aria-hidden="true" />
        </div>
        <p className="viewer-copy">
          Your role can review account and service status only. Analysis, mitigation, policy,
          and user-administration endpoints require Admin or Analyst roles and remain
          protected by backend authorization.
        </p>
        <div className="viewer-access-list">
          <span><strong>Available:</strong> Overview, Service Status</span>
          <span><strong>Not available:</strong> analysis runs, mitigation changes, policy changes, user administration</span>
        </div>
      </div>

      <div className="viewer-grid">
        <article className="viewer-card">
          <span className="viewer-card-label"><ShieldOff size={14} /> Signed-in role</span>
          <strong>{displayValue(profile?.role?.toUpperCase(), "VIEWER")}</strong>
          <p>{displayValue(profile?.username, "Authenticated user")}</p>
        </article>
        <article className="viewer-card">
          <span className="viewer-card-label"><Activity size={14} /> Backend status</span>
          <strong>{state.label}</strong>
          <p>{displayValue(health?.status, "Health endpoint not reached")}</p>
        </article>
        <article className="viewer-card">
          <span className="viewer-card-label"><Activity size={14} /> Readiness</span>
          <strong>{readinessStatus === "ready" ? "Ready" : readinessStatus === "not_ready" ? "Not ready" : "Unknown"}</strong>
          <p>
            Database: {displayValue(checks.database, "unknown")}
          </p>
        </article>
        <article className="viewer-card">
          <span className="viewer-card-label"><Clock3 size={14} /> Last checked</span>
          <strong>{lastChecked ? lastChecked.toLocaleTimeString() : "Pending"}</strong>
          <p>{state.message}</p>
        </article>
      </div>

      <div className="viewer-status-actions">
        <button
          className="refresh-button"
          type="button"
          onClick={onRefreshHealth}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? "spin" : ""} />
          {loading ? "Checking..." : "Refresh status"}
        </button>
        <span>Source: /health, /ready, and the authenticated profile endpoint.</span>
      </div>
    </section>
  );
}
