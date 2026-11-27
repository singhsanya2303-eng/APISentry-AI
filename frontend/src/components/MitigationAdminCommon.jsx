import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

export function AdminHero({ title, description, endpoint, icon: Icon, children }) {
  return (
    <header className="mad-hero">
      <div className="mad-hero-top">
        <span className="mad-kicker"><ShieldAlert size={13} /> MITIGATION ADMINISTRATION</span>
        <span className="mad-method">POST / GET</span>
      </div>
      <div className="mad-hero-main">
        <div className="mad-hero-icon"><Icon size={24} /></div>
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
      </div>
      <div className="mad-route"><span /><span>BASE PATH</span><code>{endpoint}</code></div>
      {children}
    </header>
  );
}

export function AdvisoryNote({ title = "Advisory only", children, tone = "info" }) {
  return (
    <div className={`mad-note ${tone}`} role="note">
      <ShieldAlert size={18} />
      <div>
        <strong>{title}</strong>
        <span>{children}</span>
      </div>
    </div>
  );
}

export function LoadingPanel({ label = "Loading…" }) {
  return (
    <div className="mad-state" role="status" aria-live="polite">
      <LoaderCircle className="mad-spin" size={24} />
      <strong>{label}</strong>
      <p>Waiting for the authenticated advisory API.</p>
    </div>
  );
}

export function ErrorPanel({ message, onRetry }) {
  return (
    <div className="mad-state mad-error" role="alert">
      <AlertTriangle size={21} />
      <strong>Request could not be completed</strong>
      <p>{message}</p>
      {typeof onRetry === "function" && (
        <button className="mad-button" type="button" onClick={onRetry}>
          <RefreshCw size={13} /> Retry
        </button>
      )}
    </div>
  );
}

export function EmptyPanel({ title, children, icon: Icon }) {
  return (
    <div className="mad-state mad-empty">
      {Icon ? <Icon size={22} /> : <ShieldAlert size={22} />}
      <strong>{title}</strong>
      <p>{children}</p>
    </div>
  );
}

export function StatusBadge({ label, tone = "neutral" }) {
  return <span className={`mad-badge ${tone}`}>{label || "—"}</span>;
}

export function KeyValueGrid({ entries }) {
  return (
    <div className="mad-kv-grid">
      {(entries || []).map(([label, value], index) => (
        <div key={`${label}-${index}`}>
          <span>{label}</span>
          <strong>{value ?? "—"}</strong>
        </div>
      ))}
    </div>
  );
}

export function Pager({ total, limit, offset, onOffsetChange, disabled = false }) {
  const safeTotal = Number.isFinite(Number(total)) ? Number(total) : 0;
  const safeLimit = Number.isFinite(Number(limit)) && Number(limit) > 0 ? Number(limit) : 50;
  const start = safeTotal === 0 ? 0 : Number(offset) + 1;
  const end = Math.min(Number(offset) + safeLimit, safeTotal);
  const hasPrevious = Number(offset) > 0;
  const hasNext = end < safeTotal;

  return (
    <div className="mad-pager">
      <span>{safeTotal === 0 ? "No records" : `${start}–${end} of ${safeTotal}`}</span>
      <div>
        <button
          className="mad-button mad-button-small"
          type="button"
          disabled={disabled || !hasPrevious}
          onClick={() => onOffsetChange(Math.max(0, Number(offset) - safeLimit))}
        >
          <ChevronLeft size={13} /> Previous
        </button>
        <button
          className="mad-button mad-button-small"
          type="button"
          disabled={disabled || !hasNext}
          onClick={() => onOffsetChange(Number(offset) + safeLimit)}
        >
          Next <ChevronRight size={13} />
        </button>
      </div>
    </div>
  );
}

export function MessageStrip({ message, tone = "info", onDismiss }) {
  if (!message) return null;
  return (
    <div className={`mad-message ${tone}`} role="status" aria-live="polite">
      <span>{message}</span>
      {typeof onDismiss === "function" && (
        <button type="button" onClick={onDismiss} aria-label="Dismiss message">×</button>
      )}
    </div>
  );
}

export function ActionNotice({ children }) {
  return <p className="mad-action-note">{children}</p>;
}
