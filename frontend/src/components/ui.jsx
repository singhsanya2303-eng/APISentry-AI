import "./ui.css";

const BADGE_TONES = ["neutral", "success", "warning", "danger", "info"];

export function StatusBadge({ tone = "neutral", className = "", children }) {
  const safeTone = BADGE_TONES.includes(tone) ? tone : "neutral";
  return (
    <span className={`ui-badge ui-badge--${safeTone} ${className}`.trim()}>
      {children}
    </span>
  );
}

export function LoadingState({ label = "Loading…" }) {
  return (
    <div className="ui-state" role="status">
      <span className="ui-spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, description }) {
  return (
    <div className="ui-state ui-state--empty">
      <strong>{title}</strong>
      {description && <span>{description}</span>}
    </div>
  );
}

export function ErrorState({ title = "Unable to load", message }) {
  return (
    <div className="ui-state ui-state--error" role="alert">
      <strong>{title}</strong>
      {message && <span>{message}</span>}
    </div>
  );
}
