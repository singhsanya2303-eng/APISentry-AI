import { useCallback, useState } from "react";
import {
  AlertTriangle,
  ChevronRight,
  FileClock,
  LoaderCircle,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import {
  AUDIT_ENTITY_TYPES,
  AUDIT_EVENT_TYPES,
  DEFAULT_AUDIT_FILTERS,
  buildAuditParams,
  formatNumber,
  formatTime,
  labelize,
  parseAuditDetail,
  parseAuditList,
  safeDetailEntries,
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
  Pager,
  StatusBadge,
} from "./MitigationAdminCommon";

export default function MitigationAuditHistory() {
  const [filters, setFilters] = useState(() => ({ ...DEFAULT_AUDIT_FILTERS }));
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedRef, setSelectedRef] = useState("");

  const load = useCallback(async (currentFilters) => {
    let params;
    try {
      params = buildAuditParams(currentFilters);
    } catch (validationError) {
      setError(validationError instanceof Error ? validationError.message : "Review the audit filters.");
      setData(null);
      setHasRun(true);
      return;
    }

    setLoading(true);
    setError("");
    setHasRun(true);
    try {
      const response = await mitigationAdminApi.listAuditEvents(params);
      setData(parseAuditList(response));
    } catch (requestError) {
      setData(null);
      setError(safeErrorMessage(requestError, "Audit history could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, []);

  function update(key, value) {
    setFilters((previous) => ({
      ...previous,
      [key]: value,
      ...(key === "limit" || key === "offset" ? {} : { offset: "0" }),
    }));
  }

  function applyFilters(event) {
    event.preventDefault();
    load(filters);
  }

  async function openDetail(record) {
    const reference = record?.event_uuid;
    if (!reference) return;
    setSelectedRef(reference);
    setDetail(null);
    setDetailError("");
    setDetailLoading(true);
    try {
      const response = await mitigationAdminApi.getAuditEvent(reference);
      setDetail(parseAuditDetail(response));
    } catch (requestError) {
      setDetailError(safeErrorMessage(requestError, "Audit event details could not be loaded."));
    } finally {
      setDetailLoading(false);
    }
  }

  function reset() {
    const defaults = { ...DEFAULT_AUDIT_FILTERS };
    setFilters(defaults);
    setDetail(null);
    setSelectedRef("");
    setError("");
    load(defaults);
  }

  const items = data?.items || [];

  return (
    <section className="mad-v2">
      <AdminHero
        title="Audit history"
        description="Read-only lifecycle and decision audit events returned by the authenticated Gate C APIs."
        endpoint="/api/v1/security/mitigation/audit-events"
        icon={FileClock}
      />

      <AdvisoryNote title="Integrity limitation">
        Event hashes are content digests stored as data, not a tamper-evident chain. The dashboard does not imply chain validation or tamper-proof guarantees.
      </AdvisoryNote>

      <form className="mad-card mad-form" onSubmit={applyFilters} noValidate>
        <div className="mad-card-head">
          <div>
            <span className="mad-step">01 / FILTERS</span>
            <h3>Backend-supported filters only</h3>
            <p>Event vocabulary is taken from the Gate C schema, not invented here.</p>
          </div>
          <Search size={18} />
        </div>
        <div className="mad-form-grid">
          <label><span>Policy version</span><input value={filters.policy_version} onChange={(e) => update("policy_version", e.target.value)} /></label>
          <label><span>Decision reference</span><input value={filters.decision_ref} onChange={(e) => update("decision_ref", e.target.value)} /></label>
          <label>
            <span>Event type</span>
            <select value={filters.event_type} onChange={(e) => update("event_type", e.target.value)}>
              <option value="">Any event type</option>
              {AUDIT_EVENT_TYPES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label>
            <span>Entity type</span>
            <select value={filters.entity_type} onChange={(e) => update("entity_type", e.target.value)}>
              <option value="">Any entity type</option>
              {AUDIT_ENTITY_TYPES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label><span>From time</span><input type="datetime-local" value={filters.from_time} onChange={(e) => update("from_time", e.target.value)} /></label>
          <label><span>To time</span><input type="datetime-local" value={filters.to_time} onChange={(e) => update("to_time", e.target.value)} /></label>
          <label><span>Limit (1–200)</span><input type="number" min="1" max="200" value={filters.limit} onChange={(e) => update("limit", e.target.value)} /></label>
          <label><span>Offset</span><input type="number" min="0" value={filters.offset} onChange={(e) => update("offset", e.target.value)} /></label>
        </div>
        <div className="mad-actions">
          <button className="mad-button mad-button-primary" type="submit" disabled={loading}>
            {loading ? <LoaderCircle className="mad-spin" size={14} /> : <Search size={14} />}
            {loading ? "Loading…" : "Apply filters"}
          </button>
          <button className="mad-button" type="button" onClick={reset} disabled={loading}>
            <X size={14} /> Clear
          </button>
        </div>
      </form>

      <div className="mad-card">
        <div className="mad-card-head">
          <div>
            <span className="mad-step">02 / EVENTS</span>
            <h3>Audit event records</h3>
            <p>Privacy-safe projections; raw payloads and unknown nested details are not rendered.</p>
          </div>
          <span className="mad-count">{data ? formatNumber(data.total) : "—"} total</span>
        </div>

        {loading ? (
          <LoadingPanel label="Loading audit events…" />
        ) : error ? (
          <ErrorPanel message={error} onRetry={() => load(filters)} />
        ) : !hasRun ? (
          <EmptyPanel icon={FileClock} title="No audit query run yet">
            Apply the filters to retrieve audit events.
          </EmptyPanel>
        ) : items.length === 0 ? (
          <EmptyPanel icon={ShieldCheck} title="No audit events returned">
            No records matched the selected filters. The dashboard does not invent audit events.
          </EmptyPanel>
        ) : (
          <>
            <div className="mad-table-wrap">
              <table className="mad-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Entity</th>
                    <th>Policy</th>
                    <th>Decision</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((event) => (
                    <tr key={event.event_uuid}>
                      <td>{formatTime(event.created_at)}</td>
                      <td><StatusBadge label={labelize(event.event_type)} tone={event.event_type === "policy_deactivated" ? "warn" : "info"} /></td>
                      <td>{labelize(event.entity_type)}</td>
                      <td>{event.policy_version || "—"}</td>
                      <td><code>{shortRef(event.decision_uuid, 14)}</code></td>
                      <td>
                        <button className="mad-button mad-button-small" type="button" onClick={() => openDetail(event)}>
                          <ChevronRight size={13} /> View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              total={data.total}
              limit={data.limit}
              offset={data.offset}
              disabled={loading}
              onOffsetChange={(offset) => {
                const next = { ...filters, offset: String(offset) };
                setFilters(next);
                load(next);
              }}
            />
          </>
        )}
      </div>

      {selectedRef && (
        <div className="mad-card">
          <div className="mad-card-head">
            <div>
              <span className="mad-step">03 / DETAIL</span>
              <h3>Audit event detail</h3>
              <p>{shortRef(selectedRef, 30)}</p>
            </div>
            <button className="mad-button mad-button-small" type="button" onClick={() => { setDetail(null); setSelectedRef(""); }}>
              <X size={13} /> Close
            </button>
          </div>
          {detailLoading ? (
            <LoadingPanel label="Loading audit event detail…" />
          ) : detailError ? (
            <ErrorPanel message={detailError} onRetry={() => openDetail({ event_uuid: selectedRef })} />
          ) : !detail ? (
            <EmptyPanel title="Audit event detail unavailable">The selected event could not be displayed.</EmptyPanel>
          ) : (
            <>
              <KeyValueGrid
                entries={[
                  ["Event UUID", shortRef(detail.event_uuid, 24)],
                  ["Event type", detail.event_type || "—"],
                  ["Entity type", detail.entity_type || "—"],
                  ["Entity identifier", shortRef(detail.entity_identifier, 24)],
                  ["Policy version", detail.policy_version || "—"],
                  ["Decision reference", shortRef(detail.decision_uuid, 24)],
                  ["Actor role", detail.actor_role || "—"],
                  ["Actor hash", shortRef(detail.actor_hash, 24)],
                  ["Correlation chain", shortRef(detail.chain_id, 24)],
                  ["Sequence number", formatNumber(detail.sequence_no)],
                  ["Content digest", shortRef(detail.event_hash, 24)],
                  ["Previous digest", shortRef(detail.previous_event_hash, 24)],
                  ["Created at", formatTime(detail.created_at)],
                ]}
              />
              {safeDetailEntries(detail.details).length > 0 && (
                <div className="mad-code-groups">
                  <div>
                    <span>Safe detail fields</span>
                    <div>
                      {safeDetailEntries(detail.details).map(([key, value]) => (
                        <code key={key}>{key}: {value}</code>
                      ))}
                    </div>
                  </div>
                </div>
              )}
              <p className="mad-footnote"><AlertTriangle size={13} /> Content digests are provenance data, not proof of an unbroken tamper-evident chain.</p>
            </>
          )}
        </div>
      )}

      <div className="mad-footer">
        <ShieldCheck size={14} />
        <span>Audit history is read-only. No events are invented and no sensitive fields are echoed.</span>
      </div>
    </section>
  );
}
