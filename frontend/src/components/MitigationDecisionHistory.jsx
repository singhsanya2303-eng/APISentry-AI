import { useCallback, useState } from "react";
import {
  AlertTriangle,
  ChevronRight,
  History,
  LoaderCircle,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import {
  DECISION_TYPES,
  DEFAULT_DECISION_FILTERS,
  SCOPE_TYPES,
  buildDecisionParams,
  decisionTone,
  formatNumber,
  formatTime,
  labelize,
  parseDecisionDetail,
  parseDecisionList,
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

function reasonCodes(record) {
  return Array.isArray(record?.reason_codes) ? record.reason_codes : [];
}

function evidenceCount(record) {
  return Array.isArray(record?.evidence_references) ? record.evidence_references.length : 0;
}

export default function MitigationDecisionHistory() {
  const [filters, setFilters] = useState(() => ({ ...DEFAULT_DECISION_FILTERS }));
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
      params = buildDecisionParams(currentFilters);
    } catch (validationError) {
      setError(validationError instanceof Error ? validationError.message : "Review the decision filters.");
      setData(null);
      setHasRun(true);
      return;
    }

    setLoading(true);
    setError("");
    setHasRun(true);
    try {
      const response = await mitigationAdminApi.listDecisions(params);
      setData(parseDecisionList(response));
    } catch (requestError) {
      setData(null);
      setError(safeErrorMessage(requestError, "Decision history could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, []);

  function update(key, value) {
    setFilters((previous) => ({ ...previous, [key]: value, ...(key === "limit" || key === "offset" ? {} : { offset: "0" }) }));
  }

  function applyFilters(event) {
    event.preventDefault();
    load(filters);
  }

  async function openDetail(record) {
    const reference = record?.decision_uuid || record?.dedupe_key;
    if (!reference) return;
    setSelectedRef(reference);
    setDetail(null);
    setDetailError("");
    setDetailLoading(true);
    try {
      const response = await mitigationAdminApi.getDecision(reference);
      setDetail(parseDecisionDetail(response));
    } catch (requestError) {
      setDetailError(safeErrorMessage(requestError, "Decision details could not be loaded."));
    } finally {
      setDetailLoading(false);
    }
  }

  function reset() {
    const defaults = { ...DEFAULT_DECISION_FILTERS };
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
        title="Decision history"
        description="Persisted advisory decision records returned by the authenticated Gate C read APIs."
        endpoint="/api/v1/security/mitigation/decisions"
        icon={History}
      />

      <AdvisoryNote>
        Decision records are advisory. Gate C does not store the dry-run workflow fields for intended action or policy state; use the Dry Run tab for that detail.
      </AdvisoryNote>

      <form className="mad-card mad-form" onSubmit={applyFilters} noValidate>
        <div className="mad-card-head">
          <div>
            <span className="mad-step">01 / FILTERS</span>
            <h3>Backend-supported filters only</h3>
            <p>Ranges and limits are validated before the request is sent.</p>
          </div>
          <Search size={18} />
        </div>
        <div className="mad-form-grid">
          <label><span>Policy version</span><input value={filters.policy_version} onChange={(e) => update("policy_version", e.target.value)} /></label>
          <label><span>Decision reference</span><input value={filters.decision_ref} onChange={(e) => update("decision_ref", e.target.value)} /></label>
          <label>
            <span>Decision type</span>
            <select value={filters.decision_type} onChange={(e) => update("decision_type", e.target.value)}>
              <option value="">Any decision type</option>
              {DECISION_TYPES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label>
            <span>Scope type</span>
            <select value={filters.scope_type} onChange={(e) => update("scope_type", e.target.value)}>
              <option value="">Any scope type</option>
              {SCOPE_TYPES.map((value) => <option key={value} value={value}>{value}</option>)}
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
            <span className="mad-step">02 / RECORDS</span>
            <h3>Persisted advisory decisions</h3>
            <p>Ordered by the backend; no frontend sorting or invented fields.</p>
          </div>
          <span className="mad-count">{data ? formatNumber(data.total) : "—"} total</span>
        </div>

        {loading ? (
          <LoadingPanel label="Loading decision history…" />
        ) : error ? (
          <ErrorPanel message={error} onRetry={() => load(filters)} />
        ) : !hasRun ? (
          <EmptyPanel icon={History} title="No decision query run yet">
            Apply the filters to retrieve persisted advisory decision records.
          </EmptyPanel>
        ) : items.length === 0 ? (
          <EmptyPanel icon={ShieldCheck} title="No decision records returned">
            Gate C endpoints may not persist dry-run decisions. This empty result is not converted into a simulated success.
          </EmptyPanel>
        ) : (
          <>
            <div className="mad-table-wrap">
              <table className="mad-table">
                <thead>
                  <tr>
                    <th>Reference</th>
                    <th>Policy</th>
                    <th>Decision</th>
                    <th>Scope</th>
                    <th>Issued</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((record) => (
                    <tr key={record.decision_uuid || record.dedupe_key}>
                      <td><code>{shortRef(record.decision_uuid || record.dedupe_key, 18)}</code></td>
                      <td>{record.policy_version || "—"}</td>
                      <td><StatusBadge label={labelize(record.decision_type)} tone={decisionTone(record.decision_type)} /></td>
                      <td>{labelize(record.scope_type)}</td>
                      <td>{formatTime(record.issued_at)}</td>
                      <td>
                        <button className="mad-button mad-button-small" type="button" onClick={() => openDetail(record)}>
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
              <h3>Decision detail</h3>
              <p>{shortRef(selectedRef, 30)}</p>
            </div>
            <button className="mad-button mad-button-small" type="button" onClick={() => { setDetail(null); setSelectedRef(""); }}>
              <X size={13} /> Close
            </button>
          </div>
          {detailLoading ? (
            <LoadingPanel label="Loading decision detail…" />
          ) : detailError ? (
            <ErrorPanel message={detailError} onRetry={() => openDetail({ decision_uuid: selectedRef })} />
          ) : !detail ? (
            <EmptyPanel title="Decision detail unavailable">The selected decision could not be displayed.</EmptyPanel>
          ) : (
            <>
              <KeyValueGrid
                entries={[
                  ["Decision UUID", shortRef(detail.decision_uuid, 24)],
                  ["Dedupe key", shortRef(detail.dedupe_key, 24)],
                  ["Policy version", detail.policy_version || "—"],
                  ["Decision type", detail.decision_type || "—"],
                  ["Advisory only", detail.advisory_only ? "Yes" : "No"],
                  ["Attribution", detail.attribution_status || "—"],
                  ["Verified attribution", detail.verified_attribution ? "Yes" : "No"],
                  ["Issued at", formatTime(detail.issued_at)],
                  ["Expires at", formatTime(detail.expires_at)],
                  ["Created at", formatTime(detail.created_at)],
                  ["Evidence references", formatNumber(evidenceCount(detail))],
                ]}
              />
              <p className="mad-explanation">{detail.explanation || "No explanation was returned."}</p>
              <div className="mad-code-groups">
                <div>
                  <span>Reason codes</span>
                  <div>{reasonCodes(detail).map((code) => <code key={code}>{code}</code>)}</div>
                </div>
              </div>
              {detail.rate_limit != null && (
                <p className="mad-footnote">Advisory rate limit: {formatNumber(detail.rate_limit)} requests per {formatNumber(detail.rate_limit_window_seconds)} seconds. No rate limiting was applied.</p>
              )}
            </>
          )}
        </div>
      )}

      <div className="mad-footer">
        <AlertTriangle size={14} />
        <span>Decision history is read-only. Missing records are reported honestly and are never replaced with fabricated data.</span>
      </div>
    </section>
  );
}
