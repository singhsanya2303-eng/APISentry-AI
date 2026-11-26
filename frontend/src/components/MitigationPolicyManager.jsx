import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Archive,
  BadgeCheck,
  CircleSlash,
  ClipboardCheck,
  FilePlus2,
  History,
  LoaderCircle,
  PlayCircle,
  RotateCcw,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { mitigationAdminApi } from "../services/api";
import {
  ACTIVATION_REASON_CODES,
  DEFAULT_ACTION_FORM,
  DEFAULT_POLICY_FORM,
  POLICY_MODES,
  buildCreatePolicyPayload,
  buildPolicyActionPayload,
  canManagePolicies,
  confirmationMessage,
  formatTime,
  lifecycleTone,
  nextVersion,
  nowLocalInput,
  parseEnforcementStatus,
  parsePolicyDetail,
  parsePolicyList,
  policyFormFrom,
  safeErrorMessage,
  shortRef,
} from "../utils/mitigationAdminHelpers";
import {
  ActionNotice,
  AdminHero,
  AdvisoryNote,
  EmptyPanel,
  ErrorPanel,
  KeyValueGrid,
  LoadingPanel,
  MessageStrip,
  StatusBadge,
} from "./MitigationAdminCommon";

function policyState(policy) {
  return typeof policy?.state === "string" ? policy.state : "UNKNOWN";
}

export default function MitigationPolicyManager({ role }) {
  const canManage = canManagePolicies(role);
  const [policies, setPolicies] = useState(null);
  const [status, setStatus] = useState(null);
  const [selectedVersion, setSelectedVersion] = useState("");
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listError, setListError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [form, setForm] = useState(() => ({
    ...DEFAULT_POLICY_FORM,
    created_at: nowLocalInput(),
  }));
  const [formError, setFormError] = useState("");
  const [formNotice, setFormNotice] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [actionForm, setActionForm] = useState(() => ({
    ...DEFAULT_ACTION_FORM,
    at: nowLocalInput(),
  }));
  const [actionError, setActionError] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [confirmAction, setConfirmAction] = useState(null);
  const submitLock = useRef(false);

  const loadDetail = useCallback(async (version) => {
    if (!version) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    setDetailError("");
    try {
      const data = await mitigationAdminApi.getPolicy(version);
      setDetail(parsePolicyDetail(data));
    } catch (error) {
      setDetail(null);
      setDetailError(safeErrorMessage(error, "Policy details could not be loaded."));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    setListError("");
    try {
      const [listResponse, statusResponse] = await Promise.all([
        mitigationAdminApi.listPolicies(),
        mitigationAdminApi.getEnforcementStatus(),
      ]);
      const parsedList = parsePolicyList(listResponse);
      setPolicies(parsedList);
      setStatus(parseEnforcementStatus(statusResponse));
      const nextVersion =
        parsedList.activeVersion || parsedList.versions[0] || "";
      setSelectedVersion((current) => current || nextVersion);
    } catch (error) {
      setPolicies(null);
      setStatus(null);
      setListError(safeErrorMessage(error, "Policy data could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer external synchronization so the first render is not forced to
    // re-render synchronously from the effect body.
    Promise.resolve().then(() => loadData());
  }, [loadData]);

  useEffect(() => {
    if (!selectedVersion) return;
    Promise.resolve().then(() => loadDetail(selectedVersion));
  }, [selectedVersion, loadDetail]);

  function updateForm(key, value) {
    setForm((previous) => ({ ...previous, [key]: value }));
  }

  function updateActionForm(key, value) {
    setActionForm((previous) => ({ ...previous, [key]: value }));
  }

  async function handleCreate(event) {
    event.preventDefault();
    if (submitLock.current) return;
    setFormError("");
    setFormNotice("");

    let body;
    try {
      body = buildCreatePolicyPayload(form);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Review the policy form.");
      return;
    }

    submitLock.current = true;
    setSubmitting(true);
    try {
      await mitigationAdminApi.createPolicy(body);
      const createdVersion = body.config.policy_version;
      setFormNotice(
        `Policy version ${createdVersion} was proposed. A 2xx response does not confirm persistence; the policy list and lifecycle status were refreshed.`
      );
      setSelectedVersion(createdVersion);
      setForm((previous) => ({
        ...previous,
        policy_version: nextVersion(createdVersion),
        created_at: nowLocalInput(),
        predecessor_version: createdVersion,
      }));
      await loadData();
      await loadDetail(createdVersion);
    } catch (error) {
      setFormError(safeErrorMessage(error, "The policy could not be proposed."));
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }

  function proposeReplacement(policy) {
    if (!canManage || !policy) return;
    setForm(policyFormFrom(policy));
    setFormError("");
    setFormNotice(
      "Gate C has no in-place edit endpoint. The form is prefilled to propose a new immutable version with the selected version as predecessor."
    );
  }

  function requestAction(type, version) {
    if (!canManage || !version) return;
    setActionError("");
    setActionNotice("");
    setActionForm((previous) => ({ ...previous, version }));
    setConfirmAction({ type, version, message: confirmationMessage(type, version) });
  }

  async function runConfirmedAction() {
    if (!confirmAction || submitLock.current) return;
    const { type, version } = confirmAction;
    setActionError("");
    setActionNotice("");

    let body;
    try {
      const payloadForm = { ...actionForm, version };
      body = buildPolicyActionPayload(payloadForm, type);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Review the lifecycle form.");
      return;
    }

    submitLock.current = true;
    setSubmitting(true);
    try {
      if (type === "validate") await mitigationAdminApi.validatePolicy(version, body);
      else if (type === "activate") await mitigationAdminApi.activatePolicy(version, body);
      else if (type === "deactivate") await mitigationAdminApi.deactivatePolicy(body);
      else if (type === "retire") await mitigationAdminApi.retirePolicy(version, body);
      else if (type === "rollback") await mitigationAdminApi.rollbackPolicy(version, body);

      setConfirmAction(null);
      setActionNotice(
        `${type} request accepted for ${version}. The mutation body does not report persistence outcome; policy data and lifecycle status were refreshed. No enforcement was enabled or disabled.`
      );
      await loadData();
      await loadDetail(version);
    } catch (error) {
      setActionError(safeErrorMessage(error, "The lifecycle action could not be completed."));
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }

  const actionButtons = [
    { type: "validate", label: "Validate", icon: ClipboardCheck },
    { type: "activate", label: "Activate", icon: PlayCircle },
    { type: "deactivate", label: "Deactivate", icon: CircleSlash },
    { type: "retire", label: "Retire", icon: Archive },
    { type: "rollback", label: "Rollback", icon: RotateCcw },
  ];

  return (
    <section className="mad-v2">
      <AdminHero
        title="Mitigation policies"
        description="Inspect immutable policy versions and request advisory lifecycle transitions. Nothing here enforces traffic."
        endpoint="/api/v1/security/mitigation/policies"
        icon={SlidersHorizontal}
      />

      <AdvisoryNote>
        Policy activation changes advisory lifecycle state only. It does not enable blocking, throttling, challenges, middleware, or any other request enforcement.
      </AdvisoryNote>

      <MessageStrip message={formNotice} onDismiss={() => setFormNotice("")} />
      <MessageStrip message={actionNotice} onDismiss={() => setActionNotice("")} />

      <div className="mad-card">
        <div className="mad-card-head">
          <div>
            <span className="mad-step">01 / LIFECYCLE STATUS</span>
            <h3>Current advisory state</h3>
            <p>Read-only projection from the enforcement status route.</p>
          </div>
          <BadgeCheck size={18} />
        </div>
        {loading ? (
          <LoadingPanel label="Loading lifecycle status…" />
        ) : status ? (
          <>
            <div className="mad-stats">
              <div><span>Enforcement active</span><strong>{status.enforcementActive ? "Yes" : "No"}</strong></div>
              <div><span>Advisory only</span><strong>{status.advisoryOnly ? "Yes" : "No"}</strong></div>
              <div><span>Active version</span><strong>{status.activeVersion || "None"}</strong></div>
              <div><span>Persisted version</span><strong>{status.persistedActiveVersion || "None"}</strong></div>
              <div><span>Policy mode</span><strong>{status.policyMode || "—"}</strong></div>
              <div><span>Policy available</span><strong>{status.policyAvailable ? "Yes" : "No"}</strong></div>
              <div><span>Activation events</span><strong>{status.activationEventCount ?? "—"}</strong></div>
              <div><span>Latest event</span><strong>{status.latestActivationEventType || "—"}</strong></div>
            </div>
            <p className="mad-footnote">
              In-memory lifecycle state and persisted active version can diverge after a restart. Treat this as status information, not an enforcement guarantee.
            </p>
          </>
        ) : (
          <ErrorPanel message={listError} onRetry={loadData} />
        )}
      </div>

      <div className="mad-grid">
        <div className="mad-card">
          <div className="mad-card-head">
            <div>
              <span className="mad-step">02 / VERSIONS</span>
              <h3>Policy versions</h3>
              <p>Immutable versions returned by the authenticated API.</p>
            </div>
            <History size={18} />
          </div>
          {loading ? (
            <LoadingPanel label="Loading policies…" />
          ) : listError ? (
            <ErrorPanel message={listError} onRetry={loadData} />
          ) : !policies || policies.policies.length === 0 ? (
            <EmptyPanel title="No policy versions returned">
              Propose a policy version with the form below. Gate C does not create a policy during dry-run evaluation.
            </EmptyPanel>
          ) : (
            <div className="mad-list">
              {policies.policies.map((policy) => {
                const version = policy.policy_version;
                const active = version === policies.activeVersion;
                return (
                  <button
                    key={version}
                    type="button"
                    className={`mad-list-row ${version === selectedVersion ? "selected" : ""}`}
                    onClick={() => setSelectedVersion(version)}
                  >
                    <div>
                      <strong>{version}</strong>
                      <span>{formatTime(policy.created_at)}</span>
                    </div>
                    <div>
                      <StatusBadge label={policyState(policy)} tone={lifecycleTone(policyState(policy))} />
                      {active && <StatusBadge label="Active" tone="ok" />}
                    </div>
                    <code>{shortRef(policy.config_digest, 16)}</code>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="mad-card">
          <div className="mad-card-head">
            <div>
              <span className="mad-step">03 / DETAILS</span>
              <h3>Selected policy</h3>
              <p>Exact fields exposed by the Gate C policy response.</p>
            </div>
            <ShieldCheck size={18} />
          </div>
          {detailLoading ? (
            <LoadingPanel label="Loading policy details…" />
          ) : detailError ? (
            <ErrorPanel message={detailError} onRetry={() => loadDetail(selectedVersion)} />
          ) : !detail ? (
            <EmptyPanel title="No policy selected">Select a version from the list to inspect its immutable configuration.</EmptyPanel>
          ) : (
            <>
              <KeyValueGrid
                entries={[
                  ["Version", detail.policy_version],
                  ["State", <StatusBadge key="state" label={policyState(detail)} tone={lifecycleTone(policyState(detail))} />],
                  ["Created", formatTime(detail.created_at)],
                  ["Valid from", formatTime(detail.valid_from)],
                  ["Valid until", formatTime(detail.valid_until)],
                  ["Owner role", detail.owner_role || "—"],
                  ["Owner hash", shortRef(detail.owner_actor_hash, 20)],
                  ["Approved by", shortRef(detail.approved_by_hash, 20)],
                  ["Predecessor", detail.predecessor_version || "None"],
                  ["Config digest", shortRef(detail.config_digest, 20)],
                ]}
              />
              <details className="mad-disclosure">
                <summary>Immutable policy configuration</summary>
                <pre>{JSON.stringify(detail.config || {}, null, 2)}</pre>
              </details>
              {canManage && (
                <button className="mad-button" type="button" onClick={() => proposeReplacement(detail)}>
                  <FilePlus2 size={14} /> Propose replacement version
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {canManage && (
        <div className="mad-card">
          <div className="mad-card-head">
            <div>
              <span className="mad-step">04 / PROPOSE</span>
              <h3>Create a new immutable policy version</h3>
              <p>Validation mirrors the Gate C request schema. Creation never activates a policy.</p>
            </div>
            <FilePlus2 size={18} />
          </div>
          <form className="mad-form" onSubmit={handleCreate} noValidate>
            <div className="mad-form-grid">
              <label><span>Policy version</span><input value={form.policy_version} onChange={(e) => updateForm("policy_version", e.target.value)} /></label>
              <label><span>Created at</span><input type="datetime-local" value={form.created_at} onChange={(e) => updateForm("created_at", e.target.value)} /></label>
              <label><span>Mode</span><select value={form.mode} onChange={(e) => updateForm("mode", e.target.value)}>{POLICY_MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</select></label>
              <label><span>Predecessor version (optional)</span><input value={form.predecessor_version} onChange={(e) => updateForm("predecessor_version", e.target.value)} /></label>
              <label><span>Valid from (optional)</span><input type="datetime-local" value={form.valid_from} onChange={(e) => updateForm("valid_from", e.target.value)} /></label>
              <label><span>Valid until (optional)</span><input type="datetime-local" value={form.valid_until} onChange={(e) => updateForm("valid_until", e.target.value)} /></label>
              <label><span>Monitoring threshold</span><input type="number" min="0" max="100" step="0.1" value={form.monitoring_score_threshold} onChange={(e) => updateForm("monitoring_score_threshold", e.target.value)} /></label>
              <label><span>Throttling threshold</span><input type="number" min="0" max="100" step="0.1" value={form.throttling_score_threshold} onChange={(e) => updateForm("throttling_score_threshold", e.target.value)} /></label>
              <label><span>Blocking threshold</span><input type="number" min="0" max="100" step="0.1" value={form.blocking_score_threshold} onChange={(e) => updateForm("blocking_score_threshold", e.target.value)} /></label>
              <label><span>Minimum auth failures</span><input type="number" min="1" max="1000" value={form.minimum_authentication_failures} onChange={(e) => updateForm("minimum_authentication_failures", e.target.value)} /></label>
              <label><span>Throttle limit</span><input type="number" min="1" max="100000" value={form.throttle_limit} onChange={(e) => updateForm("throttle_limit", e.target.value)} /></label>
              <label><span>Throttle window (s)</span><input type="number" min="1" max="86400" value={form.throttle_window_seconds} onChange={(e) => updateForm("throttle_window_seconds", e.target.value)} /></label>
              <label><span>Throttle duration (s)</span><input type="number" min="1" max="86400" value={form.throttle_duration_seconds} onChange={(e) => updateForm("throttle_duration_seconds", e.target.value)} /></label>
              <label><span>Block duration (s)</span><input type="number" min="1" max="86400" value={form.block_duration_seconds} onChange={(e) => updateForm("block_duration_seconds", e.target.value)} /></label>
              <label><span>Max block duration (s)</span><input type="number" min="1" max="604800" value={form.max_block_duration_seconds} onChange={(e) => updateForm("max_block_duration_seconds", e.target.value)} /></label>
              <label><span>Max evidence references</span><input type="number" min="0" max="200" value={form.max_evidence_references} onChange={(e) => updateForm("max_evidence_references", e.target.value)} /></label>
            </div>
            <div className="mad-checks">
              <label><input type="checkbox" checked={form.enabled} onChange={(e) => updateForm("enabled", e.target.checked)} /> Enabled</label>
              <label><input type="checkbox" checked={form.require_grouped_brute_force} onChange={(e) => updateForm("require_grouped_brute_force", e.target.checked)} /> Require grouped brute force</label>
              <label><input type="checkbox" checked={form.throttle_enabled} onChange={(e) => updateForm("throttle_enabled", e.target.checked)} /> Throttle recommendations allowed</label>
              <label><input type="checkbox" checked={form.block_enabled} onChange={(e) => updateForm("block_enabled", e.target.checked)} /> Block recommendations allowed</label>
              <label><input type="checkbox" checked={form.admin_protection_enabled} onChange={(e) => updateForm("admin_protection_enabled", e.target.checked)} /> Admin protection enabled</label>
            </div>
            <p className="mad-footnote">Throttle and block settings are advisory policy configuration only. No request is acted upon by this dashboard.</p>
            {formError && <div className="mad-inline-error" role="alert"><AlertTriangle size={14} /> {formError}</div>}
            <div className="mad-actions">
              <button className="mad-button mad-button-primary" type="submit" disabled={submitting || !canManage}>
                {submitting ? <LoaderCircle className="mad-spin" size={14} /> : <FilePlus2 size={14} />}
                {submitting ? "Submitting…" : "Propose policy version"}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="mad-card">
        <div className="mad-card-head">
          <div>
            <span className="mad-step">05 / LIFECYCLE ACTIONS</span>
            <h3>Version transitions</h3>
            <p>Every transition requires explicit confirmation before the request is sent.</p>
          </div>
          <RotateCcw size={18} />
        </div>

        {!canManage ? (
          <ActionNotice>
            Admin role is required for lifecycle operations. Analyst and viewer roles are read-only here; the backend remains authoritative even if an action is triggered outside this dashboard.
          </ActionNotice>
        ) : (
          <>
            <div className="mad-form-grid">
              <label><span>Action time</span><input type="datetime-local" value={actionForm.at} onChange={(e) => updateActionForm("at", e.target.value)} /></label>
              <label>
                <span>Expected active version</span>
                <select value={actionForm.expectedMode} onChange={(e) => updateActionForm("expectedMode", e.target.value)}>
                  <option value="omit">No expectation (omit field)</option>
                  <option value="null">Expect none (send null)</option>
                  <option value="version">Expect specific version</option>
                </select>
              </label>
              {actionForm.expectedMode === "version" && (
                <label><span>Expected version</span><input value={actionForm.expectedVersion} onChange={(e) => updateActionForm("expectedVersion", e.target.value)} /></label>
              )}
              <label>
                <span>Reason code</span>
                <select value={actionForm.reason_code} onChange={(e) => updateActionForm("reason_code", e.target.value)}>
                  {ACTIVATION_REASON_CODES.map((code) => <option key={code} value={code}>{code}</option>)}
                </select>
              </label>
            </div>
            <p className="mad-footnote">Omitting expected_active_version and sending explicit null are different assertions. The dashboard preserves that distinction.</p>

            <div className="mad-actions">
              {actionButtons.map(({ type, label, icon: Icon }) => (
                <button
                  key={type}
                  className="mad-button"
                  type="button"
                  disabled={submitting || !selectedVersion}
                  onClick={() => requestAction(type, selectedVersion)}
                >
                  <Icon size={14} /> {label}
                </button>
              ))}
            </div>

            {confirmAction && (
              <div className="mad-confirm" role="alertdialog" aria-label="Confirm lifecycle action">
                <div>
                  <strong>Confirm {confirmAction.type}</strong>
                  <p>{confirmAction.message}</p>
                  <code>Selected version: {confirmAction.version}</code>
                </div>
                <div className="mad-actions">
                  <button className="mad-button mad-button-danger" type="button" disabled={submitting} onClick={runConfirmedAction}>
                    {submitting ? <LoaderCircle className="mad-spin" size={14} /> : <ShieldCheck size={14} />}
                    {submitting ? "Confirming…" : "Confirm action"}
                  </button>
                  <button className="mad-button" type="button" disabled={submitting} onClick={() => setConfirmAction(null)}>Cancel</button>
                </div>
              </div>
            )}
            {actionError && <div className="mad-inline-error" role="alert"><AlertTriangle size={14} /> {actionError}</div>}
          </>
        )}
      </div>

      <div className="mad-footer">
        <ShieldCheck size={14} />
        <span>Advisory lifecycle management only. No block, deny, throttle, challenge, middleware, or network enforcement is performed.</span>
      </div>
    </section>
  );
}
