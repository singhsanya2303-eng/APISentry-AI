import { useState } from "react";
import {
  Activity,
  Beaker,
  FileClock,
  History,
  ShieldOff,
  Siren,
  SlidersHorizontal,
} from "lucide-react";
import MitigationAuditHistory from "./MitigationAuditHistory";
import MitigationDecisionHistory from "./MitigationDecisionHistory";
import MitigationDemoPanel from "./MitigationDemoPanel";
import RequestEnforcementDemoPanel from "./RequestEnforcementDemoPanel";
import MitigationDryRun from "./MitigationDryRun";
import MitigationPolicyManager from "./MitigationPolicyManager";
import { AdvisoryNote } from "./MitigationAdminCommon";
import { canManagePolicies, canUseMitigationDashboard } from "../utils/mitigationAdminHelpers";
import "./MitigationAdmin.css";

const TABS = [
  { label: "Policies", icon: SlidersHorizontal },
  { label: "Dry Run", icon: Beaker },
  { label: "Decisions", icon: History },
  { label: "Audit", icon: FileClock },
  { label: "Demo", icon: Siren },
  { label: "Isolated Enforcement", icon: Activity },
];

export default function MitigationAdminDashboard({ role }) {
  const [activeTab, setActiveTab] = useState("Policies");

  if (!canUseMitigationDashboard(role)) {
    return (
      <section className="mad-v2">
        <div className="mad-card">
          <div className="mad-card-head">
            <div>
              <span className="mad-step">ACCESS RESTRICTED</span>
              <h3>Mitigation administration unavailable</h3>
              <p>Gate C requires the admin or analyst role for every read and dry-run endpoint.</p>
            </div>
            <ShieldOff size={20} />
          </div>
          <p className="mad-footnote">
            Viewer access is not available for these routes. Backend authorization remains authoritative; the dashboard does not bypass or elevate roles.
          </p>
        </div>
      </section>
    );
  }

  const canManage = canManagePolicies(role);

  return (
    <section className="mad-dashboard">
      <nav className="mad-tabs" aria-label="Mitigation administration sections">
        {TABS.map(({ label, icon: Icon }) => (
          <button
            key={label}
            type="button"
            className={`mad-tab ${activeTab === label ? "active" : ""}`}
            aria-pressed={activeTab === label}
            onClick={() => setActiveTab(label)}
          >
            <Icon size={15} /> {label}
          </button>
        ))}
        <span className="mad-role">
          {role === "admin" ? "Admin: lifecycle + advisory" : "Analyst: advisory + read-only policies"}
        </span>
      </nav>

      {!canManage && (
        <AdvisoryNote title="Read-only policy view">
          Policy lifecycle actions require the admin role. Backend authorization is authoritative; hidden actions are still protected server-side.
        </AdvisoryNote>
      )}

      {activeTab === "Policies" ? (
        <MitigationPolicyManager role={role} />
      ) : activeTab === "Dry Run" ? (
        <MitigationDryRun />
      ) : activeTab === "Decisions" ? (
        <MitigationDecisionHistory />
      ) : activeTab === "Audit" ? (
        <MitigationAuditHistory />
      ) : activeTab === "Demo" ? (
        <MitigationDemoPanel role={role} />
      ) : (
        <RequestEnforcementDemoPanel role={role} />
      )}
    </section>
  );
}
