import AnalysisPanel from "./components/AnalysisPanel";
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  Clock3,
  Code2,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Network,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const API_KEY = import.meta.env.VITE_APISENTRY_API_KEY || "";

const modules = [
  { label: "Clustering", path: "/api/v1/security/clustering/analyze", icon: Network },
{ label: "Token Classification", path: "/api/v1/security/token-classifier/predict", icon: Code2 },
{ label: "Traffic Trend", path: "/api/v1/security/traffic-trends/analyze", icon: Activity },
  { label: "Behavioral Risk", path: "/api/v1/security/behavior/analyze", icon: Fingerprint },
  { label: "BOLA Detection", path: "/api/v1/security/bola/analyze", icon: LockKeyhole },
  { label: "Brute-Force", path: "/api/v1/security/bruteforce/analyze", icon: ShieldAlert },
  { label: "Rate Anomaly", path: "/api/v1/security/rate-anomaly/analyze", icon: Gauge },
];



function App() {
  const [apiStatus, setApiStatus] = useState("checking");
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeModule, setActiveModule] = useState("Overview");
  const [mobileMenu, setMobileMenu] = useState(false);
  const [lastChecked, setLastChecked] = useState(null);
  const [analysisResults, setAnalysisResults] = useState({});

  async function checkHealth() {
    setLoading(true);
    setHealthError("");

    try {
      const response = await fetch(`${API_BASE}/health`, {
        headers: API_KEY ? { "X-API-Key": API_KEY } : {},
      });

      if (!response.ok) {
        throw new Error(`Health endpoint returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setHealth(data);
      setApiStatus("online");
      setLastChecked(new Date());
    } catch (error) {
      setHealth(null);
      setApiStatus("offline");
      setHealthError(
        error instanceof Error ? error.message : "Unable to reach the API."
      );
      setLastChecked(new Date());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    checkHealth();
  }, []);

  const trafficResult = analysisResults["Traffic Trend"];
  const trafficPredictions = Array.isArray(trafficResult?.predictions)
    ? trafficResult.predictions
    : [];

  const trafficChartData = trafficPredictions.map((item) => ({
    time: item.window_start
      ? new Date(item.window_start).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })
      : "—",
    error: Number(item.reconstruction_error ?? 0),
    anomaly: Boolean(item.is_anomaly),
  }));

  const recentIncidents = trafficPredictions
    .filter((item) => item.is_anomaly)
    .slice()
    .reverse()
    .slice(0, 5);

  const navItems = [
    { label: "Overview", icon: LayoutDashboard },
    { label: "Threat Detection", icon: ShieldAlert },
    { label: "API Modules", icon: Network },
  ];

  return (
    <div className="app-shell">
      {mobileMenu && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setMobileMenu(false)}
        />
      )}

      <aside className={`sidebar ${mobileMenu ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={23} /></div>
          <div>
            <div className="brand-name">APISENTRY<span>AI</span></div>
            <div className="brand-caption">API SECURITY PLATFORM</div>
          </div>
          <button className="icon-button mobile-close" onClick={() => setMobileMenu(false)}>
            <X size={19} />
          </button>
        </div>

        <div className="workspace">
          <div className="workspace-icon"><Terminal size={17} /></div>
          <div className="workspace-copy">
            <strong>Security Workspace</strong>
            <span>Development environment</span>
          </div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="nav-list">
          {navItems.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activeModule === label ? "nav-active" : ""}`}
              onClick={() => {
                setActiveModule(label);
                setMobileMenu(false);
              }}
            >
              <Icon size={18} />
              <span>{label}</span>
              {label === "Threat Detection" && <span className="nav-dot" />}
            </button>
          ))}
        </nav>

        <div className="nav-label module-label">SECURITY ANALYSIS</div>
        <nav className="nav-list">
          {modules.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activeModule === label ? "nav-active" : ""}`}
              onClick={() => {
                setActiveModule(label);
                setMobileMenu(false);
              }}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="security-note">
            <div className="note-icon"><Shield size={17} /></div>
            <strong>Security first</strong>
            <p>Monitor API behavior and investigate suspicious activity.</p>
          </div>
          <div className="user-profile">
            <div className="avatar">AS</div>
            <div className="profile-info">
              <strong>Security Analyst</strong>
              <span>Local demo workspace</span>
            </div>
            <CircleDot size={15} className="profile-status" />
          </div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu-button" onClick={() => setMobileMenu(true)}>
              <Menu size={21} />
            </button>
            <div className="breadcrumb">Workspace <span>/</span> <strong>{activeModule}</strong></div>
          </div>
          <div className="topbar-actions">
            <div className={`connection-pill ${apiStatus}`}>
              <span className="status-dot" />
              {apiStatus === "checking" ? "Checking API" : apiStatus === "online" ? "API Connected" : "API Offline"}
            </div>
            <button className="icon-button notification-button" aria-label="Notifications">
              <Bell size={18} />
            </button>
            <div className="top-avatar">AS</div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> API SECURITY INTELLIGENCE</div>
              <h1>{activeModule === "Overview" ? "Security Overview" : activeModule}</h1>
              <p className="page-subtitle">
                Monitor API behavior, inspect detection modules, and assess service health.
              </p>
            </div>
            <button className="refresh-button" onClick={checkHealth} disabled={loading}>
              <RefreshCw size={16} className={loading ? "spin" : ""} />
              {loading ? "Checking..." : "Refresh status"}
            </button>
          </section>

          <section className={`api-banner ${apiStatus}`}>
            <div className="banner-icon">
              {apiStatus === "online" ? <CheckCircle2 size={22} /> : apiStatus === "offline" ? <AlertTriangle size={22} /> : <Activity size={22} />}
            </div>
            <div className="banner-copy">
              <strong>
                {apiStatus === "checking" && "Connecting to APISentry backend"}
                {apiStatus === "online" && `${health?.service || "APISentry API"} is reachable`}
                {apiStatus === "offline" && "Backend connection unavailable"}
              </strong>
              <p>
                {apiStatus === "checking" && "Checking the health endpoint. Please wait."}
                {apiStatus === "online" &&
  (trafficResult
    ? "Backend is reachable. Latest Traffic Trend analysis is loaded in this session."
    : "Backend is reachable. Run a detection module to load analysis data.")}
                {apiStatus === "offline" && (healthError || "Start the FastAPI backend and check its configuration.")}
              </p>
            </div>
            <span className="banner-tag">
              {apiStatus === "online" ? "CONNECTED" : apiStatus === "checking" ? "CHECKING" : "NEEDS ATTENTION"}
            </span>
          </section>

          {activeModule === "Overview" ? (
            <>
              <section className="section-heading">
                <div>
                  <h2>System snapshot</h2>
                  <p>Live backend connectivity and available analysis modules.</p>
                </div>
                <span className="section-period"><Clock3 size={14} /> Current session</span>
              </section>

              <section className="metric-grid">
                <MetricCard
                  icon={Activity}
                  label="API availability"
                  value={apiStatus === "online" ? "Online" : apiStatus === "checking" ? "Checking" : "Offline"}
                  detail={apiStatus === "online" ? "Health endpoint responded" : "Based on the latest health check"}
                  tone={apiStatus === "online" ? "green" : apiStatus === "offline" ? "red" : "blue"}
                />
                <MetricCard
                  icon={ShieldCheck}
                  label="Detection modules"
                  value={`${modules.length}`}
                  detail="Configured analysis endpoints"
                  tone="blue"
                />
                <MetricCard
                  icon={Activity}
                  label="Target windows"
                  value={trafficResult ? trafficResult.target_window_count ?? "—" : "—"}
                  detail={trafficResult ? `${trafficResult.baseline_window_count ?? "—"} baseline windows` : "Run Traffic Trend to load data"}
                  tone="purple"
                />
                <MetricCard
                  icon={AlertTriangle}
                  label="Anomalies detected"
                  value={trafficResult ? trafficResult.anomaly_count ?? "—" : "—"}
                  detail={trafficResult ? "From the latest Traffic Trend response" : "No analysis results loaded"}
                  tone="amber"
                />
              </section>

              <section className="content-grid">
                <div className="panel traffic-panel">
                  <div className="panel-header">
                    <div>
                      <h3>API traffic activity</h3>
                      <p>Reconstruction error across analyzed traffic windows</p>
                    </div>
                    <span className="live-label"><span /> {trafficResult ? "ANALYSIS LOADED" : "AWAITING ANALYSIS"}</span>
                  </div>
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trafficChartData} margin={{ top: 12, right: 8, left: -18, bottom: 0 }}>
                        <defs>
                          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#25c7a5" stopOpacity={0.22} />
                            <stop offset="95%" stopColor="#25c7a5" stopOpacity={0.01} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="#263344" strokeDasharray="4 5" vertical={false} />
                        <XAxis dataKey="time" tick={{ fill: "#78889d", fontSize: 11 }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fill: "#78889d", fontSize: 11 }} axisLine={false} tickLine={false} />
                        <Tooltip
                          contentStyle={{ background: "#101a27", border: "1px solid #2a394a", borderRadius: 9, color: "#e6edf5" }}
                          labelStyle={{ color: "#aab8c8" }}
                        />
                        <Area type="monotone" dataKey="error" name="Reconstruction error" stroke="#25c7a5" strokeWidth={2} fill="url(#trafficFill)" />
                      </AreaChart>
                    </ResponsiveContainer>
                    {trafficChartData.length === 0 && (
                      <div className="chart-empty">
                        <Activity size={18} />
                        <span>Run Traffic Trend to load actual traffic-window results.</span>
                      </div>
                    )}
                  </div>
                  <div className="chart-footer">
                    <span><span className="legend-dot" /> Reconstruction error</span>
                    <span>{trafficResult ? `${trafficPredictions.length} target windows analyzed` : "No analysis results loaded"}</span>
                  </div>
                </div>

                <div className="panel modules-panel">
                  <div className="panel-header">
                    <div>
                      <h3>Security modules</h3>
                      <p>Available backend analysis routes</p>
                    </div>
                    <span className="count-badge">{modules.length}</span>
                  </div>
                  <div className="module-list">
                    {modules.map(({ label, path, icon: Icon }) => (
                      <button className="module-row" key={label} onClick={() => setActiveModule(label)}>
                        <div className="module-icon"><Icon size={18} /></div>
                        <div className="module-copy">
                          <strong>{label}</strong>
                          <span>{path}</span>
                        </div>
                        <ArrowUpRight size={16} className="module-arrow" />
                      </button>
                    ))}
                  </div>
                  <div className="panel-footnote">
                    <CheckCircle2 size={14} />
                    <span>Routes discovered from the current backend configuration.</span>
                  </div>
                </div>
              </section>

              <section className="panel incidents-panel">
                <div className="panel-header">
                  <div>
                    <h3>Recent anomaly signals</h3>
                    <p>Flagged windows from the latest Traffic Trend analysis</p>
                  </div>
                  <span className="count-badge">{recentIncidents.length}</span>
                </div>
                {recentIncidents.length > 0 ? (
                  <div className="incident-list">
                    {recentIncidents.map((item, index) => (
                      <div className="incident-row" key={`${item.window_start}-${index}`}>
                        <div className="incident-indicator"><AlertTriangle size={17} /></div>
                        <div className="incident-copy">
                          <strong>Traffic anomaly flagged</strong>
                          <span>{item.window_start ? new Date(item.window_start).toLocaleString() : "Unknown time"}</span>
                        </div>
                        <div className="incident-error">
                          <span>Reconstruction error</span>
                          <strong>{Number(item.reconstruction_error ?? 0).toFixed(3)}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="incidents-empty">
                    <ShieldCheck size={21} />
                    <strong>{trafficResult ? "No anomaly signals in this response" : "No analysis loaded yet"}</strong>
                    <p>Run Traffic Trend to populate this section from backend results.</p>
                  </div>
                )}
              </section>

              <section className="panel health-panel">
                <div className="panel-header">
                  <div>
                    <h3>Service diagnostics</h3>
                    <p>Most recent connectivity check</p>
                  </div>
                  <button className="text-button" onClick={checkHealth} disabled={loading}>
                    <RefreshCw size={14} /> Run check
                  </button>
                </div>
                <div className="diagnostic-grid">
                  <div className="diagnostic-item">
                    <span>Backend base URL</span>
                    <code>{API_BASE}</code>
                  </div>
                  <div className="diagnostic-item">
                    <span>Health endpoint</span>
                    <code>/health</code>
                  </div>
                  <div className="diagnostic-item">
                    <span>Last checked</span>
                    <strong>{lastChecked ? lastChecked.toLocaleTimeString() : "Not checked yet"}</strong>
                  </div>
                  <div className="diagnostic-item">
                    <span>Service response</span>
                    <strong className={apiStatus === "online" ? "text-green" : apiStatus === "offline" ? "text-red" : ""}>
                      {health?.status || (apiStatus === "checking" ? "Checking…" : "Unavailable")}
                    </strong>
                  </div>
                </div>
              </section>
            </>
          ) : activeModule === "API Modules" ? (
            <section className="panel detail-panel">
              <div className="panel-header">
                <div><h3>Registered analysis modules</h3><p>Routes currently identified in the FastAPI application.</p></div>
                <Code2 size={20} />
              </div>
              {modules.map(({ label, path, icon: Icon }) => (
                <div className="detail-route" key={path}>
                  <Icon size={18} />
                  <div><strong>{label}</strong><code>{path}</code></div>
                  <span className="method-get">GET</span>
                </div>
              ))}
              <p className="detail-note">The exact HTTP method and required query parameters should be verified in each route definition before running an analysis.</p>
            </section>
                    ) : (
            <AnalysisPanel
  key={activeModule}
  moduleName={activeModule}
  onResult={(name, data) =>
    setAnalysisResults((previous) => ({
      ...previous,
      [name]: data,
    }))
  }
/>
          )}


          <footer className="app-footer">
            <div><ShieldCheck size={15} /> <span>APISentry AI</span><span className="footer-divider">·</span><span>API security monitoring</span></div>
            <span>Demo interface · Results reflect the latest completed analysis</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span>{label}</span>
        <div className={`metric-icon ${tone}`}><Icon size={18} /></div>
      </div>
      <div className={`metric-value ${tone === "green" ? "text-green" : tone === "red" ? "text-red" : ""}`}>{value}</div>
      <div className="metric-detail">
        <span className={`detail-dot ${tone}`} />
        {detail}
      </div>
    </article>
  );
}

export default App;
