import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  RefreshCw,
  ShieldCheck,
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

export default function SecurityOverview({
  apiStatus,
  health,
  lastChecked,
  analysisResults,
  trafficResult,
  trafficPredictions,
  trafficChartData,
  allRecentSignals,
  visibleModules,
  hasAnyResult,
  apiBase,
  loading,
  onRefreshHealth,
  onSelectModule,
}) {
  const hasTrafficData = trafficChartData.length > 0;
  const targetWindows = trafficResult?.target_window_count ?? "—";
  const baselineWindows = trafficResult?.baseline_window_count ?? "—";
  const anomalyCount = trafficResult?.anomaly_count;

  const signalDetail = trafficResult
    ? `${typeof anomalyCount === "number" ? anomalyCount : 0} traffic anomalies, ${allRecentSignals.length} displayed signals`
    : hasAnyResult
      ? `${allRecentSignals.length} signal(s) from ${Object.keys(analysisResults).length} module(s)`
      : "No analysis results loaded";

  const connectionLabel =
    apiStatus === "online"
      ? "Connected"
      : apiStatus === "checking"
        ? "Checking"
        : "Unavailable";

  const serviceResponse =
    health?.status || (apiStatus === "checking" ? "Checking…" : "Unavailable");

  return (
    <>
      <section className="section-heading">
        <div>
          <h2>System snapshot</h2>
          <p>Session health and analysis results from the current backend.</p>
        </div>
        <span className="section-period"><Clock3 size={14} /> Current session</span>
      </section>

      <section className="metric-grid" aria-label="Security overview metrics">
        <MetricCard
          icon={Activity}
          label="API availability"
          value={connectionLabel}
          detail={
            apiStatus === "online"
              ? "Health endpoint responded"
              : apiStatus === "checking"
                ? "Health check in progress"
                : "Based on the latest health check"
          }
          tone={apiStatus === "online" ? "green" : apiStatus === "offline" ? "red" : "blue"}
        />
        <MetricCard
          icon={ShieldCheck}
          label="Available Modules"
          value={`${visibleModules.length}`}
          detail={
            visibleModules.length > 0
              ? "Configured analysis endpoints"
              : "No modules available for this role"
          }
          tone="blue"
        />
        <MetricCard
          icon={Activity}
          label="Target windows"
          value={`${targetWindows}`}
          detail={
            trafficResult
              ? `${baselineWindows} baseline windows`
              : "Run Traffic Trend to load data"
          }
          tone="purple"
        />
        <MetricCard
          icon={AlertTriangle}
          label="Recent Signals Displayed"
          value={hasAnyResult ? `${allRecentSignals.length}` : "—"}
          detail={signalDetail}
          tone={allRecentSignals.length > 0 ? "amber" : "blue"}
        />
      </section>

      <section className="content-grid">
        <div className="panel traffic-panel">
          <div className="panel-header">
            <div>
              <h3>API traffic activity</h3>
              <p>Reconstruction error across the analyzed traffic windows</p>
            </div>
            <span className={`live-label ${hasTrafficData ? "loaded" : ""}`}>
              <span aria-hidden="true" />
              {hasTrafficData ? "SESSION DATA" : "AWAITING ANALYSIS"}
            </span>
          </div>

          <div className="chart-wrap">
            {hasTrafficData ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={trafficChartData}
                  margin={{ top: 10, right: 10, left: 0, bottom: 2 }}
                >
                  <defs>
                    <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.18} />
                      <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.01} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="4 5" vertical={false} />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    minTickGap={18}
                  />
                  <YAxis
                    width={44}
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(value) => Number(value).toFixed(2)}
                  />
                  <Tooltip
                    cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }}
                    contentStyle={{
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 9,
                      color: "var(--text-primary)",
                      boxShadow: "var(--shadow-sm)",
                    }}
                    labelStyle={{ color: "var(--text-secondary)" }}
                    itemStyle={{ color: "var(--text-primary)" }}
                    labelFormatter={(label) => `Window ${label}`}
                    formatter={(value) => [Number(value).toFixed(3), "Reconstruction error"]}
                  />
                  <Area
                    type="monotone"
                    dataKey="error"
                    name="Reconstruction error"
                    stroke="var(--accent)"
                    strokeWidth={2}
                    fill="url(#trafficFill)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0 }}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="chart-empty" role="status">
                <Activity size={18} aria-hidden="true" />
                <span>Run Traffic Trend to load actual traffic-window results.</span>
              </div>
            )}
          </div>

          <div className="chart-footer">
            <span><span className="legend-dot" aria-hidden="true" /> Reconstruction error</span>
            <span>
              {trafficResult
                ? `${trafficPredictions.length} target windows analyzed${
                    typeof anomalyCount === "number" ? ` · ${anomalyCount} flagged` : ""
                  }`
                : "No analysis results loaded"}
            </span>
          </div>
        </div>

        <div className="panel modules-panel">
          <div className="panel-header">
            <div>
              <h3>Security modules</h3>
              <p>Available backend analysis routes</p>
            </div>
            <span className="count-badge" aria-label={`${visibleModules.length} modules`}>
              {visibleModules.length}
            </span>
          </div>
          <div className="module-list">
            {visibleModules.map(({ label, method, path, icon: Icon }) => (
              <button
                className="module-row"
                key={label}
                onClick={() => onSelectModule(label)}
                aria-label={`Open ${label} analysis module`}
              >
                <div className="module-icon"><Icon size={17} aria-hidden="true" /></div>
                <div className="module-copy">
                  <strong>{label}</strong>
                  <span className="module-route">
                    <span className="module-method">{method}</span>
                    <code className="module-path">{path}</code>
                  </span>
                </div>
                <ArrowUpRight size={15} className="module-arrow" aria-hidden="true" />
              </button>
            ))}
          </div>
          <div className="panel-footnote">
            <CheckCircle2 size={14} aria-hidden="true" />
            <span>Routes discovered from the current backend configuration.</span>
          </div>
        </div>
      </section>

      <section className="panel incidents-panel">
        <div className="panel-header">
          <div>
            <h3>Recent anomaly signals</h3>
            <p>Analysis-derived indicators from completed runs in this session</p>
          </div>
          <span className="count-badge" aria-label={`${allRecentSignals.length} signals`}>
            {allRecentSignals.length}
          </span>
        </div>
        {allRecentSignals.length > 0 ? (
          <div className="incident-list">
            {allRecentSignals.map((item) => (
              <div className="incident-row" key={item.id}>
                <div className="incident-indicator"><AlertTriangle size={17} aria-hidden="true" /></div>
                <div className="incident-copy">
                  <strong>{item.title}</strong>
                  <span>{item.time}</span>
                </div>
                <div className="incident-error">
                  <span>{item.metricLabel}</span>
                  <strong>{item.metricValue}</strong>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="incidents-empty" role="status">
            <ShieldCheck size={21} aria-hidden="true" />
            <strong>{hasAnyResult ? "No anomaly signals flagged in completed analyses" : "No analysis loaded yet"}</strong>
            <p>{hasAnyResult ? "Completed modules returned clean baseline verdicts." : "Run any analysis module to populate this section from backend results."}</p>
          </div>
        )}
        <div className="panel-footnote">
          <ShieldCheck size={14} aria-hidden="true" />
          <span>Historical analysis results, not a live monitoring feed.</span>
        </div>
      </section>

      <section className="panel health-panel">
        <div className="panel-header">
          <div>
            <h3>Service diagnostics</h3>
            <p>Most recent liveness response from the health endpoint</p>
          </div>
          <button className="text-button" onClick={onRefreshHealth} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} aria-hidden="true" />
            {loading ? "Checking…" : "Run check"}
          </button>
        </div>
        <div className="diagnostic-grid">
          <div className="diagnostic-item">
            <span>API connection</span>
            <strong className={apiStatus === "online" ? "text-green" : apiStatus === "offline" ? "text-red" : ""}>
              {connectionLabel}
            </strong>
          </div>
          <div className="diagnostic-item">
            <span>Service response</span>
            <strong className={apiStatus === "online" ? "text-green" : apiStatus === "offline" ? "text-red" : ""}>
              {serviceResponse}
            </strong>
          </div>
          <div className="diagnostic-item">
            <span>Service name</span>
            <strong>{health?.service || "—"}</strong>
          </div>
          <div className="diagnostic-item">
            <span>Environment</span>
            <strong>{health?.environment || "—"}</strong>
          </div>
          <div className="diagnostic-item">
            <span>Enforcement mode</span>
            <strong>{health?.enforcement?.mode || "—"}</strong>
          </div>
          <div className="diagnostic-item">
            <span>Last checked</span>
            <strong>{lastChecked ? lastChecked.toLocaleTimeString() : "Not checked yet"}</strong>
          </div>
          <div className="diagnostic-item">
            <span>Backend base URL</span>
            <code>{apiBase}</code>
          </div>
          <div className="diagnostic-item">
            <span>Health endpoint</span>
            <code>/health</code>
          </div>
        </div>
        <div className="panel-footnote">
          <ShieldCheck size={14} aria-hidden="true" />
          <span>Liveness response only; subsystem and detection health are not implied.</span>
        </div>
      </section>
    </>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }) {
  const unavailable = value === "—";
  return (
    <article
      className={`metric-card${unavailable ? " metric-card-muted" : ""}`}
      aria-label={`${label}: ${value}`}
    >
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <div className={`metric-icon ${tone}`}><Icon size={17} aria-hidden="true" /></div>
      </div>
      <div className={`metric-value ${tone === "green" ? "text-green" : tone === "red" ? "text-red" : ""}`}>
        {value}
      </div>
      <div className="metric-detail">
        <span className={`detail-dot ${tone}`} aria-hidden="true" />
        <span>{detail}</span>
      </div>
    </article>
  );
}
