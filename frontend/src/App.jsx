import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  Braces,
  CheckCircle2,
  Code2,
  Fingerprint,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  SlidersHorizontal,
  UserRound,
  Users,
} from "lucide-react";
import {
  API_BASE,
  adminApi,
  authApi,
  healthApi,
  isRequestCancelled,
  readyApi,
} from "./services/api";
import {
  clearAccessToken,
  getAccessToken,
  setAccessToken,
  UNAUTHORIZED_EVENT,
} from "./services/tokenStorage";
import {
  BACKEND_STATES,
  READINESS_POLL_DELAYS_MS,
  READINESS_POLL_MAX_DURATION_MS,
  READINESS_REQUEST_TIMEOUT_MS,
  backendStateCopy,
  classifyBackendState,
  isReadinessCancelled,
  readinessAttemptCount,
  readinessRequestTimeout,
} from "./services/backendStatus";
import { isPublicRegistrationAvailable } from "./services/registrationPolicy";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import SecurityOverview from "./components/SecurityOverview";
import ViewerLanding from "./components/ViewerLanding";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  StatusBadge,
} from "./components/ui";
import "./App.css";

const AnalysisPanel = lazy(() => import("./components/AnalysisPanel"));
const HttpPayloadClassifier = lazy(() =>
  import("./components/HttpPayloadClassifier")
);
const BotDetection = lazy(() => import("./components/BotDetection"));
const MitigationAnalysis = lazy(() =>
  import("./components/MitigationAnalysis")
);
const MitigationAdminDashboard = lazy(() =>
  import("./components/MitigationAdminDashboard")
);
const modules = [
  { label: "Clustering", method: "POST", path: "/api/v1/security/clustering/analyze", icon: Network },
  { label: "Token Classification", method: "POST", path: "/api/v1/security/token-classifier/predict", icon: Code2 },
  { label: "Traffic Trend", method: "GET", path: "/api/v1/security/traffic-trends/analyze", icon: Activity },
  { label: "Behavioral Risk", method: "GET", path: "/api/v1/security/behavior/analyze", icon: Fingerprint },
  { label: "BOLA Detection", method: "GET", path: "/api/v1/security/bola/analyze", icon: LockKeyhole },
  { label: "Brute-Force", method: "GET", path: "/api/v1/security/bruteforce/analyze", icon: ShieldAlert },
  { label: "Rate Anomaly", method: "GET", path: "/api/v1/security/rate-anomaly/analyze", icon: Gauge },
  { label: "Bot Detection", method: "GET", path: "/api/v1/security/bot/analyze", icon: Bot },
  { label: "Bot Mitigation", method: "GET", path: "/api/v1/security/mitigation/analyze", icon: ShieldOff },
  { label: "HTTP Payload Classifier", method: "POST", path: "/api/v1/security/payload-classifier/predict", icon: Braces },
];

// Read-only analysis modules restricted to Admin and Analyst by the UI. The
// backend dependency remains the authoritative authorization boundary.
const ANALYST_MODULE_LABELS = new Set(["Bot Detection", "Bot Mitigation"]);

const ROLE_LABELS = {
  admin: "Administrator",
  analyst: "Analyst",
  viewer: "Viewer",
};
const READINESS_ATTEMPTS = readinessAttemptCount(READINESS_POLL_DELAYS_MS);
const RUNTIME_ENV = import.meta.env || {};
const PUBLIC_REGISTRATION_AVAILABLE = isPublicRegistrationAvailable(RUNTIME_ENV);
const REGISTRATION_DISABLED_MESSAGE =
  "Public registration is disabled. Ask an administrator for an account.";

function toProfile(user) {
  return {
    username: user?.username || "",
    email: user?.email || "",
    actor_id: user?.actor_id || "",
    role: user?.role || "viewer",
    is_active: user?.is_active !== false,
  };
}

function waitForReadinessDelay(delayMs, signal, deadline) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Readiness polling cancelled", "AbortError"));
      return;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      resolve();
      return;
    }

    const onAbort = () => {
      clearTimeout(timeoutId);
      reject(new DOMException("Readiness polling cancelled", "AbortError"));
    };
    const timeoutId = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, Math.min(delayMs, remaining));
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function App() {
  const [apiStatus, setApiStatus] = useState(BACKEND_STATES.CHECKING);
  const [health, setHealth] = useState(null);
  const [readiness, setReadiness] = useState(null);
  const [healthError, setHealthError] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeModule, setActiveModule] = useState("Overview");
  const [mobileMenu, setMobileMenu] = useState(false);
  const [lastChecked, setLastChecked] = useState(null);
  const [analysisResults, setAnalysisResults] = useState({});
  const [currentUser, setCurrentUser] = useState(null);
  const [authStatus, setAuthStatus] = useState(() =>
    getAccessToken() ? "checking" : "anonymous"
  );
  const [authError, setAuthError] = useState("");
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({
    username: "",
    email: "",
    password: "",
  });
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminError, setAdminError] = useState("");
  const [adminLoading, setAdminLoading] = useState(false);
  const readinessRunRef = useRef(0);
  const readinessAbortRef = useRef(null);
  const manualReadinessRunsRef = useRef(new Set());

  function cancelReadinessPolling() {
    readinessRunRef.current += 1;
    const controller = readinessAbortRef.current;
    if (controller) controller.abort();
    readinessAbortRef.current = null;
    // A cancelled check must not leave a manual spinner or disabled refresh
    // button behind. This runs on logout, unauthorized events, and unmount too.
    if (manualReadinessRunsRef.current.size > 0) {
      manualReadinessRunsRef.current.clear();
      setLoading(false);
    }
  }

  function pollingCancelled(controller, runId) {
    return isReadinessCancelled(
      controller.signal,
      runId,
      readinessRunRef.current
    );
  }

  async function signIn(identifier, password) {
    const data = await authApi.login({ username: identifier, password });
    setAccessToken(data.access_token);
    const profile = data.user || (await authApi.me());
    setCurrentUser(toProfile(profile));
    setAuthStatus("authenticated");
    setAuthError("");
    setAuthForm((previous) => ({ ...previous, password: "" }));
    checkHealth();
  }

  async function handleLogin(event) {
    event.preventDefault();
    setAuthSubmitting(true);
    setAuthError("");
    try {
      await signIn(authForm.username.trim(), authForm.password);
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Unable to sign in."
      );
    } finally {
      setAuthSubmitting(false);
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    // Defence in depth: production is owner-provisioned only, even if client
    // state is manipulated or a stale bundle still exposes register mode.
    if (!PUBLIC_REGISTRATION_AVAILABLE) {
      setAuthError(REGISTRATION_DISABLED_MESSAGE);
      return;
    }
    setAuthSubmitting(true);
    setAuthError("");
    try {
      const username = authForm.username.trim();
      await authApi.register({
        username,
        email: authForm.email.trim(),
        password: authForm.password,
      });
      await signIn(username, authForm.password);
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Unable to create account."
      );
    } finally {
      setAuthSubmitting(false);
    }
  }

  async function handleLogout() {
    cancelReadinessPolling();
    try {
      await authApi.logout();
    } catch {
      // Clear local state even when the server rejects an expired token.
    }
    clearAccessToken();
    setCurrentUser(null);
    setAuthStatus("anonymous");
    setAuthError("");
    setActiveModule("Overview");
    setAnalysisResults({});
    setHealth(null);
    setReadiness(null);
    setHealthError("");
    setApiStatus(BACKEND_STATES.CHECKING);
  }

  async function checkHealth({ manual = false } = {}) {
    cancelReadinessPolling();
    const runId = readinessRunRef.current;
    const controller = new AbortController();
    readinessAbortRef.current = controller;
    const deadline = Date.now() + READINESS_POLL_MAX_DURATION_MS;
    const requestOptions = () => ({
      signal: controller.signal,
      timeoutMs: readinessRequestTimeout(deadline),
    });

    if (manual) {
      manualReadinessRunsRef.current.add(runId);
      setLoading(true);
    }
    setHealthError("");

    try {
      for (let attempt = 0; attempt < READINESS_ATTEMPTS; attempt += 1) {
        if (pollingCancelled(controller, runId)) return;
        if (Date.now() >= deadline) {
          setApiStatus(BACKEND_STATES.OFFLINE);
          setLastChecked(new Date());
          return;
        }

        if (attempt > 0) {
          try {
            await waitForReadinessDelay(
              READINESS_POLL_DELAYS_MS[attempt - 1],
              controller.signal,
              deadline
            );
          } catch (error) {
            if (isRequestCancelled(error)) return;
          }
        }
        if (pollingCancelled(controller, runId)) return;
        if (Date.now() >= deadline) {
          setApiStatus(BACKEND_STATES.OFFLINE);
          setLastChecked(new Date());
          return;
        }

        const finalAttempt =
          attempt === READINESS_ATTEMPTS - 1 ||
          Date.now() + READINESS_REQUEST_TIMEOUT_MS >= deadline;
        let healthOk = false;
        let readyState = "network_error";

        try {
          const data = await healthApi(requestOptions());
          if (pollingCancelled(controller, runId)) return;
          healthOk = true;
          setHealth(data);
          setHealthError("");
        } catch (error) {
          if (pollingCancelled(controller, runId) || isRequestCancelled(error)) return;
          healthOk = false;
          setHealth(null);
          setHealthError(
            error instanceof Error ? error.message : "Unable to reach the API."
          );
        }

        if (healthOk) {
          try {
            const data = await readyApi(requestOptions());
            if (pollingCancelled(controller, runId)) return;
            readyState = "ready";
            setReadiness(data);
            setApiStatus(BACKEND_STATES.ONLINE);
            setLastChecked(new Date());
            return;
          } catch (error) {
            if (pollingCancelled(controller, runId) || isRequestCancelled(error)) return;
            readyState = error?.status === 503 ? "not_ready" : "network_error";
            setReadiness(error?.data || { status: "not_ready" });
            setHealthError(
              error instanceof Error ? error.message : "Readiness check failed."
            );
          }
        } else {
          setReadiness(null);
        }

        setApiStatus(classifyBackendState({ healthOk, readyState, finalAttempt }));
        setLastChecked(new Date());
      }
    } finally {
      if (readinessAbortRef.current === controller) {
        readinessAbortRef.current = null;
      }
      if (manual) {
        // Clear this run's own spinner even when a newer check superseded it.
        manualReadinessRunsRef.current.delete(runId);
        if (manualReadinessRunsRef.current.size === 0) setLoading(false);
      }
    }
  }

  useEffect(() => {
    checkHealth();
    return () => cancelReadinessPolling();
  }, []);

  // Restore a persistent session on first load using the stored bearer token.
  useEffect(() => {
    let active = true;
    if (!getAccessToken()) return undefined;

    authApi
      .me()
      .then((profile) => {
        if (active) {
          setCurrentUser(toProfile(profile));
          setAuthStatus("authenticated");
        }
      })
      .catch((error) => {
        if (active) {
          clearAccessToken();
          setCurrentUser(null);
          setAuthStatus("anonymous");
          setAuthError(
            error instanceof Error
              ? error.message
              : "Stored session could not be restored."
          );
        }
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    function handleUnauthorized(event) {
      cancelReadinessPolling();
      clearAccessToken();
      setCurrentUser(null);
      setAuthStatus("anonymous");
      setAuthError(
        event.detail || "Your session expired. Please sign in again."
      );
      setActiveModule("Overview");
      setHealth(null);
      setReadiness(null);
      setApiStatus(BACKEND_STATES.CHECKING);
    }

    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, []);

  const shouldLoadAdminUsers =
    activeModule === "User Administration" && currentUser?.role === "admin";

  useEffect(() => {
    if (!shouldLoadAdminUsers) return undefined;

    let active = true;
    async function loadUsers() {
      setAdminLoading(true);
      setAdminError("");
      try {
        const data = await adminApi.listUsers();
        if (active) setAdminUsers(Array.isArray(data) ? data : []);
      } catch (error) {
        if (active) {
          setAdminUsers([]);
          setAdminError(
            error instanceof Error ? error.message : "Unable to load users."
          );
        }
      } finally {
        if (active) setAdminLoading(false);
      }
    }

    loadUsers();

    return () => {
      active = false;
    };
  }, [shouldLoadAdminUsers]);

  const hasAnyResult = Object.keys(analysisResults).length > 0;
  const userInitials = (currentUser?.username || currentUser?.email || "AP")
    .slice(0, 2)
    .toUpperCase();
  const canUseBotAnalysis =
    currentUser?.role === "admin" || currentUser?.role === "analyst";
  // Any role without admin/analyst analysis rights is restricted to the
  // read-only status surface. The backend dependency remains authoritative.
  const isRestrictedViewer = !canUseBotAnalysis;
  // Gate C requires admin/analyst for every mitigation admin route. Viewer has
  // no permitted Gate C resource, so the navigation entry is hidden entirely.
  const canUseMitigationAdmin = canUseBotAnalysis;
  const visibleModules = isRestrictedViewer
    ? []
    : modules.filter(({ label }) => !ANALYST_MODULE_LABELS.has(label) || canUseBotAnalysis);
  const trafficResult = analysisResults["Traffic Trend"];
  const trafficPredictions = useMemo(() => {
    return Array.isArray(trafficResult?.predictions)
      ? trafficResult.predictions
      : [];
  }, [trafficResult]);

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

  const allRecentSignals = useMemo(() => {
    const signals = [];

    // 1. Traffic Trend anomalies
    trafficPredictions
      .filter((item) => item.is_anomaly)
      .forEach((item, index) => {
        signals.push({
          id: `traffic-${item.window_start || index}`,
          title: "Traffic anomaly flagged",
          time: item.window_start ? new Date(item.window_start).toLocaleString() : "Traffic window",
          metricLabel: "Reconstruction error",
          metricValue: Number(item.reconstruction_error ?? 0).toFixed(3),
        });
      });

    // 2. Brute-Force candidate evidences
    const bruteForce = analysisResults["Brute-Force"];
    if (Array.isArray(bruteForce?.evidences)) {
      bruteForce.evidences.forEach((ev, index) => {
        signals.push({
          id: `bruteforce-${index}`,
          title: `Brute-force signal (${ev.client_ip || "client"})`,
          time: "Authentication window",
          metricLabel: "Failed attempts",
          metricValue: String(ev.failed_attempt_count ?? ev.failure_count ?? 1),
        });
      });
    }

    // 3. BOLA candidate evidences
    const bola = analysisResults["BOLA Detection"];
    if (Array.isArray(bola?.evidences)) {
      bola.evidences.forEach((ev, index) => {
        signals.push({
          id: `bola-${index}`,
          title: `BOLA candidate (${ev.resource_type || "resource"}: ${ev.actor_id || "actor"})`,
          time: "Resource access event",
          metricLabel: "Distinct IDs",
          metricValue: String(ev.distinct_object_count ?? 1),
        });
      });
    }

    // 4. Rate Anomaly candidate evidences
    const rateAnomaly = analysisResults["Rate Anomaly"];
    if (Array.isArray(rateAnomaly?.evidences)) {
      rateAnomaly.evidences.forEach((ev, index) => {
        signals.push({
          id: `rate-${index}`,
          title: `Rate anomaly (${ev.client_ip || "client"})`,
          time: "Rate window",
          metricLabel: "Requests",
          metricValue: String(ev.anomalous_request_count ?? ev.request_count ?? 1),
        });
      });
    }

    // 5. Behavioral Risk elevated findings
    const behavior = analysisResults["Behavioral Risk"];
    if (Array.isArray(behavior?.results)) {
      behavior.results
        .filter((r) => r.risk_level && r.risk_level !== "LOW")
        .forEach((r, index) => {
          signals.push({
            id: `behavior-${index}`,
            title: `Behavioral risk: ${r.risk_level} (${r.client_ip || "client"})`,
            time: "Behavior assessment",
            metricLabel: "Risk score",
            metricValue: Number(r.risk_score ?? 0).toFixed(1),
          });
        });
    }

    // 6. Clustering Outliers
    const clustering = analysisResults["Clustering"];
    if (clustering?.kmeans && typeof clustering.kmeans.anomaly_count === "number" && clustering.kmeans.anomaly_count > 0) {
      signals.push({
        id: "clustering-kmeans",
        title: "Clustering: Outlier vectors identified",
        time: "Feature clustering",
        metricLabel: "K-Means outliers",
        metricValue: String(clustering.kmeans.anomaly_count),
      });
    }

    // 7. Token Classifier
    const tokenClf = analysisResults["Token Classification"];
    if (tokenClf?.predicted_label && tokenClf.predicted_label !== "Normal") {
      signals.push({
        id: "token-classification",
        title: `Token usage flagged: ${tokenClf.predicted_label}`,
        time: "Token inference",
        metricLabel: "Confidence",
        metricValue: `${(Number(tokenClf.confidence ?? 0) * 100).toFixed(1)}%`,
      });
    }

    return signals.slice(0, 5);
  }, [analysisResults, trafficPredictions]);

  const navItems = isRestrictedViewer
    ? [
        { label: "Overview", icon: LayoutDashboard },
        { label: "Service Status", target: "Service Status", icon: Activity },
      ]
    : [
        { label: "Overview", icon: LayoutDashboard },
        ...(canUseBotAnalysis
          ? [{ label: "Threat Detection", target: "Behavioral Risk", icon: ShieldAlert }]
          : []),
        { label: "API Modules", target: "API Modules", icon: Network },
        ...(canUseMitigationAdmin
          ? [{ label: "Mitigation Control", icon: SlidersHorizontal }]
          : []),
        ...(currentUser?.role === "admin"
          ? [{ label: "User Administration", icon: Users }]
          : []),
      ];
  const statusCopy = backendStateCopy(apiStatus);

  if (authStatus !== "authenticated") {
    return (
      <AuthScreen
        mode={authMode}
        form={authForm}
        error={authError}
        submitting={authSubmitting}
        checking={authStatus === "checking"}
        registrationAvailable={PUBLIC_REGISTRATION_AVAILABLE}
        registrationDisabledMessage={REGISTRATION_DISABLED_MESSAGE}
        onModeChange={setAuthMode}
        onFieldChange={(field, value) =>
          setAuthForm((previous) => ({ ...previous, [field]: value }))
        }
        onSubmit={authMode === "login" ? handleLogin : handleRegister}
      />
    );
  }

  return (
    <div className="app-shell">
      <Sidebar
        navItems={navItems}
        visibleModules={visibleModules}
        activeModule={activeModule}
        username={currentUser?.username || "Authenticated user"}
        roleLabel={ROLE_LABELS[currentUser?.role] || currentUser?.role || "Viewer"}
        userInitials={userInitials}
        mobileMenu={mobileMenu}
        viewerMode={isRestrictedViewer}
        onNavigate={(target) => {
          setActiveModule(target);
          setMobileMenu(false);
        }}
        onCloseMobileMenu={() => setMobileMenu(false)}
        onLogout={handleLogout}
      />

      <main className="main-panel">
        <Topbar
          activeModule={activeModule}
          apiStatus={apiStatus}
          userInitials={userInitials}
          onOpenMobileMenu={() => setMobileMenu(true)}
          onLogout={handleLogout}
        />

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> API SECURITY INTELLIGENCE</div>
              <h1>
                {activeModule === "Overview"
                  ? isRestrictedViewer
                    ? "Viewer Overview"
                    : "Security Overview"
                  : activeModule}
              </h1>
              <p className="page-subtitle">
                {isRestrictedViewer
                  ? "Review your read-only account and backend service status."
                  : "Monitor API behavior, inspect detection modules, and assess service health."}
              </p>
            </div>
            <button
              className="refresh-button"
              onClick={() => checkHealth({ manual: true })}
              disabled={loading}
            >
              <RefreshCw size={16} className={loading ? "spin" : ""} />
              {loading ? "Checking..." : "Refresh status"}
            </button>
          </section>

          <section className={`api-banner ${apiStatus}`}>
            <div className="banner-icon">
              {apiStatus === "online" ? (
                <CheckCircle2 size={22} />
              ) : apiStatus === "offline" ? (
                <AlertTriangle size={22} />
              ) : (
                <Activity size={22} />
              )}
            </div>
            <div className="banner-copy">
              <strong>
                {apiStatus === "online"
                  ? `${health?.service || "APISentry API"} is reachable and ready`
                  : statusCopy.banner}
              </strong>
              <p>
                {apiStatus === "online"
                  ? trafficResult
                    ? "Backend is reachable. Latest Traffic Trend analysis is loaded in this session."
                    : hasAnyResult
                      ? `Backend is reachable. ${Object.keys(analysisResults).length} analysis module(s) run in this session.`
                      : "Backend is reachable. Run a detection module to load analysis data."
                  : healthError && apiStatus !== "checking"
                    ? healthError
                    : statusCopy.message}
              </p>
            </div>
            <span className="banner-tag">{statusCopy.tag}</span>
          </section>

          {isRestrictedViewer &&
          (activeModule === "Overview" || activeModule === "Service Status") ? (
            <ViewerLanding
              profile={currentUser}
              health={health}
              readiness={readiness}
              apiStatus={apiStatus}
              lastChecked={lastChecked}
              loading={loading}
              onRefreshHealth={() => checkHealth({ manual: true })}
            />
          ) : activeModule === "Overview" ? (
            <SecurityOverview
              apiStatus={apiStatus}
              health={health}
              lastChecked={lastChecked}
              analysisResults={analysisResults}
              trafficResult={trafficResult}
              trafficPredictions={trafficPredictions}
              trafficChartData={trafficChartData}
              allRecentSignals={allRecentSignals}
              visibleModules={visibleModules}
              hasAnyResult={hasAnyResult}
              apiBase={API_BASE}
              loading={loading}
              onRefreshHealth={() => checkHealth({ manual: true })}
              onSelectModule={setActiveModule}
            />
          ) : activeModule === "User Administration" ? (
            <AdminPanel
              users={adminUsers}
              loading={shouldLoadAdminUsers && adminLoading}
              error={adminError}
            />
          ) : activeModule === "Mitigation Control" ? (
            <Suspense fallback={<div className="panel">Loading mitigation administration…</div>}>
              <MitigationAdminDashboard role={currentUser?.role} />
            </Suspense>
          ) : activeModule === "API Modules" ? (
            <section className="panel detail-panel">
              <div className="panel-header">
                <div><h3>Registered analysis modules</h3><p>Routes currently identified in the FastAPI application.</p></div>
                <Code2 size={20} />
              </div>
              {visibleModules.map(({ label, method, path, icon: Icon }) => (
                <div className="detail-route" key={path}>
                  <Icon size={18} />
                  <div><strong>{label}</strong><code>{path}</code></div>
                  <span className="method-get">{method}</span>
                </div>
              ))}
              <p className="detail-note">The exact HTTP method and required query parameters should be verified in each route definition before running an analysis.</p>
            </section>
          ) : isRestrictedViewer ? (
            <section className="panel detail-panel">
              <div className="panel-header">
                <div>
                  <h3>Module unavailable</h3>
                  <p>Your role does not have access to this analysis module.</p>
                </div>
                <ShieldOff size={20} />
              </div>
              <p className="detail-note">Admin and Analyst roles are required for analysis modules. Backend authorization remains authoritative.</p>
            </section>
          ) : activeModule === "Bot Detection" && canUseBotAnalysis ? (
            <Suspense fallback={<div className="panel">Loading bot detection…</div>}>
              <BotDetection />
            </Suspense>
          ) : activeModule === "Bot Mitigation" && canUseBotAnalysis ? (
            <Suspense fallback={<div className="panel">Loading mitigation analysis…</div>}>
              <MitigationAnalysis />
            </Suspense>
          ) : activeModule === "HTTP Payload Classifier" && canUseBotAnalysis ? (
            <Suspense fallback={<div className="panel">Loading payload classifier…</div>}>
              <HttpPayloadClassifier />
            </Suspense>
          ) : (
            <Suspense fallback={<div className="panel">Loading analysis module…</div>}>
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
            </Suspense>
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

function AuthScreen({
  mode,
  form,
  error,
  submitting,
  checking,
  registrationAvailable,
  registrationDisabledMessage,
  onModeChange,
  onFieldChange,
  onSubmit,
}) {
  const registrationEnabled = registrationAvailable === true;
  // Production never renders the registration entry point, even if stale
  // component state requests register mode.
  const isLogin = !registrationEnabled || mode === "login";

  return (
    <main className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand">
          <div className="brand-mark"><ShieldCheck size={24} /></div>
          <div>
            <div className="brand-name">APISENTRY<span>AI</span></div>
            <div className="brand-caption">API SECURITY PLATFORM</div>
          </div>
        </div>

        <h1>{isLogin ? "Sign in to your workspace" : "Create your account"}</h1>
        <p className="auth-subtitle">
          {isLogin
            ? "Authenticate with your persistent APISentry account to access protected analysis modules."
            : "Create a viewer account to access the security platform. Elevated roles are assigned by an administrator."}
        </p>
        {!registrationEnabled && (
          <p className="auth-policy-note">{registrationDisabledMessage}</p>
        )}

        {checking && (
          <div className="auth-notice">Restoring your secure session…</div>
        )}
        {error && (
          <div className="auth-error">
            <AlertTriangle size={15} /> <span>{error}</span>
          </div>
        )}

        <form className="auth-form" onSubmit={onSubmit}>
          <label className="auth-field">
            <span><UserRound size={14} /> Username or email</span>
            <input
              type="text"
              value={form.username}
              onChange={(event) => onFieldChange("username", event.target.value)}
              autoComplete="username"
              placeholder="analyst_jane"
              required
            />
          </label>

          {!isLogin && (
            <label className="auth-field">
              <span><UserRound size={14} /> Email address</span>
              <input
                type="email"
                value={form.email}
                onChange={(event) => onFieldChange("email", event.target.value)}
                autoComplete="email"
                placeholder="analyst@apisentry.ai"
                required
              />
            </label>
          )}

          <label className="auth-field">
            <span><KeyRound size={14} /> Password</span>
            <input
              type="password"
              value={form.password}
              onChange={(event) => onFieldChange("password", event.target.value)}
              autoComplete={isLogin ? "current-password" : "new-password"}
              placeholder="At least 8 characters"
              minLength={8}
              required
            />
          </label>

          <button className="auth-submit" type="submit" disabled={submitting || checking}>
            {submitting ? "Please wait…" : isLogin ? "Sign in" : "Create account"}
          </button>
        </form>

        {registrationEnabled && (
          <button
            className="auth-switch"
            type="button"
            onClick={() => onModeChange(isLogin ? "register" : "login")}
          >
            {isLogin ? "Need an account? Register" : "Already registered? Sign in"}
          </button>
        )}
      </div>
    </main>
  );
}

function AdminPanel({ users, loading, error }) {
  return (
    <section className="panel detail-panel admin-panel">
      <div className="panel-header">
        <div>
          <h3>Registered users</h3>
          <p>Admin-only view of persistent accounts from the backend.</p>
        </div>
        <Users size={20} />
      </div>

      {error && <ErrorState title="Unable to load users" message={error} />}

      {loading ? (
        <LoadingState label="Loading users…" />
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.id}</td>
                  <td>{user.username}</td>
                  <td>{user.email}</td>
                  <td><StatusBadge tone="info">{user.role}</StatusBadge></td>
                  <td>
                    <StatusBadge tone={user.is_active ? "success" : "danger"}>
                      {user.is_active ? "Active" : "Disabled"}
                    </StatusBadge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && (
            <EmptyState
              title="No users returned"
              description="The API did not return any registered accounts."
            />
          )}
        </div>
      )}
    </section>
  );
}

export default App;
