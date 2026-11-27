import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { isPublicRegistrationAvailable } from "../src/services/registrationPolicy.js";

const appSource = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");
const registrationPolicySource = readFileSync(
  new URL("../src/services/registrationPolicy.js", import.meta.url),
  "utf8"
);
const apiSource = readFileSync(
  new URL("../src/services/api.js", import.meta.url),
  "utf8"
);
const viewerSource = readFileSync(
  new URL("../src/components/ViewerLanding.jsx", import.meta.url),
  "utf8"
);
const sidebarSource = readFileSync(
  new URL("../src/components/Sidebar.jsx", import.meta.url),
  "utf8"
);

test("production registration UI is gated and client-side state cannot bypass it", () => {
  assert.match(appSource, /isPublicRegistrationAvailable\(RUNTIME_ENV\)/);
  assert.match(appSource, /registrationAvailable=\{PUBLIC_REGISTRATION_AVAILABLE\}/);
  assert.match(appSource, /const isLogin = !registrationEnabled \|\| mode === "login"/);
  assert.match(appSource, /\{registrationEnabled && \(\s*<button\s+className="auth-switch"/);
  assert.match(appSource, /if \(!PUBLIC_REGISTRATION_AVAILABLE\) \{[\s\S]*?REGISTRATION_DISABLED_MESSAGE/);
});

test("registration availability is build-time only and hidden in production", () => {
  assert.equal(isPublicRegistrationAvailable({ PROD: true }), false);
  assert.equal(isPublicRegistrationAvailable({ PROD: false }), true);
  assert.match(registrationPolicySource, /return env\?\.PROD !== true/);
  assert.doesNotMatch(
    registrationPolicySource,
    /localStorage|sessionStorage|window\.|document\.|fetch\(|XMLHttpRequest|axios/
  );
  assert.match(appSource, /const RUNTIME_ENV = import\.meta\.env \|\| \{\}/);
  assert.match(appSource, /registrationAvailable=\{PUBLIC_REGISTRATION_AVAILABLE\}/);
  assert.match(appSource, /const registrationEnabled = registrationAvailable === true/);
  assert.match(appSource, /const isLogin = !registrationEnabled \|\| mode === "login"/);
  assert.match(appSource, /\{registrationEnabled && \(/);
});

test("restricted roles receive a read-only status surface with no analysis routes", () => {
  assert.match(appSource, /const isRestrictedViewer = !canUseBotAnalysis/);
  assert.match(appSource, /const visibleModules = isRestrictedViewer\s*\? \[\]/);
  assert.match(appSource, /<ViewerLanding[\s\S]*?onRefreshHealth/);
  assert.match(appSource, /viewerMode=\{isRestrictedViewer\}/);
  assert.match(sidebarSource, /nav\("Service Status", "Service Status"\)/);
  assert.match(sidebarSource, /viewerMode \? "Viewer Overview" : "Security Dashboard"/);
  assert.match(viewerSource, /ShieldOff size=\{20\}/);
  assert.doesNotMatch(appSource, /VIEWER_DENIED_MODULE_LABELS/);
});

test("readiness polling is bounded and cancelled on unmount and session termination", () => {
  assert.match(appSource, /readyApi\(requestOptions\(\)\)/);
  assert.match(appSource, /READINESS_POLL_MAX_DURATION_MS/);
  assert.match(appSource, /waitForReadinessDelay\(/);
  assert.match(appSource, /return \(\) => cancelReadinessPolling\(\);/);
  assert.match(appSource, /async function handleLogout\(\) \{\s*cancelReadinessPolling\(\);/);
  assert.match(appSource, /function handleUnauthorized\(event\) \{\s*cancelReadinessPolling\(\);/);
  assert.match(appSource, /manualReadinessRunsRef\.current\.add\(runId\)/);
  assert.match(appSource, /manualReadinessRunsRef\.current\.delete\(runId\)/);
  assert.match(
    appSource,
    /if \(manualReadinessRunsRef\.current\.size === 0\) setLoading\(false\)/
  );
  assert.match(appSource, /if \(manualReadinessRunsRef\.current\.size > 0\) \{\s*manualReadinessRunsRef\.current\.clear\(\);\s*setLoading\(false\);/);
  assert.equal((appSource.match(/cancelReadinessPolling\(\);/g) || []).length >= 4, true);
});

test("API retry logic is restricted to idempotent GET requests", () => {
  assert.match(apiSource, /normalizedMethod\(method\) === "GET"/);
  assert.match(apiSource, /MAX_IDEMPOTENT_GET_RETRIES = 1/);
  assert.match(apiSource, /error\?\.status && RETRYABLE_STATUSES\.has\(error\.status\)/);
  assert.match(apiSource, /error\?\.reason === "network"/);
  assert.match(apiSource, /if \(error\?\.timedOut \|\| error\?\.aborted\) return false/);
  assert.doesNotMatch(apiSource, /method !== "GET" && shouldRetry/);
});
