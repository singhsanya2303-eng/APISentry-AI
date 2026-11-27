// Production is owner-provisioned only. This helper is intentionally driven by
// the build environment so the same rule can be tested without a browser.
export function isPublicRegistrationAvailable(env) {
  return env?.PROD !== true;
}
