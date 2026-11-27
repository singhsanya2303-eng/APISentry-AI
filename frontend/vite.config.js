import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

const SECRET_VITE_KEY_PATTERN = /(SECRET|PASSWORD|API_KEY|DATABASE_URL|POSTGRES|JWT|CREDENTIAL|TOKEN)/i
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])

function requireProductionApiBase(env) {
  const configured = env.VITE_API_BASE_URL
  if (!configured) {
    throw new Error('Refusing frontend build: VITE_API_BASE_URL is required for production builds.')
  }

  let parsed
  try {
    parsed = new URL(configured)
  } catch {
    throw new Error('Refusing frontend build: VITE_API_BASE_URL must be an absolute HTTPS URL.')
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (parsed.protocol !== 'https:' || !parsed.host || LOOPBACK_HOSTS.has(hostname)) {
    throw new Error('Refusing frontend build: VITE_API_BASE_URL must be a non-loopback HTTPS origin in production.')
  }

  // The value is injected into the public bundle and rendered in the UI, so it
  // must be a bare origin. Credentials, paths, queries, and fragments could
  // leak secrets or corrupt URL construction in the API client.
  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    configured !== parsed.origin
  ) {
    throw new Error('Refusing frontend build: VITE_API_BASE_URL must be an origin-only HTTPS URL without credentials, path, query, or fragment.')
  }
  return configured
}

export default defineConfig(({ mode }) => {
  // A build-specific env directory keeps existing local env files out of the
  // bundle. CI and release builds set this to a temporary directory containing
  // only a reviewed staging env template.
  const envDir = process.env.APISENTRY_VITE_ENV_DIR || process.cwd()
  const env = loadEnv(mode, envDir, 'VITE_')
  const unsafeKeys = Object.keys(env).filter((key) => SECRET_VITE_KEY_PATTERN.test(key))

  if (unsafeKeys.length > 0) {
    throw new Error(
      `Refusing frontend build: backend-secret-like VITE_* variables are configured (${unsafeKeys.join(', ')}). Only VITE_API_BASE_URL is supported.`
    )
  }

  const productionApiBase = mode === 'production' ? requireProductionApiBase(env) : null

  return {
    plugins: [react()],
    envDir,
    define: productionApiBase
      ? { __APISENTRY_API_BASE__: JSON.stringify(productionApiBase) }
      : undefined,
  }
})
