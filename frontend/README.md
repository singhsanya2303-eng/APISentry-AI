# APISentry Frontend

## Purpose

This React dashboard is the browser interface for APISentry AI. It displays
detection and security-analysis results from the FastAPI backend and provides
panels for traffic analysis, bot detection, payload classification, mitigation
policy administration, audit history, and isolated local demos.

Local tests and builds do not establish production readiness. Production
request-time enforcement remains disabled/advisory-only, and Gate E/WP9 are
isolated, default-disabled demonstrations.

## Architecture

- **React 19** and **Vite 8** (see `package.json`).
- `src/main.jsx` is the React entry point; `src/App.jsx` defines the dashboard.
- `src/components/` contains feature panels and shared UI components.
- `src/services/api.js` is the centralized REST client.
- `src/services/tokenStorage.js` stores and clears the signed-in user's JWT.
- `src/theme/` provides the theme context and provider; `ThemeToggle.jsx`
  exposes the toggle.
- `src/utils/` contains frontend helper modules.
- `tests/` contains Node test-runner tests for API clients, helpers, and theme
  behavior.

## Development setup

From the repository root:

```powershell
cd frontend
npm install
npm run dev
```

`frontend/vite.config.js` does not override the port, so Vite uses its default
`http://localhost:5173`. The backend development CORS template and non-production
auto-added origins include both `5173` and `5174` loopback origins. If you use a
different local port, add the browser origin you actually use to the local
backend configuration. Do not expose a local demo server publicly.

## API base URL

`src/services/api.js` uses `VITE_API_BASE_URL` when present. Local Node tests and
development imports keep a loopback fallback, but production builds must supply
an explicit non-loopback HTTPS origin; `vite.config.js` fails the build when it
is missing or unsafe. Use `frontend/.env.staging.example` for staging/production
builds. Never place backend secrets in `VITE_*` variables: Vite injects those
names into browser bundles. `vite.config.js` rejects secret-like `VITE_*` names
and supports `APISENTRY_VITE_ENV_DIR` so a build can ignore local `.env.local`
files.

## Authentication

The login flow obtains a JWT and stores it through `src/services/tokenStorage.js`.
Protected requests attach the bearer token in `Authorization` headers, and an
HTTP 401 clears an invalid local session. The browser has no API-key dependency:
no source module reads or sends `X-API-Key`, and server-to-server API keys stay
configured only in the backend.

## Checks

From the repository root:

```powershell
npm run lint
node --test frontend/tests/*.test.js
```

Build into a unique temporary directory outside the repository, using an
isolated env directory and no `--emptyOutDir`:

```powershell
$buildRoot = Join-Path $env:TEMP ('apisentry-frontend-build-' + [guid]::NewGuid().ToString('N'))
$envDir = Join-Path $buildRoot 'env'
$outDir = Join-Path $buildRoot 'site'
New-Item -ItemType Directory -Path $envDir -Force | Out-Null
Copy-Item frontend/.env.staging.example (Join-Path $envDir '.env')
$env:APISENTRY_VITE_ENV_DIR = $envDir
# Edit only the temporary copy above so VITE_API_BASE_URL is the HTTPS backend URL.
npm --prefix frontend run build -- --outDir $outDir
```

Do not publish the existing local `frontend/dist`. It is an untracked legacy
artifact from an older revision and may contain credential-shaped material from
that build. It must not be cleaned, overwritten, or included in a release.
Always publish only a freshly generated build from the temporary output path.
