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
`http://localhost:5173`. The backend CORS template lists `5174` origins from
earlier isolated demos. If the frontend port differs from your local
`CORS_ORIGINS`, add the browser origin you actually use to the local backend
configuration. Do not expose a local demo server publicly.

## API base URL

`src/services/api.js` uses `VITE_API_BASE_URL` when present and otherwise falls
back to `http://127.0.0.1:8000`. Set `VITE_API_BASE_URL` in a local Vite
environment file or shell environment when the backend is not at the default
address. Never commit secrets or a shared browser API key.

## Authentication

The login flow obtains a JWT and stores it through `src/services/tokenStorage.js`.
Protected requests attach the bearer token in `Authorization` headers, and an
HTTP 401 clears an invalid local session. Browser-delivered API keys are not
secrets, so server-to-server API keys remain configured only in the backend.

## Checks

From the repository root:

```powershell
npm run lint
npm run build
node --test frontend/tests/*.test.js
```

`npm run build` writes generated output to `frontend/dist`; that directory is
not part of the source contribution. The build command is documented here but
was not executed during the documentation cleanup task.
