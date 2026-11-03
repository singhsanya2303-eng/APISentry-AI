# APISentry AI

**Intelligent API Security Monitoring and Threat Detection System**

APISentry AI is a web-based API security monitoring and threat detection project built to analyze API traffic and identify potentially suspicious request patterns. It combines multiple detection modules with a FastAPI backend and a React dashboard to provide security insights and risk analysis.

> **Project status:** Academic / development project. Detection results are based on the traffic data supplied to the system. They should not be treated as proof of real-world attacks without further validation.

## Key Features

- API traffic monitoring and analysis
- Behavioral risk analysis
- Broken Object Level Authorization (BOLA) detection
- Brute-force activity detection
- Rate anomaly detection
- Traffic clustering and comparison
- Token usage classification
- Traffic trend analysis
- Risk scoring and security insights
- JWT-based authentication
- API key protection for sensitive security endpoints
- Interactive dashboard for viewing analysis results

## Detection Modules

| Module | Purpose |
|---|---|
| Behavioral Risk | Identifies unusual API request behavior |
| BOLA Detection | Analyzes potential object-level authorization issues |
| Brute-Force Detection | Identifies repeated suspicious request attempts |
| Rate Anomaly | Detects unusual request rates |
| Clustering | Groups traffic patterns for comparison |
| Token Classification | Classifies token usage patterns |
| Traffic Trends | Analyzes traffic patterns and trends over time |

Detection results depend on the available traffic data, configured thresholds, and analysis logic.

## Technology Stack

### Backend
- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic
- JWT authentication
- Scikit-learn
- PyTorch
- NumPy

### Frontend
- React 19
- Vite
- JavaScript
- Recharts
- Lucide React

### Testing
- Pytest
- FastAPI TestClient
- SQLite for isolated test database operations

## Project Structure

```text
API-SENTRY-AI/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       └── routes/
│   │   ├── core/
│   │   ├── db/
│   │   ├── detection/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── utils/
│   ├── models/
│   ├── tests/
│   ├── .env.example
│   ├── requirements.txt
│   └── train_token_classifier.py
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── services/
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
│
├── scripts/
│   ├── generate_traffic_test_data.py
│   └── simulate_bruteforce_demo.py
│
└── README.md
```

## Prerequisites

Install the following before running the project:

- Python 3.10 or later
- Node.js and npm
- PostgreSQL
- Git

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/singhsanya2303-eng/APISentry-AI.git
cd APISentry-AI
```

### 2. Backend setup

Create and activate a Python virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install backend dependencies:

```powershell
pip install -r backend/requirements.txt
```

### 3. Configure environment variables

Create your local environment file:

```powershell
Copy-Item backend/.env.example backend/.env
```

Update `backend/.env` with your PostgreSQL configuration and a secure JWT secret.

Example database configuration:

```env
PROJECT_NAME="APISentry AI"
VERSION="0.1.0"
ENVIRONMENT="development"
DEBUG=True

POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_local_database_password
POSTGRES_DB=apisentry_db

APISENTRY_ENABLE_DEMO_AUTH=false
```

Create the PostgreSQL database named `apisentry_db` before starting the backend.

**Security:** Never commit `.env` files or real credentials to GitHub. Use unique, strong secrets outside development environments.

### 4. Start the backend

From the project root:

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m uvicorn app.main:app --app-dir .\backend --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

FastAPI interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

### 5. Start the frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

## Authentication and Security

APISentry AI includes JWT-based authentication and API key protection for sensitive security endpoints.

Authentication endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/auth/login` | Obtain an authentication token |
| GET | `/api/v1/auth/me` | Retrieve the authenticated user's profile |
| GET | `/api/v1/auth/users/{user_id}` | Retrieve a protected user resource |

Protected endpoints require the appropriate authentication credentials.

**Current implementation limitation:** The user registry is in-memory. User records are not persisted across backend restarts. Persistent user management is a future improvement.

The demo authentication feature is disabled by default and should only be enabled intentionally for development or demonstration.

## Running Tests

Run the backend test suite from the project root:

```powershell
python -m pytest backend/tests -q
```

The project has previously achieved:

```text
590 passed
```

This is a recorded test result, not a guarantee that every future code revision will pass.

## Frontend Commands

Run these commands from the `frontend` directory:

| Command | Purpose |
|---|---|
| `npm run dev` | Start development server |
| `npm run build` | Build production frontend |
| `npm run lint` | Run frontend lint checks |
| `npm run preview` | Preview production build |

## Limitations and Future Improvements

- Persistent user registration and database-backed authentication
- Improved production-grade identity and access management
- Further validation against real-world API attack datasets
- More comprehensive security event logging and alerting
- Production deployment and monitoring
- Additional integration and end-to-end testing

## Disclaimer

APISentry AI is an academic development project intended for learning, experimentation, and API security analysis. It is not a replacement for a production Web Application Firewall (WAF), API Gateway, or dedicated security monitoring platform.

## Author

**Prityush Pal**

GitHub: [@palprityush-ops](https://github.com/palprityush-ops)
