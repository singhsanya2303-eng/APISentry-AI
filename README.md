# API-SENTRY-AI

An API security analysis system built with FastAPI to identify suspicious API usage, detect anomalies, analyze user behavior, and support security monitoring.

## Features

- **BOLA Detection:** Analyze potential Broken Object Level Authorization risks.
- **Brute-Force Detection:** Identify suspicious repeated authentication attempts.
- **Rate Anomaly Detection:** Detect unusual API request patterns.
- **Behavior Analysis:** Analyze API usage and user behavior.
- **Token Usage Classification:** Classify token usage patterns.
- **Traffic Trend Analysis:** Analyze API traffic trends.
- **Clustering Analysis:** Compare traffic patterns using clustering techniques.
- **API-Key Authentication:** Protect security-analysis endpoints using the `X-API-Key` header.
- **Health Checks:** Expose health endpoints for basic service monitoring.
- **Automated Tests:** Test API routes, detection services, authentication, and related functionality.

## Tech Stack

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pytest
- Git and GitHub

## Project Structure

```text
APISentry-AI/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── detection/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── utils/
│   │   └── main.py
│   ├── tests/
│   ├── .env.example
│   └── requirements.txt
├── scripts/
│   └── generate_traffic_test_data.py
├── .gitignore
└── README.md
```

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/singhsanya2303-eng/APISentry-AI.git
cd APISentry-AI
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

Create a local environment file from the example:

```powershell
Copy-Item backend/.env.example backend/.env
```

Configure the required environment variables in `backend/.env`, including a strong, private API key and the database settings required by your environment.

**Never commit `backend/.env` or expose your API key.**

### 5. Start the API

From the repository root:

```powershell
$env:PYTHONPATH = "$PWD\backend"
python -m uvicorn app.main:app --app-dir backend --reload
```

The API should be available at:

- API documentation: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

## API Authentication

Security-analysis endpoints require an API key in the `X-API-Key` request header.

Example:

```http
X-API-Key: YOUR_API_KEY
```

Example PowerShell request:

```powershell
$headers = @{
    "X-API-Key" = "YOUR_API_KEY"
}

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/v1/security/clustering/analyze" `
    -Method Post `
    -Headers $headers `
    -ContentType "application/json" `
    -Body "{}"
```

Replace the example key with your locally configured key. Supply the request body required by the endpoint; an empty JSON object may return a validation error.

## Run Tests

From the repository root:

```powershell
$env:PYTHONPATH = "$PWD\backend"
python -m pytest backend/tests -q
```

The current local test suite has passed **546 tests**. Results may vary with dependency versions and environment configuration.

## Security Notes

- Keep API keys and database credentials out of source control.
- Use environment variables for sensitive configuration.
- Use HTTPS when deploying the API publicly.
- Configure database access and deployment secrets securely.

## Future Improvements

- Automated CI with GitHub Actions.
- Expanded authentication and authorization tests.
- Improved API documentation and deployment configuration.
- Additional monitoring and security-analysis capabilities.
