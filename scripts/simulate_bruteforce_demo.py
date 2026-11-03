#!/usr/bin/env python3
"""
Brute-Force Attack Simulation Script — APISentry AI Live Demonstration.

Sends 5 controlled failed-login requests from the local client to the
development-only demo endpoint: POST /demo/auth/login.

Verifies:
  1. Each request receives HTTP 401 Unauthorized.
  2. Each request passes through RequestLoggingMiddleware (attaching X-Request-ID).
  3. Traffic is persisted to the PostgreSQL database.
  4. The existing Brute-Force analysis endpoint recognizes the attempts and
     emits a 'suspicious_bruteforce_candidate' verdict with evidence.

Usage:
  python scripts/simulate_bruteforce_demo.py
"""

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def send_request(url: str, payload: dict) -> tuple[int, dict, dict]:
    """Send an HTTP POST request and return (status_code, response_body, headers)."""
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "APISentry-BruteForce-Simulator/1.0",
        },
        method="POST",
    )
    start = time.perf_counter()
    try:
        with urlopen(req) as resp:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            body = json.loads(resp.read().decode("utf-8"))
            headers = dict(resp.headers)
            headers["_elapsed_ms"] = elapsed_ms
            return resp.status, body, headers
    except HTTPError as err:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        try:
            body = json.loads(err.read().decode("utf-8"))
        except Exception:
            body = {"raw": str(err)}
        headers = dict(err.headers)
        headers["_elapsed_ms"] = elapsed_ms
        return err.code, body, headers


def get_analysis(url: str, api_key: str) -> tuple[int, dict]:
    """Invoke the Brute-Force analysis API with the required X-API-Key."""
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "APISentry-BruteForce-Simulator/1.0",
        },
        method="GET",
    )
    with urlopen(req) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return resp.status, body


def main():
    parser = argparse.ArgumentParser(description="Simulate Brute-Force Failed Logins")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL of the running FastAPI server",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=5,
        help="Number of failed login attempts to send (default: 5)",
    )
    parser.add_argument(
        "--api-key",
        default="rz0oQlqj0VLjQ9CdLjsBhXexXKuPDHJDM3qsEsdeYeY",
        help="API Key for the security analysis endpoints",
    )
    args = parser.parse_args()

    demo_login_url = f"{args.base_url}/demo/auth/login"
    analysis_url = f"{args.base_url}/api/v1/security/bruteforce/analyze"

    print("=" * 70)
    print(" APISentry AI — Brute-Force Live Demonstration Simulation")
    print("=" * 70)
    print(f"Target Demo Auth URL : {demo_login_url}")
    print(f"Analysis Endpoint    : {analysis_url}")
    print(f"Planned Attempts     : {args.attempts} failed login requests")
    print("-" * 70)

    # 1. Check server health
    health_url = f"{args.base_url}/health"
    try:
        with urlopen(health_url) as health_resp:
            if health_resp.status != 200:
                print(f"[ERROR] Health check returned unexpected status {health_resp.status}")
                sys.exit(1)
            print("[OK] Backend is reachable and healthy.")
    except URLError as e:
        print(f"[ERROR] Cannot reach backend at {health_url}: {e.reason}")
        print("Please ensure the FastAPI backend is running before launching this script.")
        sys.exit(1)

    # 2. Transmit controlled failed login attempts
    print(f"\n[PHASE 1] Transmitting {args.attempts} controlled failed login requests...")
    successful_401s = 0
    request_ids = []

    for i in range(1, args.attempts + 1):
        payload = {
            "username": "demo_user",
            "password": f"deliberately_invalid_password_{i}",
        }
        status_code, body, headers = send_request(demo_login_url, payload)
        req_id = headers.get("x-request-id") or headers.get("X-Request-ID") or "N/A"
        process_time = headers.get("x-process-time") or f"{headers.get('_elapsed_ms')}ms"
        request_ids.append(req_id)

        if status_code == 401:
            successful_401s += 1
            print(
                f"  [Attempt {i}/{args.attempts}] Status: 401 Unauthorized | "
                f"Request-ID: {req_id} | Latency: {process_time} | "
                f"Detail: {body.get('detail', '')}"
            )
        else:
            print(
                f"  [Attempt {i}/{args.attempts}] UNEXPECTED Status: {status_code} | "
                f"Response: {body}"
            )

        time.sleep(0.1)

    print("-" * 70)
    print(f"Phase 1 Complete: {successful_401s}/{args.attempts} requests returned HTTP 401.")

    if successful_401s < args.attempts:
        print("[ERROR] Not all requests returned 401. Demonstration aborted.")
        sys.exit(1)

    # 3. Give middleware persistence task a moment to ensure DB transaction is committed
    print("\n[PHASE 2] Waiting 1 second for persistence and database commit...")
    time.sleep(1.0)

    # 4. Invoke the existing Brute-Force detection analysis endpoint
    print("[PHASE 3] Invoking Brute-Force Analysis Endpoint...")
    try:
        status_code, result = get_analysis(analysis_url, args.api_key)
    except HTTPError as e:
        print(f"[ERROR] Analysis API call failed with HTTP {e.code}: {e.read().decode('utf-8')}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to query analysis endpoint: {e}")
        sys.exit(1)

    print(f"Analysis API Response (HTTP {status_code}):")
    print(f"  - Verdict              : {result.get('verdict')}")
    print(f"  - Analyzed Event Count : {result.get('analyzed_event_count')}")
    print(f"  - Failed Attempt Count : {result.get('failed_attempt_count')}")
    print(f"  - Distinct Clients     : {result.get('distinct_client_count')}")
    print(f"  - Summary              : {result.get('summary')}")

    evidences = result.get("evidences", [])
    print(f"  - Evidence Records     : {len(evidences)}")
    for idx, ev in enumerate(evidences, 1):
        print(f"    Evidence #{idx}:")
        print(f"      • Client IP       : {ev.get('client_ip')}")
        print(f"      • Auth Endpoint   : {ev.get('auth_endpoint')}")
        print(f"      • Failures Count  : {ev.get('failed_attempt_count')}")
        print(f"      • Confidence Score: {ev.get('confidence_score')}")
        print(f"      • Explanation     : {ev.get('explanation')}")

    print("=" * 70)
    if result.get("verdict") == "suspicious_bruteforce_candidate":
        print("[SUCCESS] Brute-Force candidate successfully detected with complete evidence!")
        sys.exit(0)
    else:
        print(f"[FAILURE] Expected verdict 'suspicious_bruteforce_candidate', got '{result.get('verdict')}'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
