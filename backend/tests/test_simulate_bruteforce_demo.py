"""Tests for the brute-force demo simulator's credential handling.

The simulator lives at the repository root, outside the backend package. It is
loaded by path and all HTTP calls are replaced with deterministic in-memory
doubles, so no server, network, or credential is required.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "simulate_bruteforce_demo.py"
)
_spec = importlib.util.spec_from_file_location(
    "simulate_bruteforce_demo", _SCRIPT_PATH
)
simulator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(simulator)

_KEY_SENTINEL = "local-only-sentinel-key"


class _HealthResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def _set_argv(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["simulate_bruteforce_demo.py", *args])


def _stub_network(monkeypatch, captured):
    monkeypatch.setattr(simulator, "urlopen", lambda *a, **k: _HealthResponse())
    monkeypatch.setattr(
        simulator,
        "send_request",
        lambda url, payload: (
            401,
            {"detail": "invalid credentials"},
            {"x-request-id": "test-request-id"},
        ),
    )

    def fake_get_analysis(url, api_key):
        captured["api_key"] = api_key
        captured["analysis_url"] = url
        return 200, {
            "verdict": "suspicious_bruteforce_candidate",
            "analyzed_event_count": 5,
            "failed_attempt_count": 5,
            "distinct_client_count": 1,
            "summary": "demo summary",
            "evidences": [],
        }

    monkeypatch.setattr(simulator, "get_analysis", fake_get_analysis)
    monkeypatch.setattr(simulator, "time", SimpleNamespace(sleep=lambda _seconds: None))


def test_missing_api_key_fails_safely(monkeypatch, capsys):
    monkeypatch.delenv(simulator.API_KEY_ENV_VAR, raising=False)
    _set_argv(monkeypatch)
    calls = []
    monkeypatch.setattr(simulator, "urlopen", lambda *a, **k: calls.append(a))

    with pytest.raises(SystemExit) as exc:
        simulator.main()

    assert exc.value.code == 2
    assert calls == []
    output = capsys.readouterr()
    assert "ERROR" in output.err
    assert "--api-key" in output.err
    assert simulator.API_KEY_ENV_VAR in output.err
    assert output.out == ""


def test_blank_api_key_is_treated_as_missing(monkeypatch, capsys):
    monkeypatch.setenv(simulator.API_KEY_ENV_VAR, "   ")
    _set_argv(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        simulator.main()

    assert exc.value.code == 2
    assert "No API key supplied" in capsys.readouterr().err


@pytest.mark.parametrize("via_environment", [False, True])
def test_supplied_api_key_is_used_and_never_printed(
    monkeypatch, capsys, caplog, via_environment
):
    caplog.set_level("DEBUG")
    captured = {}
    _stub_network(monkeypatch, captured)
    if via_environment:
        monkeypatch.setenv(simulator.API_KEY_ENV_VAR, _KEY_SENTINEL)
        _set_argv(monkeypatch)
    else:
        monkeypatch.delenv(simulator.API_KEY_ENV_VAR, raising=False)
        _set_argv(monkeypatch, "--api-key", _KEY_SENTINEL)

    with pytest.raises(SystemExit) as exc:
        simulator.main()

    assert exc.value.code == 0
    assert captured["api_key"] == _KEY_SENTINEL
    assert captured["analysis_url"].endswith(
        "/api/v1/security/bruteforce/analyze"
    )
    output = capsys.readouterr()
    assert _KEY_SENTINEL not in output.out
    assert _KEY_SENTINEL not in output.err
    assert _KEY_SENTINEL not in caplog.text


def test_resolve_api_key_precedence_and_blank_values():
    env = {simulator.API_KEY_ENV_VAR: "env-key"}
    assert simulator.resolve_api_key("cli-key", env) == "cli-key"
    assert simulator.resolve_api_key(None, env) == "env-key"
    assert simulator.resolve_api_key("  ", env) is None
    assert simulator.resolve_api_key(None, {}) is None
