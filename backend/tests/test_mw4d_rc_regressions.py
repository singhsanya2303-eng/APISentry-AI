"""MW4-D release-candidate focused regressions (safe, non-PG)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_p1_harness_cli_rejects_out_of_bounds(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    script = repo / "backend" / "scripts" / "run_mw4_p1_harness.py"
    cmd = [sys.executable, str(script), "--out", str(tmp_path / "out"), "--n-per-category", "201"]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo))
    assert p.returncode != 0
    assert "n-per-category" in (p.stderr + p.stdout).lower()


def test_p1_harness_cli_rejects_negative_iterations(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    script = repo / "backend" / "scripts" / "run_mw4_p1_harness.py"
    cmd = [sys.executable, str(script), "--out", str(tmp_path / "out"), "--iterations", "-1"]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo))
    assert p.returncode != 0
    assert "iterations" in (p.stderr + p.stdout).lower()