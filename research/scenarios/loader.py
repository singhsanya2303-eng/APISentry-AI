"""Load and validate scenario definitions without executing traffic."""

from pathlib import Path

import yaml

from research.capture.models import ExperimentScenario
from research.capture.target_validation import validate_target_origin


def load_scenario(path: Path) -> ExperimentScenario:
    """Load one YAML scenario and validate its local target origin."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("scenario YAML must contain a mapping")
    scenario = ExperimentScenario.model_validate(data)
    validate_target_origin(scenario.target_origin)
    return scenario


def load_scenarios(directory: Path) -> list[ExperimentScenario]:
    """Load all scenario YAML files in deterministic filename order."""
    return [load_scenario(path) for path in sorted(directory.glob("*.yaml"))]
