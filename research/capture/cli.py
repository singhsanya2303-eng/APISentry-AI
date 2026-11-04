"""Fail-closed CLI for validation, dry-run, execution, and collection."""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from research.capture.action_mapping import (
    RequestClassification,
    RequestDiagnostic,
    correlate_request,
)
from research.capture.models import (
    ActionPhase,
    CaptureKind,
    ExperimentAction,
    ExperimentScenario,
)
from research.capture.runners import (
    ResponseInspectionError,
    RequestObservation,
    event_id_for_action,
    execute_http_request,
)
from research.capture.sanitize import sanitize_observation, to_canonical_event
from research.capture.target_validation import ApprovedOrigin, validate_target_origin
from research.datasets.evaluation import build_split_metadata, create_evaluation_splits
from research.datasets.manifest import (
    build_manifest,
    verify_manifest,
    write_manifest,
)
from research.datasets.reader import read_events
from research.datasets.writer import write_events
from research.scenarios.loader import load_scenario, load_scenarios

DEFAULT_TARGET = "http://127.0.0.1:8888"
DEFAULT_SCENARIOS = Path(__file__).parents[1] / "scenarios"
ACCEPTED_SIGNUP_STATUS_CODES = frozenset({200})
ACCEPTED_LOGIN_STATUS_CODES = frozenset({200})


@dataclass
class ExecutionDiagnostics:
    excluded: list[RequestDiagnostic] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    cleanup_pending: list[str] = field(default_factory=list)
    cleanup_accounts: list[dict[str, str]] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)


def ordered_actions(scenario: ExperimentScenario) -> list[ExperimentAction]:
    return [*scenario.setup_actions, *scenario.actions, *scenario.cleanup_actions]


def action_request_count(action: ExperimentAction) -> int:
    value = action.execution.get("request_count", 1)
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"action {action.action_id} has invalid request_count")
    if value > 20:
        raise ValueError(f"action {action.action_id} exceeds request bound")
    return value


def build_execution_plan(scenario: ExperimentScenario) -> list[str]:
    """Create a side-effect-free execution plan for dry-run output."""
    plan: list[str] = []

    for action in ordered_actions(scenario):
        method = action.execution.get("method")
        path = action.execution.get("path")

        if action.phase is ActionPhase.CLEANUP and method == "NONE":
            plan.append(
                f"{action.phase.value}: {action.action_id} (operator cleanup)"
            )
            continue

        count = action_request_count(action)
        line = (
            f"{action.phase.value}: "
            f"{action.action_id} "
            f"{method} "
            f"{path} "
            f"x{count} "
            f"label={action.label.value}"
        )

        plan.append(line)

    return plan


def _runtime_accounts(scenario: ExperimentScenario) -> dict[str, dict[str, str]]:
    accounts: dict[str, dict[str, str]] = {}
    for account in scenario.controlled_accounts:
        accounts[account.account_id] = {
            "email": f"{account.account_id}.{secrets.token_hex(8)}@example.invalid",
            "name": f"APISentry {account.account_id}",
            "number": f"+1555{secrets.randbelow(10**7):07d}",
            "password": secrets.token_urlsafe(24),
        }
    return accounts


def _request_payload(
    action: ExperimentAction,
    *,
    account: dict[str, str] | None,
    invalid: bool = False,
) -> dict[str, str]:
    fields = action.execution.get("body_fields", [])
    if not isinstance(fields, list):
        raise ValueError(f"action {action.action_id} body_fields must be a list")
    if "coupon_code" in fields:
        return {"coupon_code": "INVALID-TEST"}
    if account is None:
        return {}
    payload = {field: account.get(field, "SAFE-TEST") for field in fields}
    if invalid and "password" in payload:
        payload["password"] = "invalid-runtime-password"
    return payload


def _action_account(scenario: ExperimentScenario, action: ExperimentAction):
    for account in scenario.controlled_accounts:
        if account.principal_id == action.principal_id:
            return account.account_id
    return None


def _actual_outcome(action: ExperimentAction, status_code: int) -> str:
    if action.attack_category == "bola_idor":
        return "inconclusive: response semantics require runtime verification"
    if action.attack_category in {"brute_force", "rate_abuse", "malformed_input"}:
        return f"observed_status_{status_code}"
    return f"observed_status_{status_code}"


def crapi_commit(repository: Path) -> str:
    """Return the checked-out crAPI commit, failing closed if unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("unable to establish crAPI Git provenance") from exc
    commit = result.stdout.strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError("crAPI Git provenance is not a valid commit")
    return commit


def _token_inspector(token_store: dict[str, str], account_id: str | None):
    def inspect(body: bytes) -> None:
        if account_id is None:
            raise RuntimeError("login action has no controlled account")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("login response did not contain a valid token") from None
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("login response did not contain a valid token")
        token_store[account_id] = token

    return inspect


def _vehicle_inspector(discovered: dict[str, str], owner_account_id: str):
    def inspect(body: bytes) -> None:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        vehicles = payload.get("vehicles", payload) if isinstance(payload, dict) else payload
        if not isinstance(vehicles, list):
            return
        for vehicle in vehicles:
            if not isinstance(vehicle, dict):
                continue
            owner_id = next(
                (
                    vehicle.get(key)
                    for key in ("ownerAccountId", "owner_account_id", "ownerId", "owner_id")
                ),
                None,
            )
            if owner_id is None or str(owner_id) != owner_account_id:
                return
            vehicle_id = next(
                (vehicle.get(key) for key in ("vehicleId", "vehicle_id", "carId", "id")),
                None,
            )
            if vehicle_id is not None:
                discovered["vehicle_id"] = str(vehicle_id)
                discovered["owner_account_id"] = owner_account_id
                return

    return inspect


def _bola_outcome_inspector(outcome: dict[str, str], resource_id: str):
    def inspect(body: bytes) -> None:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        returned_id = next(
            (payload.get(key) for key in ("vehicleId", "vehicle_id", "carId", "id")),
            None,
        )
        protected_keys = {
            "latitude",
            "longitude",
            "location",
            "address",
            "geolocation",
        }
        has_protected_data = any(
            key in payload and payload[key] not in (None, "", [], {})
            for key in protected_keys
        )
        outcome["value"] = (
            "confirmed_access"
            if returned_id is not None
            and str(returned_id) == resource_id
            and has_protected_data
            else "inconclusive"
        )

    return inspect


def _root_cause(exc: BaseException) -> BaseException:
    cause = exc
    seen: set[int] = set()
    while id(cause) not in seen:
        seen.add(id(cause))
        next_cause = cause.__cause__ or cause.__context__
        if next_cause is None:
            break
        cause = next_cause
    return cause


def _safe_failure_detail(
    *,
    scenario_id: str,
    action_id: str | None,
    exc: BaseException,
    status_code: int | None,
) -> str:
    detail = (
        f"{scenario_id}: action={action_id or 'unknown'} "
        f"failure={type(exc).__name__} "
        f"root_cause={type(_root_cause(exc)).__name__}"
    )
    if status_code is not None:
        detail += f" status={status_code}"
    return detail


def execute_scenario(
    scenario: ExperimentScenario,
    *,
    origin: ApprovedOrigin,
    principal_secret: str | bytes,
    max_requests: int,
    diagnostics: ExecutionDiagnostics | None = None,
) -> ExecutionDiagnostics:
    """Execute one selected scenario; caller must have explicitly enabled execution."""
    diagnostics = diagnostics or ExecutionDiagnostics()
    accounts = _runtime_accounts(scenario)
    diagnostics.cleanup_accounts.extend(
        {"account_id": account_id, "email": values["email"]}
        for account_id, values in accounts.items()
    )
    tokens: dict[str, str] = {}
    discovered: dict[str, str] = {}
    request_total = 0
    current_action_id: str | None = None
    response_status: int | None = None
    client = httpx.Client(timeout=30.0, follow_redirects=False)
    try:
        for action in ordered_actions(scenario):
            current_action_id = action.action_id
            response_status = None
            method = action.execution.get("method")
            path = action.execution.get("path")
            if action.phase is ActionPhase.CLEANUP and method == "NONE":
                diagnostics.cleanup_pending.append(action.action_id)
                continue
            if not isinstance(method, str) or method not in {
                "GET", "POST", "PUT", "DELETE"
            }:
                raise ValueError(f"unsupported HTTP method for {action.action_id}")
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError(f"unsupported HTTP path for {action.action_id}")
            if "${" in path:
                if "${victim_vehicle_id}" not in path:
                    raise RuntimeError(f"{action.action_id}: unsupported runtime placeholder")
                if (
                    discovered.get("vehicle_id") is None
                    or discovered.get("owner_account_id") != "bola_victim"
                ):
                    raise RuntimeError(
                        f"{action.action_id}: victim resource ownership is unresolved"
                    )
                path = path.replace("${victim_vehicle_id}", discovered["vehicle_id"])
            count = action_request_count(action)
            if request_total + count > max_requests:
                raise ValueError("CLI maximum request limit exceeded")
            account_id = _action_account(scenario, action)
            account = accounts.get(account_id) if account_id else None
            if (
                action.execution.get("authentication") == "bearer_jwt"
                and account_id not in tokens
            ):
                raise RuntimeError(
                    f"{action.action_id}: no validated authentication token"
                )
            headers: dict[str, str] = {"Accept": "application/json"}
            if account_id in tokens:
                headers["Authorization"] = "Bearer " + tokens[account_id]
            payload = _request_payload(
                action,
                account=account,
                invalid=action.attack_category == "brute_force",
            )
            for sequence in range(count):
                if sequence:
                    time.sleep(int(action.execution.get("delay_ms", 0)) / 1000)
                bola_outcome = {"value": "inconclusive"}
                response_inspector = (
                    _token_inspector(tokens, account_id)
                    if action.execution.get("openapi_operation") == "login"
                    else (
                        _vehicle_inspector(discovered, "bola_victim")
                        if action.action_id == "bola_establish_victim_resource"
                        else (
                            _bola_outcome_inspector(
                                bola_outcome,
                                discovered["vehicle_id"],
                            )
                            if action.attack_category == "bola_idor"
                            and "vehicle_id" in discovered
                            else None
                        )
                    )
                )
                observation = execute_http_request(
                    client=client,
                    origin=origin,
                    action=action,
                    event_id=event_id_for_action(action.action_id, sequence),
                    method=method,
                    path=path,
                    headers=headers,
                    params=action.execution.get("query_parameters"),
                    json=payload or None,
                    response_inspector=response_inspector,
                )
                response_status = observation.status_code
                request_total += 1
                operation = action.execution.get("openapi_operation")
                if operation == "signup" and observation.status_code not in ACCEPTED_SIGNUP_STATUS_CODES:
                    raise RuntimeError(f"{action.action_id}: registration was not accepted")
                if operation == "login" and observation.status_code not in ACCEPTED_LOGIN_STATUS_CODES:
                    raise RuntimeError(f"{action.action_id}: login was not accepted")
                mapped, diagnostic = correlate_request(
                    event_id=observation.event_id,
                    classification=RequestClassification.PRIMARY_API,
                    action=action,
                )
                if diagnostic is not None:
                    diagnostics.excluded.append(diagnostic)
                    continue
                if mapped is None:
                    raise ValueError("primary request was not mapped")
                capture = sanitize_observation(
                    observation,
                    actual_outcome=(
                        bola_outcome["value"]
                        if action.attack_category == "bola_idor"
                        else _actual_outcome(action, observation.status_code)
                    ),
                )
                diagnostics.events.append(
                    to_canonical_event(
                        capture,
                        source_dataset=scenario.source_dataset,
                        principal_secret=principal_secret,
                    )
                )
    except Exception as exc:
        if isinstance(exc, ResponseInspectionError):
            response_status = exc.status_code
        detail = _safe_failure_detail(
            scenario_id=scenario.scenario_id,
            action_id=current_action_id,
            exc=exc,
            status_code=response_status,
        )
        diagnostics.failures.append(detail)
        raise RuntimeError(
            f"scenario execution failed; cleanup required ({detail})"
        ) from exc
    finally:
        client.close()
        known_cleanup = set(diagnostics.cleanup_pending)
        for cleanup_action in scenario.cleanup_actions:
            if cleanup_action.action_id not in known_cleanup:
                diagnostics.cleanup_pending.append(cleanup_action.action_id)
        accounts.clear()
        tokens.clear()
        discovered.clear()
    return diagnostics


def _scenario_selection(directory: Path, scenario_ids: list[str]) -> list[ExperimentScenario]:
    scenarios = load_scenarios(directory)
    if not scenario_ids:
        raise ValueError("explicit scenario IDs are required for execution")
    selected = [scenario for scenario in scenarios if scenario.scenario_id in scenario_ids]
    missing = set(scenario_ids) - {scenario.scenario_id for scenario in selected}
    if missing:
        raise ValueError(f"unknown scenario IDs: {', '.join(sorted(missing))}")
    return selected


def _print_summary(diagnostics: ExecutionDiagnostics) -> None:
    labels = Counter(event.label for event in diagnostics.events)
    categories = Counter(
        event.attack_category
        for event in diagnostics.events
        if event.attack_category
    )
    print(f"events={len(diagnostics.events)} labels={dict(labels)} categories={dict(categories)}")
    print(
        f"excluded={len(diagnostics.excluded)} "
        f"failures={len(diagnostics.failures)} "
        f"cleanup_pending={len(diagnostics.cleanup_pending)}"
    )
    if diagnostics.cleanup_accounts:
        print(
            "cleanup_accounts="
            + ",".join(
                f"{item['account_id']}:{item['email']}"
                for item in diagnostics.cleanup_accounts
            )
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m research.capture.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "dry-run"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--scenario-dir", type=Path, default=DEFAULT_SCENARIOS)
        sub.add_argument("--scenario", action="append", default=[])
    sub = subparsers.add_parser("verify-manifest")
    sub.add_argument("--manifest", type=Path, required=True)
    sub.add_argument("--principal-secret-env", default="APISENTRY_PRINCIPAL_SECRET")
    sub.add_argument("--dataset-root", type=Path)
    for command in ("run", "collect"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--scenario-dir", type=Path, default=DEFAULT_SCENARIOS)
        sub.add_argument("--scenario", action="append", required=True)
        sub.add_argument("--execute", action="store_true")
        sub.add_argument("--target", default=DEFAULT_TARGET)
        sub.add_argument("--principal-secret-env", default="APISENTRY_PRINCIPAL_SECRET")
        sub.add_argument("--max-requests", type=int, default=20)
        sub.add_argument("--output-dir", type=Path, default=Path(".research-local"))
        sub.add_argument(
            "--crapi-repository",
            type=Path,
            default=Path(__file__).parents[3] / "crAPI",
        )
    sub = subparsers.add_parser("split")
    sub.add_argument("--events", type=Path, required=True)
    sub.add_argument(
        "--strategy",
        choices=(
            "known-category",
            "random",
            "campaign",
            "principal",
            "time",
            "held-out-category",
        ),
        required=True,
    )
    sub.add_argument("--seed", type=int)
    sub.add_argument("--principal-secret-env", default="APISENTRY_PRINCIPAL_SECRET")
    sub.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"validate", "dry-run"}:
        scenarios = (
            _scenario_selection(args.scenario_dir, args.scenario)
            if args.scenario
            else load_scenarios(args.scenario_dir)
        )
        for scenario in scenarios:
            print(f"{scenario.scenario_id}: valid")
            if args.command == "dry-run":
                print("\n".join(build_execution_plan(scenario)))
        return 0
    if args.command in {"run", "collect"}:
        if not args.execute:
            raise SystemExit("--execute is required for network execution")
        if args.max_requests < 1 or args.max_requests > 100:
            raise SystemExit("--max-requests must be between 1 and 100")
        if args.target != DEFAULT_TARGET:
            raise SystemExit("only the default local target is permitted")
        secret = os.environ.get(args.principal_secret_env)
        if not secret:
            raise SystemExit("principal secret environment variable is required")
        origin = validate_target_origin(args.target)
        events = []
        diagnostics = ExecutionDiagnostics()
        for scenario in _scenario_selection(args.scenario_dir, args.scenario):
            execute_scenario(
                scenario,
                origin=origin,
                principal_secret=secret,
                max_requests=args.max_requests,
                diagnostics=diagnostics,
            )
        _print_summary(diagnostics)
        if args.command == "collect":
            output = args.output_dir / "events.jsonl"
            checksum = write_events(diagnostics.events, output)
            persisted_events = read_events(output, principal_secret=secret)
            if len(persisted_events) != len(diagnostics.events):
                raise RuntimeError("manifest event count does not match JSONL records")
            manifest = build_manifest(
                persisted_events,
                dataset_name="custom_crapi",
                dataset_version="1.0",
                crapi_commit=crapi_commit(args.crapi_repository),
                collection_run_id=secrets.token_hex(8),
                files=[output],
            )
            manifest["excluded_event_count"] = len(diagnostics.excluded)
            manifest["execution_failures"] = len(diagnostics.failures)
            manifest["files"][0]["sha256"] = checksum
            write_manifest(manifest, args.output_dir / "manifest.yaml")
        return 0
    if args.command == "verify-manifest":
        secret = os.environ.get(args.principal_secret_env)
        if not secret:
            raise SystemExit("principal secret environment variable is required")
        result = verify_manifest(
            args.manifest,
            principal_secret=secret,
            dataset_root=args.dataset_root,
        )
        print(
            f"verified_events={result['event_count']} "
            f"verified_files={len(result['verified_files'])}"
        )
        return 0
    if args.command == "split":
        secret = os.environ.get(args.principal_secret_env)
        if not secret:
            raise SystemExit("principal secret environment variable is required")
        events = read_events(args.events, principal_secret=secret)
        splits = create_evaluation_splits(
            events,
            strategy=args.strategy,
            seed=args.seed,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        split_paths = {}
        for name, split_events in splits.items():
            split_path = args.output_dir / f"{name}.jsonl"
            write_events(split_events, split_path)
            if len(read_events(split_path, principal_secret=secret)) != len(split_events):
                raise RuntimeError(f"split validation failed for {name}")
            split_paths[name] = split_path
        split_metadata = build_split_metadata(
            splits,
            strategy=args.strategy,
            seed=args.seed,
            files=split_paths,
        )
        write_manifest(
            {"schema_version": "1.0", "split_metadata": split_metadata},
            args.output_dir / "split_metadata.yaml",
        )
        print(f"strategy={args.strategy} splits={','.join(splits)}")
        return 0
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
