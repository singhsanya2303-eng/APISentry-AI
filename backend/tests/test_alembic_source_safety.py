"""Source-only Alembic chain validation.

These tests parse migration files as Python source. They do not import Alembic
commands, create engines, connect to databases, stamp revisions, or run DDL.
"""

import ast
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"

EXPECTED_CHAIN = [
    (
        "0001_baseline_existing_schema.py",
        "0001_baseline_existing_schema",
        None,
        {"api_traffic_logs", "users"},
    ),
    (
        "0002_mitigation_policy_models.py",
        "0002_mitigation_policy_models",
        "0001_baseline_existing_schema",
        {
            "mitigation_policies",
            "mitigation_policy_state",
            "mitigation_policy_activation_events",
        },
    ),
    (
        "0003_mitigation_decision_audit.py",
        "0003_mitigation_decision_audit",
        "0002_mitigation_policy_models",
        {"mitigation_decisions", "mitigation_audit_events"},
    ),
    (
        "0004_revoked_tokens.py",
        "0004_revoked_tokens",
        "0003_mitigation_decision_audit",
        {"revoked_tokens"},
    ),
]


def _parse(filename: str) -> tuple[str, ast.Module]:
    path = VERSIONS_DIR / filename
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=str(path))


def _literal_assignment(tree: ast.Module, name: str):
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"missing module assignment: {name}")


def _created_tables(tree: ast.Module) -> set[str]:
    tables = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create_table"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            tables.add(node.args[0].value)
    return tables


def _foreign_key_targets(tree: ast.Module) -> set[str]:
    targets = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "ForeignKey" and node.args:
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                targets.add(value.value.split(".", 1)[0])
        elif node.func.attr == "ForeignKeyConstraint" and len(node.args) > 1:
            ref_arg = node.args[1]
            if isinstance(ref_arg, ast.List):
                for element in ref_arg.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        targets.add(element.value.split(".", 1)[0])
    return targets


def test_only_reviewed_migration_files_exist():
    actual = {path.name for path in VERSIONS_DIR.glob("*.py")}
    assert actual == {entry[0] for entry in EXPECTED_CHAIN}


def test_revision_chain_is_linear_and_matches_expected_order():
    parsed = {
        filename: _parse(filename)[1]
        for filename, _, _, _ in EXPECTED_CHAIN
    }
    for index, (filename, revision, parent, _) in enumerate(EXPECTED_CHAIN):
        tree = parsed[filename]
        assert _literal_assignment(tree, "revision") == revision
        assert _literal_assignment(tree, "down_revision") == parent
        assert _literal_assignment(tree, "branch_labels") is None
        assert _literal_assignment(tree, "depends_on") is None
        if index:
            previous_revision = EXPECTED_CHAIN[index - 1][1]
            assert parent == previous_revision


def test_revision_ids_fit_alembic_version_varchar32():
    for filename, revision, _, _ in EXPECTED_CHAIN:
        assert len(revision) <= 32, filename
        assert revision, filename


def test_baseline_downgrade_is_deliberately_refused():
    source, tree = _parse(EXPECTED_CHAIN[0][0])
    downgrade = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "downgrade"
    )
    assert any(isinstance(node, ast.Raise) for node in ast.walk(downgrade))
    assert "RuntimeError" in source
    assert "downgradeable" in source


def test_each_revision_creates_only_its_expected_tables():
    available_tables: set[str] = set()
    for filename, _, _, expected_tables in EXPECTED_CHAIN:
        created = _created_tables(_parse(filename)[1])
        assert created == expected_tables, filename
        available_tables |= created

    assert len(available_tables) == 8
    assert "alembic_version" not in available_tables


def test_foreign_keys_reference_tables_created_earlier_in_chain():
    available_tables: set[str] = set()
    for filename, _, _, _ in EXPECTED_CHAIN:
        tree = _parse(filename)[1]
        created_here = _created_tables(tree)
        for target in _foreign_key_targets(tree):
            assert target in available_tables | created_here, (filename, target)
        available_tables |= created_here
