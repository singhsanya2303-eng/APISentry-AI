"""Read-only, revision-aware existing-schema verification.

The verifier never modifies schema or data and never stamps a revision. It
inspects schema objects and performs one read-only SELECT of ``alembic_version``
when that table exists. It prints schema object names and reason codes only;
no records, credentials, DSNs, host names, API keys, request IDs, IP addresses,
emails, or usernames are emitted.

Data checksums are intentionally not implemented. A safe checksum would require
a securely managed key outside the database and a documented reproducible
canonicalization; that is a documented prerequisite rather than a weak shortcut.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Sequence, Tuple

from sqlalchemy import CheckConstraint, create_engine, inspect, text

from app.models import (
    APITrafficLog,
    MitigationAuditEvent,
    MitigationDecision,
    MitigationPolicy,
    MitigationPolicyActivationEvent,
    MitigationPolicyState,
    RevokedToken,
    User,
)

KNOWN_EXTRA_TABLES = frozenset({"alembic_version"})

# Explicit, revision-independent expectation sets. Importing the model package
# registers later models in Base.metadata, so the baseline must not be derived
# from the whole registry.
_PHASE0_TABLES = (User.__table__, APITrafficLog.__table__)
_PHASE1_TABLES = (
    MitigationPolicy.__table__,
    MitigationPolicyState.__table__,
    MitigationPolicyActivationEvent.__table__,
)
_PHASE2_TABLES = (
    MitigationDecision.__table__,
    MitigationAuditEvent.__table__,
)
_PHASE3_TABLES = (
    RevokedToken.__table__,
)
_BASELINE_REVISION = "0001_baseline_existing_schema"
_PHASE1_REVISION = "0002_mitigation_policy_models"
_PHASE2_REVISION = "0003_mitigation_decision_audit"
_PHASE3_REVISION = "0004_revoked_tokens"

_STATUS_PASS = "PASS"
_STATUS_FAIL = "FAIL"
_STATUS_INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    """A single safe, actionable verification finding."""

    status: str
    code: str
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """Aggregated verification result."""

    dialect: str
    findings: Tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        """Return True only when no FAIL finding was produced."""
        return all(finding.status != _STATUS_FAIL for finding in self.findings)

    def render(self) -> str:
        """Render a non-sensitive, human-readable report."""
        lines = [
            f"SCHEMA_VERIFICATION: {_STATUS_PASS if self.passed else _STATUS_FAIL}",
            f"DIALECT: {self.dialect}",
            "FINDINGS:",
        ]
        for finding in self.findings:
            lines.append(f"  {finding.status} {finding.code}: {finding.detail}")
        return "\n".join(lines)


def _read_revision_state(engine, inspector) -> Tuple[Optional[str], List[Finding]]:
    """Read the stored revision without guessing or modifying revision state."""
    if "alembic_version" not in set(inspector.get_table_names()):
        return None, []

    try:
        columns = {
            str(column["name"]) for column in inspector.get_columns("alembic_version")
        }
        if "version_num" not in columns:
            return None, [
                Finding(
                    _STATUS_FAIL,
                    "MALFORMED_REVISION_STATE",
                    "alembic_version has no version_num column",
                )
            ]

        # The only SQL emitted by the verifier is this read-only SELECT.
        with engine.connect() as connection:
            rows = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).fetchall()
    except Exception:  # noqa: BLE001 - never emit raw exception text or DSNs
        return None, [
            Finding(
                _STATUS_FAIL,
                "REVISION_INSPECTION_FAILED",
                "Stored revision could not be inspected safely",
            )
        ]

    values = [row[0] for row in rows]
    if not values:
        return None, [
            Finding(
                _STATUS_FAIL,
                "EMPTY_REVISION_STATE",
                "alembic_version contains no revision row",
            )
        ]
    if len(values) != 1:
        return None, [
            Finding(
                _STATUS_FAIL,
                "MULTIPLE_REVISION_ROWS",
                "alembic_version must contain exactly one revision row",
            )
        ]

    revision = values[0]
    if (
        not isinstance(revision, str)
        or not revision
        or revision != revision.strip()
    ):
        return None, [
            Finding(
                _STATUS_FAIL,
                "MALFORMED_REVISION_STATE",
                "alembic_version contains an empty or malformed revision",
            )
        ]
    if revision not in {_BASELINE_REVISION, _PHASE1_REVISION, _PHASE2_REVISION, _PHASE3_REVISION}:
        return None, [
            Finding(
                _STATUS_FAIL,
                "UNKNOWN_REVISION",
                "alembic_version contains an unknown revision",
            )
        ]

    return revision, []


def _type_family(value: object) -> str:
    """Normalize SQLAlchemy or reflected type strings into a portable family."""
    text = str(value).upper()
    if "JSON" in text:
        return "json"
    if "TIMESTAMP" in text or "DATETIME" in text:
        return "datetime"
    if "BOOL" in text:
        return "boolean"
    if "INT" in text:
        return "integer"
    if any(token in text for token in ("FLOAT", "REAL", "DOUBLE", "NUMERIC", "DECIMAL")):
        return "numeric"
    if any(token in text for token in ("VARCHAR", "CHAR", "TEXT", "STRING")):
        return "string"
    return "other"


def _expected_indexes(table) -> Dict[str, Tuple[List[str], bool]]:
    """Build expected index definitions from SQLAlchemy metadata."""
    return {
        index.name: ([column.name for column in index.columns], bool(index.unique))
        for index in table.indexes
    }


def _actual_indexes(inspector, table_name: str) -> Dict[str, Tuple[List[str], bool]]:
    """Build actual index definitions from a read-only SQLAlchemy inspector."""
    definitions: Dict[str, Tuple[List[str], bool]] = {}
    for index in inspector.get_indexes(table_name):
        columns = [column for column in index.get("column_names", []) if column is not None]
        definitions[str(index.get("name", "unnamed"))] = (columns, bool(index.get("unique")))
    return definitions


# (constrained columns, referenced table, referenced columns, ON DELETE)
_ForeignKeyDefinition = Tuple[Tuple[str, ...], Optional[str], Tuple[str, ...], Optional[str]]
_ForeignKeyKey = Tuple[str, Tuple[str, ...]]


def _foreign_key_key(name: object, columns: Sequence[str]) -> _ForeignKeyKey:
    """Build a stable key for named and unnamed reflected foreign keys."""
    return ("" if name is None else str(name), tuple(columns))


def _normalized_ondelete(value: object) -> Optional[str]:
    """Normalize dialect-specific ON DELETE spellings without emitting values."""
    if value is None:
        return None
    normalized = str(value).strip().upper()
    return normalized or None


def _expected_foreign_keys(table) -> Dict[_ForeignKeyKey, _ForeignKeyDefinition]:
    """Build expected foreign-key definitions from SQLAlchemy metadata."""
    definitions: Dict[_ForeignKeyKey, _ForeignKeyDefinition] = {}
    for foreign_key in table.foreign_key_constraints:
        columns = tuple(element.parent.name for element in foreign_key.elements)
        referenced_tables = {element.column.table.name for element in foreign_key.elements}
        referenced_table = next(iter(referenced_tables)) if len(referenced_tables) == 1 else None
        referenced_columns = tuple(element.column.name for element in foreign_key.elements)
        definitions[_foreign_key_key(foreign_key.name, columns)] = (
            columns,
            referenced_table,
            referenced_columns,
            _normalized_ondelete(foreign_key.ondelete),
        )
    return definitions


def _actual_foreign_keys(inspector, table_name: str) -> Dict[_ForeignKeyKey, _ForeignKeyDefinition]:
    """Build actual foreign-key definitions from a read-only inspector."""
    definitions: Dict[_ForeignKeyKey, _ForeignKeyDefinition] = {}
    for foreign_key in inspector.get_foreign_keys(table_name):
        columns = tuple(
            column
            for column in (foreign_key.get("constrained_columns") or [])
            if column is not None
        )
        options = foreign_key.get("options") or {}
        raw_ondelete = options.get("ondelete", foreign_key.get("ondelete"))
        definitions[_foreign_key_key(foreign_key.get("name"), columns)] = (
            columns,
            foreign_key.get("referred_table"),
            tuple(
                column
                for column in (foreign_key.get("referred_columns") or [])
                if column is not None
            ),
            _normalized_ondelete(raw_ondelete),
        )
    return definitions


def _string_column_names(table) -> frozenset[str]:
    """Return column names whose declared type is a string-like family."""
    return frozenset(
        column.name
        for column in table.columns
        if _type_family(column.type) == "string"
    )


class _UnsupportedCheckExpression(Exception):
    """Raised when a CHECK expression is outside the conservative grammar."""


@dataclass(frozen=True)
class _CheckToken:
    kind: str
    value: str


_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
_SYMBOL_KINDS = {
    "(": "lparen",
    ")": "rparen",
    ",": "comma",
    "[": "lbracket",
    "]": "rbracket",
}
_SAFE_TEXT_CASTS = frozenset({"TEXT", "VARCHAR", "CHARACTER VARYING", "TEXT[]"})
_STRING_RETURNING_FUNCTIONS = frozenset({"substr", "replace", "lower"})
_SQL_BOUNDARY_KEYWORDS = frozenset(
    {"AND", "OR", "NOT", "IS", "NULL", "IN", "BETWEEN", "LIKE"}
)


def _tokenize_check_expression(expression: str) -> list[_CheckToken]:
    """Tokenize the small, reviewed subset of SQL used by model CHECK clauses."""
    tokens: list[_CheckToken] = []
    index = 0
    length = len(expression)
    while index < length:
        char = expression[index]
        if char.isspace():
            index += 1
            continue
        if char == '"':
            index += 1
            value: list[str] = []
            while index < length:
                if expression[index] == '"':
                    if index + 1 < length and expression[index + 1] == '"':
                        value.append('"')
                        index += 2
                        continue
                    index += 1
                    break
                value.append(expression[index])
                index += 1
            else:
                raise _UnsupportedCheckExpression
            tokens.append(_CheckToken("ident", "".join(value)))
            continue
        if char == "'":
            index += 1
            value = []
            while index < length:
                if expression[index] == "'":
                    if index + 1 < length and expression[index + 1] == "'":
                        value.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(expression[index])
                index += 1
            else:
                raise _UnsupportedCheckExpression
            tokens.append(_CheckToken("string", "".join(value)))
            continue
        if expression.startswith("::", index):
            tokens.append(_CheckToken("cast", "::"))
            index += 2
            continue
        operator = next(
            (item for item in (">=", "<=", "<>", "!=") if expression.startswith(item, index)),
            None,
        )
        if operator is not None:
            tokens.append(_CheckToken("op", "<>" if operator == "!=" else operator))
            index += 2
            continue
        if char in "=<>+-*/":
            tokens.append(_CheckToken("op", char))
            index += 1
            continue
        if char in _SYMBOL_KINDS:
            tokens.append(_CheckToken(_SYMBOL_KINDS[char], char))
            index += 1
            continue
        match = _NUMBER_RE.match(expression, index)
        if match is not None:
            tokens.append(_CheckToken("number", match.group(0)))
            index = match.end()
            continue
        match = _IDENTIFIER_RE.match(expression, index)
        if match is not None:
            tokens.append(_CheckToken("ident", match.group(0)))
            index = match.end()
            continue
        raise _UnsupportedCheckExpression
    tokens.append(_CheckToken("eof", ""))
    return tokens


class _CheckExpressionParser:
    """Conservative recursive-descent parser for reviewed CHECK expressions."""

    def __init__(self, tokens: list[_CheckToken], string_columns: frozenset[str]):
        self._tokens = tokens
        self._position = 0
        self._string_columns = frozenset(name.lower() for name in string_columns)

    def parse(self):
        expression = self._parse_or()
        self._expect_symbol("eof")
        return expression

    def _peek(self) -> _CheckToken:
        return self._tokens[self._position]

    def _advance(self) -> _CheckToken:
        token = self._tokens[self._position]
        self._position += 1
        return token

    def _is_keyword(self, keyword: str) -> bool:
        token = self._peek()
        return token.kind == "ident" and token.value.lower() == keyword

    def _accept_keyword(self, keyword: str) -> bool:
        if not self._is_keyword(keyword):
            return False
        self._advance()
        return True

    def _expect_keyword(self, keyword: str) -> None:
        if not self._accept_keyword(keyword):
            raise _UnsupportedCheckExpression

    def _accept_symbol(self, kind: str) -> bool:
        if self._peek().kind != kind:
            return False
        self._advance()
        return True

    def _expect_symbol(self, kind: str) -> None:
        if not self._accept_symbol(kind):
            raise _UnsupportedCheckExpression

    def _parse_or(self):
        terms = [self._parse_and()]
        while self._accept_keyword("or"):
            terms.append(self._parse_and())
        return terms[0] if len(terms) == 1 else ("or", tuple(terms))

    def _parse_and(self):
        terms = [self._parse_not()]
        while self._accept_keyword("and"):
            terms.append(self._parse_not())
        return terms[0] if len(terms) == 1 else ("and", tuple(terms))

    def _parse_not(self):
        if self._accept_keyword("not"):
            return ("not", self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self):
        left = self._parse_value()
        if self._accept_keyword("is"):
            negated = self._accept_keyword("not")
            self._expect_keyword("null")
            return ("is_not_null" if negated else "is_null", left)

        negated = self._accept_keyword("not")
        if self._accept_keyword("between"):
            lower = self._parse_value()
            self._expect_keyword("and")
            upper = self._parse_value()
            expression = ("between", left, lower, upper)
            return ("not", expression) if negated else expression
        if self._accept_keyword("in"):
            expression = ("in", left, self._parse_in_values())
            return ("not", expression) if negated else expression
        if negated:
            raise _UnsupportedCheckExpression

        token = self._peek()
        if token.kind != "op":
            return left
        operator = self._advance().value
        right = self._parse_value()
        if (
            operator == "="
            and right[0] == "any"
            and right[1][0] == "array"
            and all(item[0] == "lit" for item in right[1][1])
        ):
            return ("in", left, right[1][1])
        return ("op", operator, left, right)

    def _parse_in_values(self) -> tuple:
        self._expect_symbol("lparen")
        values = []
        if not self._accept_symbol("rparen"):
            while True:
                values.append(self._parse_value())
                if self._accept_symbol("comma"):
                    continue
                self._expect_symbol("rparen")
                break
        return tuple(values)

    def _parse_array(self) -> tuple:
        self._expect_symbol("lbracket")
        values = []
        if not self._accept_symbol("rbracket"):
            while True:
                values.append(self._parse_value())
                if self._accept_symbol("comma"):
                    continue
                self._expect_symbol("rbracket")
                break
        return ("array", tuple(values))

    def _parse_value(self):
        expression = self._parse_primary()
        while self._peek().kind == "cast":
            self._advance()
            target = self._parse_cast_target()
            expression = self._apply_cast(expression, target)
        return expression

    def _parse_cast_target(self) -> str:
        parts: list[str] = []
        while (
            self._peek().kind == "ident"
            and self._peek().value.upper() not in _SQL_BOUNDARY_KEYWORDS
        ):
            parts.append(self._advance().value.upper())
        if not parts:
            raise _UnsupportedCheckExpression
        if self._accept_symbol("lbracket"):
            self._expect_symbol("rbracket")
            parts[-1] += "[]"
        return " ".join(parts)

    def _apply_cast(self, expression: tuple, target: str) -> tuple:
        if target in _SAFE_TEXT_CASTS and self._is_safe_string_operand(expression):
            return expression
        return ("cast", target, expression)

    def _is_safe_string_operand(self, expression: tuple) -> bool:
        tag = expression[0]
        if tag == "lit":
            return True
        if tag == "ident":
            return expression[1] in self._string_columns
        if tag == "func":
            return expression[1] in _STRING_RETURNING_FUNCTIONS
        if tag == "array":
            return all(item[0] == "lit" for item in expression[1])
        return False

    def _parse_primary(self):
        if self._accept_symbol("lparen"):
            expression = self._parse_or()
            self._expect_symbol("rparen")
            return expression
        token = self._advance()
        if token.kind == "string":
            return ("lit", token.value)
        if token.kind == "number":
            return ("num", token.value)
        if token.kind == "op" and token.value in {"+", "-"}:
            following = self._advance()
            if following.kind != "number":
                raise _UnsupportedCheckExpression
            return ("num", token.value + following.value)
        if token.kind != "ident":
            raise _UnsupportedCheckExpression

        name = token.value.lower()
        if name == "array" and self._peek().kind == "lbracket":
            return self._parse_array()
        if self._peek().kind == "lparen":
            self._advance()
            arguments = []
            if not self._accept_symbol("rparen"):
                while True:
                    arguments.append(self._parse_value())
                    if self._accept_symbol("comma"):
                        continue
                    self._expect_symbol("rparen")
                    break
            if name == "any":
                if len(arguments) != 1:
                    raise _UnsupportedCheckExpression
                return ("any", arguments[0])
            return ("func", name, tuple(arguments))
        return ("ident", name)


def _canonicalize_check_ast(expression: tuple) -> tuple:
    """Apply only reviewed structural equivalences to a parsed expression."""
    tag = expression[0]
    if tag in {"and", "or"}:
        terms = tuple(_canonicalize_check_ast(term) for term in expression[1])
        if tag == "and":
            terms = _fold_between_terms(terms)
        if len(terms) == 1:
            return terms[0]
        return (tag, terms)
    if tag == "op":
        return (
            tag,
            expression[1],
            _canonicalize_check_ast(expression[2]),
            _canonicalize_check_ast(expression[3]),
        )
    if tag == "between":
        return (
            tag,
            _canonicalize_check_ast(expression[1]),
            _canonicalize_check_ast(expression[2]),
            _canonicalize_check_ast(expression[3]),
        )
    if tag == "in":
        return (
            tag,
            _canonicalize_check_ast(expression[1]),
            tuple(_canonicalize_check_ast(value) for value in expression[2]),
        )
    if tag in {"not", "is_null", "is_not_null", "any"}:
        return (tag, _canonicalize_check_ast(expression[1]))
    if tag == "func":
        return (
            tag,
            expression[1],
            tuple(_canonicalize_check_ast(arg) for arg in expression[2]),
        )
    if tag == "array":
        return (tag, tuple(_canonicalize_check_ast(item) for item in expression[1]))
    if tag == "cast":
        return (tag, expression[1], _canonicalize_check_ast(expression[2]))
    return expression


def _fold_between_terms(terms: tuple) -> tuple:
    """Fold a demonstrated ``>= low AND <= high`` pair into ``BETWEEN``."""
    folded: list[tuple] = []
    index = 0
    while index < len(terms):
        if index + 1 < len(terms):
            lower, upper = terms[index], terms[index + 1]
            if (
                lower[0] == "op"
                and lower[1] == ">="
                and upper[0] == "op"
                and upper[1] == "<="
                and lower[2] == upper[2]
            ):
                folded.append(("between", lower[2], lower[3], upper[3]))
                index += 2
                continue
        folded.append(terms[index])
        index += 1
    return tuple(folded)


def _encode_check_value(value: object) -> str:
    rendered = str(value)
    return f"{len(rendered)}:{rendered}"


def _dump_check_ast(expression: tuple) -> str:
    tag = expression[0]
    if tag == "ident":
        return f"ident({_encode_check_value(expression[1])})"
    if tag == "lit":
        return f"lit({_encode_check_value(expression[1])})"
    if tag == "num":
        return f"num({_encode_check_value(expression[1])})"
    if tag == "func":
        arguments = ",".join(_dump_check_ast(argument) for argument in expression[2])
        return f"func({_encode_check_value(expression[1])},{arguments})"
    if tag == "array":
        items = ",".join(_dump_check_ast(item) for item in expression[1])
        return f"array({items})"
    if tag in {"and", "or"}:
        terms = ",".join(_dump_check_ast(term) for term in expression[1])
        return f"{tag}({terms})"
    if tag == "op":
        return (
            f"op({_encode_check_value(expression[1])},"
            f"{_dump_check_ast(expression[2])},{_dump_check_ast(expression[3])})"
        )
    if tag == "between":
        return (
            f"between({_dump_check_ast(expression[1])},"
            f"{_dump_check_ast(expression[2])},{_dump_check_ast(expression[3])})"
        )
    if tag == "in":
        values = ",".join(_dump_check_ast(value) for value in expression[2])
        return f"in({_dump_check_ast(expression[1])},{values})"
    if tag in {"not", "is_null", "is_not_null", "any"}:
        return f"{tag}({_dump_check_ast(expression[1])})"
    if tag == "cast":
        return (
            f"cast({_encode_check_value(expression[1])},"
            f"{_dump_check_ast(expression[2])})"
        )
    raise _UnsupportedCheckExpression


def _normalized_check_expression(
    value: object, string_columns: frozenset[str] = frozenset()
) -> str:
    """Normalize a CHECK expression across reviewed model/reflection forms.

    Expressions inside the reviewed grammar are parsed into a conservative AST
    so that only demonstrated PostgreSQL equivalences are ignored. Anything
    outside that grammar falls back to a strict text comparison with no cast,
    operator, or grouping transformations.
    """
    expression = str(value)
    try:
        tokens = _tokenize_check_expression(expression)
        parsed = _CheckExpressionParser(tokens, string_columns).parse()
        canonical = _canonicalize_check_ast(parsed)
        return "ast-v1:" + _dump_check_ast(canonical)
    except _UnsupportedCheckExpression:
        strict = "".join(expression.lower().replace('"', "").split())
        return "strict-v1:" + strict


def _expected_check_constraints(table) -> Dict[str, str]:
    """Build expected CHECK definitions from SQLAlchemy metadata."""
    string_columns = _string_column_names(table)
    return {
        str(constraint.name): _normalized_check_expression(
            constraint.sqltext, string_columns
        )
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }


_SQLITE_NAMED_CHECK_PATTERN = re.compile(
    r"CONSTRAINT\s+(?P<name>\"[^\"]+\"|[^\s]+)\s+CHECK\s*\(", re.I
)


def _parse_reflected_checks(fragment: str) -> List[Tuple[str, str]]:
    """Parse named CHECK clauses from a reflected DDL fragment.

    SQLAlchemy's SQLite reflection regex greedily merges multiple same-line
    named CHECK constraints into one reflected ``name``. Re-parsing the
    reconstructed fragment with balanced-parenthesis tracking restores each
    individual name and expression. No clause is dropped or relaxed here; an
    unparseable fragment falls through to the strict whole-value comparison.
    """
    parsed: List[Tuple[str, str]] = []
    for match in _SQLITE_NAMED_CHECK_PATTERN.finditer(fragment):
        name = match.group("name").strip('"')
        start = match.end()
        depth = 1
        quote: Optional[str] = None
        cursor = start
        while cursor < len(fragment):
            char = fragment[cursor]
            if quote is not None:
                if char == quote:
                    if cursor + 1 < len(fragment) and fragment[cursor + 1] == quote:
                        cursor += 1
                    else:
                        quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if depth != 0:
            return []
        parsed.append((name, fragment[start:cursor].strip()))
    return parsed


def _expand_reflected_checks(constraint: dict) -> List[Tuple[str, object]]:
    """Expand SQLAlchemy's merged SQLite CHECK reflection into real checks."""
    name = constraint.get("name")
    sqltext = constraint.get("sqltext")
    if not isinstance(name, str) or not re.search(r"CHECK|CONSTRAINT", name, re.I):
        return [(str(name or ""), sqltext)]
    parsed = _parse_reflected_checks(f"CONSTRAINT {name} CHECK ({sqltext})")
    if len(parsed) < 2:
        return [(str(name or ""), sqltext)]
    return parsed


def _actual_check_constraints(
    inspector, table_name: str, string_columns: frozenset[str]
) -> Dict[str, str]:
    """Build actual CHECK definitions from a read-only SQLAlchemy inspector.

    SQLite reflection may merge several named CHECK clauses into one entry;
    those entries are expanded before normalization so a genuine definition
    change is reported as a definition mismatch instead of being split into
    misleading missing/unexpected constraint findings.
    """
    actual: Dict[str, str] = {}
    for constraint in inspector.get_check_constraints(table_name):
        for name, expression in _expand_reflected_checks(constraint):
            actual[name] = _normalized_check_expression(expression, string_columns)
    return actual


def _is_known_extra_index(table_name: str, index_name: str) -> bool:
    """Classify non-metadata indexes that are known application artifacts."""
    if table_name not in KNOWN_EXTRA_TABLES:
        return False
    return index_name.startswith("sqlite_autoindex_") or index_name.startswith("ix_alembic_version")


def _verify_table(inspector, table, findings: List[Finding]) -> None:
    """Compare one expected metadata table with the inspected table."""
    table_name = table.name
    actual_columns = {
        str(column["name"]): column for column in inspector.get_columns(table_name)
    }
    expected_columns = {column.name: column for column in table.columns}

    for name in sorted(expected_columns.keys() - actual_columns.keys()):
        findings.append(
            Finding(_STATUS_FAIL, "MISSING_COLUMN", f"{table_name}.{name} is missing")
        )
    for name in sorted(actual_columns.keys() - expected_columns.keys()):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "UNEXPECTED_COLUMN",
                f"{table_name}.{name} is not part of the reviewed baseline",
            )
        )

    for name in sorted(expected_columns.keys() & actual_columns.keys()):
        expected = expected_columns[name]
        actual = actual_columns[name]
        expected_family = _type_family(expected.type)
        actual_family = _type_family(actual.get("type"))
        if expected_family != actual_family:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "COLUMN_TYPE_MISMATCH",
                    f"{table_name}.{name} type family differs from metadata",
                )
            )
        if bool(expected.nullable) != bool(actual.get("nullable")):
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "COLUMN_NULLABILITY_MISMATCH",
                    f"{table_name}.{name} nullability differs from metadata",
                )
            )

    actual_pk = list(
        inspector.get_pk_constraint(table_name).get("constrained_columns", []) or []
    )
    expected_pk = [column.name for column in table.primary_key.columns]
    if set(actual_pk) != set(expected_pk):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "PRIMARY_KEY_MISMATCH",
                f"{table_name} primary key differs from metadata",
            )
        )

    expected_indexes = _expected_indexes(table)
    actual_indexes = _actual_indexes(inspector, table_name)

    for name in sorted(expected_indexes.keys() - actual_indexes.keys()):
        findings.append(
            Finding(_STATUS_FAIL, "MISSING_INDEX", f"{table_name}.{name} is missing")
        )
    for name in sorted(expected_indexes.keys() & actual_indexes.keys()):
        if expected_indexes[name] != actual_indexes[name]:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "INDEX_DEFINITION_MISMATCH",
                    f"{table_name}.{name} definition differs from metadata",
                )
            )
    for name in sorted(actual_indexes.keys() - expected_indexes.keys()):
        if _is_known_extra_index(table_name, name):
            findings.append(
                Finding(
                    _STATUS_INFO,
                    "KNOWN_ADDITIONAL_OBJECT",
                    f"{table_name}.{name} is a known Alembic metadata index",
                )
            )
        else:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "UNEXPECTED_INDEX",
                    f"{table_name}.{name} is not part of the reviewed baseline",
                )
            )

    expected_unique_columns = {
        tuple(columns)
        for columns, unique in expected_indexes.values()
        if unique
    }
    for constraint in inspector.get_unique_constraints(table_name):
        columns = tuple(
            column for column in constraint.get("column_names", []) if column is not None
        )
        if columns not in expected_unique_columns:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "UNEXPECTED_UNIQUE_CONSTRAINT",
                    f"{table_name} has an unexplained unique constraint",
                )
            )

    expected_checks = _expected_check_constraints(table)
    actual_checks = _actual_check_constraints(
        inspector, table_name, _string_column_names(table)
    )

    for name in sorted(expected_checks.keys() - actual_checks.keys()):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "MISSING_CHECK_CONSTRAINT",
                f"{table_name}.{name} check constraint is missing",
            )
        )
    for name in sorted(actual_checks.keys() - expected_checks.keys()):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "UNEXPECTED_CHECK_CONSTRAINT",
                f"{table_name}.{name} check constraint is not part of the reviewed schema",
            )
        )
    for name in sorted(expected_checks.keys() & actual_checks.keys()):
        if expected_checks[name] != actual_checks[name]:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "CHECK_CONSTRAINT_DEFINITION_MISMATCH",
                    f"{table_name}.{name} check constraint definition differs from metadata",
                )
            )

    expected_foreign_keys = _expected_foreign_keys(table)
    actual_foreign_keys = _actual_foreign_keys(inspector, table_name)

    for key in sorted(expected_foreign_keys.keys() - actual_foreign_keys.keys()):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "MISSING_FOREIGN_KEY",
                f"{table_name}.{','.join(key[1])} foreign key is missing",
            )
        )
    for key in sorted(actual_foreign_keys.keys() - expected_foreign_keys.keys()):
        findings.append(
            Finding(
                _STATUS_FAIL,
                "UNEXPECTED_FOREIGN_KEY",
                f"{table_name}.{','.join(key[1])} foreign key is not part of the reviewed schema",
            )
        )
    for key in sorted(expected_foreign_keys.keys() & actual_foreign_keys.keys()):
        if expected_foreign_keys[key] != actual_foreign_keys[key]:
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "FOREIGN_KEY_DEFINITION_MISMATCH",
                    f"{table_name}.{','.join(key[1])} foreign key definition differs from metadata",
                )
            )


def verify_schema(database_url: str) -> VerificationResult:
    """Inspect a database read-only and compare it with its declared revision."""
    engine = create_engine(database_url)
    findings: List[Finding] = []
    dialect = "unknown"
    try:
        inspector = inspect(engine)
        dialect = inspector.dialect.name
        actual_tables = set(inspector.get_table_names())

        revision, revision_findings = _read_revision_state(engine, inspector)
        findings.extend(revision_findings)
        if revision_findings:
            return VerificationResult(dialect=dialect, findings=tuple(findings))

        if revision == _PHASE3_REVISION:
            expected_tables = _PHASE0_TABLES + _PHASE1_TABLES + _PHASE2_TABLES + _PHASE3_TABLES
            mode = "revision-0004-revoked-tokens"
        elif revision == _PHASE2_REVISION:
            expected_tables = _PHASE0_TABLES + _PHASE1_TABLES + _PHASE2_TABLES
            mode = "revision-0003-mitigation-decision-audit"
        elif revision == _PHASE1_REVISION:
            expected_tables = _PHASE0_TABLES + _PHASE1_TABLES
            mode = "revision-0002-mitigation-policy"
        elif revision == _BASELINE_REVISION or revision is None:
            expected_tables = _PHASE0_TABLES
            mode = (
                "unversioned-existing-schema"
                if revision is None
                else "revision-0001-baseline"
            )
        else:
            # Unknown revision: report, but verify against all known metadata as best-effort
            expected_tables = _PHASE0_TABLES + _PHASE1_TABLES + _PHASE2_TABLES + _PHASE3_TABLES
            mode = f"unknown-revision:{revision}"
            findings.append(Finding(_STATUS_FAIL, "UNKNOWN_REVISION", f"Unsupported alembic revision: {revision}"))
        findings.append(Finding(_STATUS_INFO, "VERIFICATION_MODE", mode))

        expected_names = {table.name for table in expected_tables}
        known_tables = expected_names | KNOWN_EXTRA_TABLES

        for name in sorted(expected_names - actual_tables):
            findings.append(
                Finding(_STATUS_FAIL, "MISSING_TABLE", f"{name} is missing")
            )
        for name in sorted(actual_tables - known_tables):
            findings.append(
                Finding(
                    _STATUS_FAIL,
                    "UNEXPECTED_TABLE",
                    f"{name} is not a known application or Alembic object",
                )
            )

        for table in expected_tables:
            if table.name in actual_tables:
                _verify_table(inspector, table, findings)

        findings.append(
            Finding(
                _STATUS_INFO,
                "DATA_CHECKSUM_DEFERRED",
                "Data checksum requires a securely managed out-of-band key and is deferred",
            )
        )
        if not any(finding.status == _STATUS_FAIL for finding in findings):
            findings.append(
                Finding(
                    _STATUS_PASS,
                    "SCHEMA_MATCHES_BASELINE",
                    "Expected columns, primary keys, indexes and constraints match the baseline",
                )
            )
        return VerificationResult(dialect=dialect, findings=tuple(findings))
    except Exception as exc:  # noqa: BLE001 - never emit raw exception text or DSNs
        safe_findings = (
            Finding(
                _STATUS_FAIL,
                "DATABASE_INSPECTION_FAILED",
                f"Inspection failed ({type(exc).__name__}); no raw diagnostic was emitted",
            ),
        )
        return VerificationResult(dialect=dialect, findings=safe_findings)
    finally:
        engine.dispose()


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point. Exits 0 for PASS and 1 for FAIL."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        dest="database_url",
        default=None,
        help="Optional isolated target URL; credentials are never printed",
    )
    args = parser.parse_args(argv)

    from app.core.config import settings

    database_url = args.database_url or settings.get_database_url()
    result = verify_schema(database_url)
    print(result.render())
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
