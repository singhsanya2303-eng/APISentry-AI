"""Shared validation and safe diagnostics for Stage 2C Phase 3 persistence.

This module contains no persistence logic and no enforcement behaviour. It provides
explicit exception types, heuristic privacy validators, and safe transaction setup
helpers so persistence services can reject raw privacy data before touching a
database without echoing submitted values in messages or logs.

Privacy validation is deliberately heuristic. It cannot guarantee that arbitrary
free text contains no sensitive information; callers must still supply only
pre-redacted, opaque values.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any, Type

from sqlalchemy.orm import Session

logger = logging.getLogger("apisentry.persistence.mitigation.common")

_SENSITIVE_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "authorization_header",
        "bearer",
        "body",
        "client_address",
        "client_ip",
        "cookie",
        "credential",
        "credentials",
        "email",
        "forwarded_for",
        "http_user_agent",
        "ip",
        "ip_address",
        "ip_addr",
        "passwd",
        "password",
        "password_hash",
        "payload",
        "query",
        "query_params",
        "query_string",
        "query_values",
        "raw_body",
        "raw_ip",
        "raw_payload",
        "raw_query",
        "raw_request_id",
        "remote_addr",
        "remote_ip",
        "request_body",
        "request_id",
        "request_uri",
        "secret",
        "session_id",
        "token",
        "user_agent",
        "user_id",
        "username",
        "x_api_key",
        "x_client_ip",
        "x_forwarded_for",
        "x_real_ip",
    }
)

_NORMALIZE_KEY_RE = re.compile(r"[^a-z0-9]+")
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_TOKEN_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|x[_-]?api[_-]?key|token|credential|password|passwd|"
    r"authorization(?:_header)?|cookie|user[_-]?agent|user[_-]?id|username|email|"
    r"ip|client[_-]?ip|client[_-]?address|remote[_-]?addr|remote[_-]?ip|"
    r"x[_-]?forwarded[_-]?for|query|query_string|payload|secret)\b"
    r"\s*[:=]\s*\S+",
    re.I,
)
_EMBEDDED_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)


class MitigationPersistenceError(RuntimeError):
    """Base class for explicit Stage 2C persistence failures."""


class PrivacySensitiveDataError(MitigationPersistenceError):
    """A caller supplied raw identity, traffic, or credential material."""


class PolicyLoadError(MitigationPersistenceError):
    """Base class for active-policy loading failures."""


class ActivePolicyNotFoundError(PolicyLoadError):
    """No usable active policy marker or referenced policy exists."""


class PolicyConfigurationError(PolicyLoadError):
    """Stored policy configuration failed Stage 2B schema validation."""


class PolicyVersionMismatchError(PolicyLoadError):
    """A caller-expected policy version did not match the stored version."""


class DecisionValidationError(MitigationPersistenceError):
    """An evaluated decision cannot be safely persisted."""


class DecisionPolicyNotFoundError(DecisionValidationError):
    """The decision's policy version is not present in the database."""


class DecisionPersistenceError(MitigationPersistenceError):
    """A database failure occurred while persisting a decision."""


class DuplicateDecisionConflictError(DecisionPersistenceError):
    """An opaque decision UUID was already used by a different dedupe key."""


class AuditEventValidationError(MitigationPersistenceError):
    """An audit event cannot be safely persisted."""


class AuditEventPersistenceError(MitigationPersistenceError):
    """A database failure occurred while persisting an audit event."""


def _normalized_key(key: object) -> str:
    if not isinstance(key, str):
        return ""
    # Split camelCase before lowercasing so aliases such as ``userId`` normalize
    # to ``user_id`` instead of the ambiguous ``userid``.
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key.strip())
    return _NORMALIZE_KEY_RE.sub("_", camel_split.lower()).strip("_")


def _contains_sensitive_key(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if _normalized_key(key) in _SENSITIVE_FIELD_NAMES:
                return True
            if _contains_sensitive_key(nested, depth=depth + 1):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_sensitive_key(item, depth=depth + 1) for item in value)
    return False


def reject_sensitive_fields(value: Any, *, context: str) -> None:
    """Reject mappings that contain raw privacy field names.

    Only field names are inspected. No submitted value is included in the error
    message.
    """
    if _contains_sensitive_key(value):
        raise PrivacySensitiveDataError(
            f"{context} contains a raw privacy-sensitive field"
        )


def reject_raw_privacy_text(
    text: Any,
    *,
    field_name: str,
    error_type: Type[MitigationPersistenceError] = MitigationPersistenceError,
) -> None:
    """Reject obvious raw identifiers in free-form text.

    This is deliberately conservative: it catches common raw IP/email/credential
    forms without attempting to infer identity from arbitrary prose.
    """
    if text is None:
        return
    if not isinstance(text, str):
        raise error_type(f"{field_name} must be text")
    if _EMAIL_RE.search(text) or _ASSIGNMENT_SECRET_RE.search(text):
        raise error_type(f"{field_name} contains raw privacy-sensitive text")
    for candidate in _IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        raise error_type(f"{field_name} contains raw privacy-sensitive text")
    if _IPV6_TOKEN_RE.search(text):
        raise error_type(f"{field_name} contains raw privacy-sensitive text")
    # Accept lowercase UUID5 opaque identifiers anywhere in the text. Reject
    # uppercase or non-UUID5 UUIDs, which are treated as raw identifiers.
    for match in _EMBEDDED_UUID_RE.finditer(text):
        candidate = match.group(0)
        if candidate != candidate.lower() or candidate[14] != "5" or candidate[19] not in "89ab":
            raise error_type(f"{field_name} contains a raw non-opaque identifier")


def ensure_outer_transaction(db: Session) -> None:
    """Ensure a driver-level outer transaction exists before using savepoints.

    SQLite treats ``SAVEPOINT`` as a transaction by itself when no driver-level
    ``BEGIN`` has been issued; releasing that outermost savepoint commits. Calling
    this before any query prevents a Phase 3 service from implicitly committing
    the caller's work on SQLite. PostgreSQL uses SQLAlchemy's normal transaction
    and savepoint semantics and needs no driver-level intervention here.
    """
    connection = db.connection()
    if connection.dialect.name != "sqlite":
        return
    dbapi_connection = connection.connection.dbapi_connection
    if not getattr(dbapi_connection, "in_transaction", False):
        connection.exec_driver_sql("BEGIN")


def safe_database_error(operation: str, exc: BaseException) -> MitigationPersistenceError:
    """Build a persistence error that exposes only the exception class name."""
    return MitigationPersistenceError(
        f"{operation} failed ({type(exc).__name__})"
    )


def ensure_outer_transaction_safely(
    db: Session,
    *,
    error_type: Type[MitigationPersistenceError],
    operation: str,
) -> None:
    """Call :func:`ensure_outer_transaction` with safe diagnostics.

    Raw SQLAlchemy exception text, bound parameters, and SQL are never logged or
    included in the raised error. Only the exception class name is retained.
    """
    try:
        ensure_outer_transaction(db)
    except MitigationPersistenceError:
        raise
    except Exception as exc:
        safe = safe_database_error(operation, exc)
        logger.error("%s", safe)
        raise error_type(str(safe)) from None
