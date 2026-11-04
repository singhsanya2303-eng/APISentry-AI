"""Procedure-level ground truth contracts for controlled BOLA experiments."""

from enum import Enum
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AccessOutcome(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"


class ControlledAccount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)


class ResourceOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(min_length=1)
    owner_account_id: str = Field(min_length=1)


class BolaGroundTruth(BaseModel):
    """Requires two distinct accounts and explicitly tracked ownership."""

    model_config = ConfigDict(extra="forbid")

    accounts: list[ControlledAccount] = Field(min_length=2)
    resources: list[ResourceOwnership] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_setup(self) -> "BolaGroundTruth":
        account_ids = {account.account_id for account in self.accounts}
        if len(account_ids) < 2:
            raise ValueError("BOLA setup requires at least two distinct accounts")
        if any(resource.owner_account_id not in account_ids for resource in self.resources):
            raise ValueError("every resource owner must be a controlled account")
        return self


class BolaAccessCheck(BaseModel):
    """Separates expected/actual access from HTTP status interpretation."""

    model_config = ConfigDict(extra="forbid")

    attacker_account_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    expected_outcome: AccessOutcome
    actual_outcome: AccessOutcome
    verification_method: str = Field(min_length=1)
    status_code: int = Field(ge=100, le=599)

    @model_validator(mode="after")
    def reject_status_only_proof(self) -> "BolaAccessCheck":
        if self.verification_method.strip().lower() in {"status", "status_code", "http_status"}:
            raise ValueError("HTTP status alone is not BOLA ground truth")
        if self.actual_outcome is AccessOutcome.UNKNOWN:
            raise ValueError("BOLA access outcome must be verified")
        return self


def verify_bola_access(
    *,
    ground_truth: BolaGroundTruth,
    attacker_account_id: str,
    resource_id: str,
    status_code: int,
    response_body: bytes | str,
    semantic_verifier: Callable[[bytes | str], AccessOutcome],
) -> BolaAccessCheck:
    """Verify cross-account access using in-memory response semantics only."""
    accounts = {account.account_id for account in ground_truth.accounts}
    if attacker_account_id not in accounts:
        raise ValueError("attacker must be a controlled account")
    resource = next(
        (item for item in ground_truth.resources if item.resource_id == resource_id),
        None,
    )
    if resource is None:
        raise ValueError("resource is not declared in ground truth")
    if resource.owner_account_id == attacker_account_id:
        raise ValueError("BOLA check requires a resource owned by another account")
    actual = semantic_verifier(response_body)
    if not isinstance(actual, AccessOutcome) or actual is AccessOutcome.UNKNOWN:
        raise ValueError("semantic verifier must return a known access outcome")
    result = BolaAccessCheck(
        attacker_account_id=attacker_account_id,
        resource_id=resource_id,
        expected_outcome=AccessOutcome.DENIED,
        actual_outcome=actual,
        verification_method="in_memory_response_semantics",
        status_code=status_code,
    )
    del response_body
    return result
