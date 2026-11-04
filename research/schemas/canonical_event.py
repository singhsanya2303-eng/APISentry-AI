"""Privacy-preserving canonical event schema."""

from datetime import datetime, timezone
import re
from typing import Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_TRUST_MARKER = object()


class TrustedPrincipalId:
    """Principal pseudonym produced by the HMAC preprocessing boundary."""

    __slots__ = ("value",)

    def __init__(self, value: str, *, marker: object = None):
        if marker is not _TRUST_MARKER:
            raise TypeError("use anonymize_principal to create principal IDs")
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __len__(self) -> int:
        return len(self.value)

    def __repr__(self) -> str:
        return f"TrustedPrincipalId({self.value!r})"

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TrustedPrincipalId) and self.value == other.value


def restore_trusted_principal(value: str) -> TrustedPrincipalId:
    """Restore a previously serialized, format-validated pseudonym."""
    if not isinstance(value, str) or not re.fullmatch(
        r"principal_[0-9a-f]{64}", value
    ):
        raise ValueError("serialized principal is not a trusted pseudonym")
    return TrustedPrincipalId(value, marker=_TRUST_MARKER)


class CanonicalEvent(BaseModel):
    """One normalized API event suitable for dataset storage and splitting."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    principal_id: TrustedPrincipalId = Field(
        description="HMAC-derived principal pseudonym"
    )
    session_id: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    method: str = Field(min_length=1)
    endpoint_template: str = Field(min_length=1)
    status_code: int = Field(ge=100, le=599)
    latency_ms: float = Field(ge=0)
    request_size_bytes: int = Field(ge=0)
    response_size_bytes: int = Field(ge=0)
    client_features: Dict[str, float] = Field(default_factory=dict)
    network_features: Dict[str, float] = Field(default_factory=dict)
    label: Literal["normal", "attack"]
    attack_category: Optional[str] = None
    source_dataset: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_consistent_label_category(self) -> "CanonicalEvent":
        if self.label == "normal" and self.attack_category is not None:
            raise ValueError("normal events cannot have an attack category")
        if self.label == "attack" and self.attack_category is None:
            raise ValueError("attack events require an attack category")
        return self

    @field_validator(
        "event_id",
        "principal_id",
        "session_id",
        "campaign_id",
        "source_dataset",
        mode="before",
    )
    @classmethod
    def require_non_blank_identifier(cls, value: str) -> str:
        if isinstance(value, TrustedPrincipalId):
            return value
        if not isinstance(value, str) or not value.strip():
            raise ValueError("identifier must be a non-blank string")
        return value.strip()

    @field_validator("timestamp")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("principal_id")
    @classmethod
    def require_anonymized_principal(cls, value: str) -> str:
        if not isinstance(value, TrustedPrincipalId):
            raise ValueError("principal_id must come from anonymize_principal")
        if not re.fullmatch(r"principal_[0-9a-f]{64}", str(value)):
            raise ValueError(
                "principal_id must be an anonymized principal_<64 lowercase hex> identifier"
            )
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("method must not be empty")
        return normalized

    @field_validator("endpoint_template")
    @classmethod
    def normalize_endpoint(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/"):
            raise ValueError("endpoint_template must start with '/'")
        return normalized

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("attack_category")
    @classmethod
    def normalize_attack_category(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None
