"""Protected advisory API for the isolated HTTP payload classifier.

Endpoints:
    POST /api/v1/security/payload-classifier/predict
    GET  /api/v1/security/payload-classifier/metadata

The router itself performs no detection, no enforcement, no bot/mitigation
integration, and no persistence. Payloads are only ever taken from the explicit
JSON request body supplied by an authorized caller; incoming headers, cookies,
query parameters, bodies of other requests, and application logs are never
inspected automatically.

All validation failures are normalized to one generic 422 detail. FastAPI's
default validation error format is deliberately bypassed by parsing the body in
the handler, so submitted payload values and raw Pydantic error objects can
never be reflected to callers.
"""

from __future__ import annotations

import json
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.http_payload_classifier import (
    FEATURE_MODE_TEXT,
    HttpPayloadClassifierRequest,
    HttpPayloadClassifierResponse,
)
from app.services.http_payload_classifier_service import (
    ARTIFACT_SHA256,
    LIMITATIONS,
    HttpPayloadClassifierInputError,
    HttpPayloadClassifierUnavailableError,
    predict_payloads,
)

logger = logging.getLogger("apisentry.api.http_payload_classifier")

router = APIRouter(
    prefix="/security/payload-classifier",
    tags=["HTTP Payload Classification (Research Only)"],
)

_INVALID_REQUEST_DETAIL = "Invalid request."
_UNAVAILABLE_DETAIL = "Payload classifier model is not available."
_INTERNAL_ERROR_DETAIL = "Internal server error."

# Safe, static identification from the frozen artifact metadata. These values
# contain no filesystem paths, credentials, or environment details.
_MODEL_NAME = "tfidf_char_svm"
_DATASET_NAME = "HttpParamsDataset (binary HTTP parameter-value corpus)"
_DATASET_SHA256 = "b67bbb66ac3e280584741c3ad234eb0c0f5ef6bd57017031afb295c7651fb7de"


class HttpPayloadClassifierMetadataResponse(BaseModel):
    """Non-sensitive model identification and documented limitations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str = Field(description="Name of the frozen selected model.")
    feature_mode: Literal["text"] = Field(description="Text-only TF-IDF features.")
    artifact_sha256: str = Field(description="SHA-256 of the verified model bundle.")
    dataset: str = Field(description="Dataset name only; no local path is exposed.")
    dataset_sha256: str = Field(description="SHA-256 digest identifying the source dataset.")
    advisory_only: Literal[True] = Field(
        default=True,
        description="Always true; no enforcement action is taken.",
    )
    limitations: list[str] = Field(description="Known model limitations and caveats.")


def _parse_request(raw_body: bytes) -> HttpPayloadClassifierRequest:
    """Parse and validate the caller's explicit body without echoing it."""
    try:
        document = json.loads(raw_body.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("request body must be a JSON object")
        return HttpPayloadClassifierRequest.model_validate(document)
    except Exception:
        # Never log the body or chain the exception into the response.
        logger.warning("Rejected malformed payload classifier request")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_INVALID_REQUEST_DETAIL,
        ) from None


@router.post(
    "/predict",
    response_model=HttpPayloadClassifierResponse,
    summary="Classify HTTP parameter values (advisory research output only)",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": HttpPayloadClassifierRequest.model_json_schema(),
                }
            },
        }
    },
)
async def predict_payload_classifier(request: Request) -> HttpPayloadClassifierResponse:
    """Return one independent advisory prediction per submitted value."""
    classified_request = _parse_request(await request.body())

    try:
        return predict_payloads(
            classified_request.payloads,
            include_payload_echo=classified_request.include_payload_echo,
        )
    except HttpPayloadClassifierInputError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_INVALID_REQUEST_DETAIL,
        ) from None
    except HttpPayloadClassifierUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_UNAVAILABLE_DETAIL,
        ) from None
    except Exception:
        logger.warning("Unexpected payload classifier failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_ERROR_DETAIL,
        ) from None


@router.get(
    "/metadata",
    response_model=HttpPayloadClassifierMetadataResponse,
    summary="Return safe metadata for the frozen payload classifier",
)
def payload_classifier_metadata() -> HttpPayloadClassifierMetadataResponse:
    """Expose static, non-sensitive model identification and limitations."""
    return HttpPayloadClassifierMetadataResponse(
        model_name=_MODEL_NAME,
        feature_mode=FEATURE_MODE_TEXT,
        artifact_sha256=ARTIFACT_SHA256,
        dataset=_DATASET_NAME,
        dataset_sha256=_DATASET_SHA256,
        advisory_only=True,
        limitations=list(LIMITATIONS),
    )


__all__ = ["router", "HttpPayloadClassifierMetadataResponse"]
