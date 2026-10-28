
"""API endpoint for saved Random Forest token-usage predictions."""

import logging
import math
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.services.token_usage_classifier_service import (
    TokenUsageRandomForestClassifier,
)

logger = logging.getLogger("apisentry.api.token_classifier")

router = APIRouter(
    prefix="/security/token-classifier",
    tags=["Token Usage Classification"],
)

# Default checkpoint: backend/models/token_usage_classifier.joblib
MODEL_PATH = (
    Path(__file__).resolve().parents[3]
    / "models"
    / "token_usage_classifier.joblib"
)


class TokenClassificationRequest(BaseModel):
    """Numeric behavioral features keyed by their trained feature names."""

    model_config = ConfigDict(extra="forbid")

    features: Dict[str, float] = Field(
        ...,
        min_length=1,
        description="Feature names and numeric values expected by the trained model",
    )


class TokenClassificationResponse(BaseModel):
    """Prediction returned by the saved Random Forest model."""

    predicted_label: str
    confidence: float = Field(ge=0.0, le=1.0)
    class_probabilities: Dict[str, float]


@router.post(
    "/predict",
    response_model=TokenClassificationResponse,
    summary="Classify token usage with a saved Random Forest model",
)
def predict_token_usage(
    request: TokenClassificationRequest,
) -> TokenClassificationResponse:
    """Load the trusted checkpoint and classify one feature vector."""
    if any(not math.isfinite(value) for value in request.features.values()):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All feature values must be finite numbers",
        )

    try:
        # Only load model files created by a trusted training process.
        classifier = TokenUsageRandomForestClassifier.load(str(MODEL_PATH))
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token classifier model is not available. Train and save the model first.",
        )
    except Exception as exc:
        logger.error("Could not load token classifier checkpoint: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token classifier model could not be loaded.",
        )

    expected_names = classifier.feature_names
    provided_names = set(request.features)
    expected_set = set(expected_names)

    if provided_names != expected_set:
        missing = sorted(expected_set - provided_names)
        unexpected = sorted(provided_names - expected_set)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Feature names do not match the trained model.",
                "missing_features": missing,
                "unexpected_features": unexpected,
            },
        )

    ordered_values = [[request.features[name] for name in expected_names]]

    try:
        prediction = classifier.predict(ordered_values)[0]
    except (ValueError, RuntimeError) as exc:
        logger.warning("Token classifier prediction rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The supplied features could not be classified.",
        )

    return TokenClassificationResponse(**prediction)
