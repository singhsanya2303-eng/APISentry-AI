
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

# Model location: API-SENTRY_MINIPROJECT/backend/models/
MODEL_PATH = (
    Path(__file__).resolve().parents[4]
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
    """Load the checkpoint and classify one feature vector."""

    if any(not math.isfinite(value) for value in request.features.values()):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All feature values must be finite numbers",
        )

    # Log the resolved path to help diagnose loading problems.
    logger.info("Loading token classifier model from: %s", MODEL_PATH)

    try:
        classifier = TokenUsageRandomForestClassifier.load(str(MODEL_PATH))

    except FileNotFoundError:
        logger.exception("Token classifier checkpoint file was not found")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Token classifier model is not available. "
                "Train and save the model first."
            ),
        )

    except Exception as exc:
        # Print the complete traceback in the backend terminal.
        logger.exception("Could not load token classifier checkpoint")

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Token classifier model could not be loaded: {exc}",
        ) from exc

    expected_names = classifier.feature_names
    provided_names = set(request.features)
    expected_set = set(expected_names)

    if provided_names != expected_set:
        missing = sorted(expected_set - provided_names)
        unexpected = sorted(provided_names - expected_set)

        logger.warning(
            "Feature mismatch. Missing=%s, unexpected=%s",
            missing,
            unexpected,
        )

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Feature names do not match the trained model.",
                "missing_features": missing,
                "unexpected_features": unexpected,
            },
        )

    ordered_values = [
        [request.features[name] for name in expected_names]
    ]

    try:
        prediction = classifier.predict(ordered_values)[0]

    except (ValueError, RuntimeError) as exc:
        logger.exception("Token classifier prediction failed")

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The supplied features could not be classified.",
        ) from exc

    return TokenClassificationResponse(**prediction)
