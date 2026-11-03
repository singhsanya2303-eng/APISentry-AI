
"""API endpoint for comparing clustering-based anomaly detectors."""

from typing import Any, Dict, List

import numpy as np
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.clustering_comparison_service import (
    compare_clustering_detectors,
)

router = APIRouter(
    prefix="/security/clustering",
    tags=["Clustering Anomaly Analysis"],
)


class ClusteringAnalysisRequest(BaseModel):
    feature_vectors: List[List[float]] = Field(
        ...,
        min_length=3,
        description="Rows of numerical feature vectors with equal dimensions.",
    )
    contamination: float = Field(default=0.1, gt=0, lt=0.5)
    random_state: int = 42


@router.post("/analyze")
def analyze_clustering(
    request: ClusteringAnalysisRequest,
) -> Dict[str, Any]:
    """Compare K-Means distance and LOF anomaly predictions."""
    dimensions = {
        len(row) for row in request.feature_vectors
    }

    if not dimensions or 0 in dimensions or len(dimensions) != 1:
        raise HTTPException(
            status_code=422,
            detail="feature_vectors must have equal, non-zero dimensions.",
        )

    try:
        matrix = np.asarray(request.feature_vectors, dtype=np.float64)

        if not np.isfinite(matrix).all():
            raise ValueError(
                "feature_vectors must contain only finite values"
            )

        return compare_clustering_detectors(
            feature_vectors=matrix,
            contamination=request.contamination,
            random_state=request.random_state,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
