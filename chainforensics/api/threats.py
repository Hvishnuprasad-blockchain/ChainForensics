from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from chainforensics.api.dependencies import get_db
from chainforensics.api.schemas import ThreatDistributionResponse
from chainforensics.database.models import Incident
from chainforensics.threat_scoring import compute_threat_score

logger = logging.getLogger("chainforensics.api.threats")
router = APIRouter(prefix="/api/v2/threats", tags=["Threat Scoring"])


@router.get("/distribution", response_model=ThreatDistributionResponse)
def get_threat_distribution(db: Session = Depends(get_db)) -> ThreatDistributionResponse:
    """
    Compute threat score distribution across all persisted incident records in the database.
    Combines attack vector severity, confidence, and observed frequency.
    """
    incidents = db.query(Incident).all()
    distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    scores: list[int] = []

    # Count prior frequencies by source IP
    source_counts: dict[str, int] = {}
    for inc in incidents:
        if inc.attack_type != "BENIGN":
            source_counts[inc.source_ip] = source_counts.get(inc.source_ip, 0) + 1

    for inc in incidents:
        priors = max(source_counts.get(inc.source_ip, 1) - 1, 0)
        score, level = compute_threat_score(
            attack_type=inc.attack_type,
            confidence=inc.confidence,
            prior_offenses=priors,
        )
        distribution[level] = distribution.get(level, 0) + 1
        scores.append(score)

    total = len(incidents)
    mean_score = round(sum(scores) / total, 2) if total > 0 else 0.0

    return ThreatDistributionResponse(
        distribution=distribution,
        total_evaluated=total,
        mean_threat_score=mean_score,
    )
