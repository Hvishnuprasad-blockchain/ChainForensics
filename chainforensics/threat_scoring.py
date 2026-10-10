from __future__ import annotations

import logging
from typing import Any, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from chainforensics.database.models import IncidentModel

logger = logging.getLogger("chainforensics.threat_scoring")

# Inherent Severity Weights (0-100)
INHERENT_SEVERITY_WEIGHTS: dict[str, int] = {
    "BENIGN": 5,
    "PortScan": 45,
    "BruteForce": 65,
    "DoS": 80,
    "DDoS": 85,
    "WebAttack": 85,
    "SQLInjection": 85,
    "Infiltration": 90,
    "Bot": 75,
}
DEFAULT_SEVERITY_WEIGHT = 50


def compute_threat_score(
    attack_type: str,
    confidence: float,
    prior_offenses: int = 0,
) -> tuple[int, str]:
    """
    Compute multi-factor threat score and level.

    Formula:
      ThreatScore = clamp(
        0.55 * InherentSeverity +
        0.25 * (Confidence * 100) +
        0.20 * (min(prior_offenses * 5, 25) * 4),
        0,
        100
      )

    Thresholds:
      Score < 30   -> LOW
      30 <= Score < 60 -> MEDIUM
      60 <= Score < 85 -> HIGH
      Score >= 85  -> CRITICAL
    """
    severity_weight = INHERENT_SEVERITY_WEIGHTS.get(attack_type, DEFAULT_SEVERITY_WEIGHT)
    conf_clamped = max(0.0, min(float(confidence), 1.0))
    repeat_factor = min(max(prior_offenses, 0) * 5, 25)

    raw_score = (
        (0.55 * severity_weight) +
        (0.25 * (conf_clamped * 100.0)) +
        (0.20 * (repeat_factor * 4.0))
    )
    score = int(round(max(0.0, min(raw_score, 100.0))))

    if score >= 85:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def assess_event_threat(
    event: dict[str, Any],
    db: Optional[Session] = None,
) -> tuple[int, str]:
    """
    Assess threat score and threat level for a forensic event, querying the
    database for prior offenses by the source IP if available.
    """
    attack_type = str(event.get("attack_type", "UNKNOWN"))
    confidence = float(event.get("confidence", 0.95))
    source_ip = str(event.get("source", {}).get("ip") or event.get("src_ip", ""))

    prior_offenses = 0
    if db is not None and source_ip:
        try:
            prior_offenses = (
                db.query(func.count(IncidentModel.id))
                .filter(
                    IncidentModel.source_ip == source_ip,
                    IncidentModel.attack_type != "BENIGN",
                )
                .scalar()
                or 0
            )
        except Exception as exc:
            logger.warning("Error querying prior offenses for %s: %s", source_ip, exc)
            prior_offenses = 0

    return compute_threat_score(attack_type, confidence, prior_offenses)
