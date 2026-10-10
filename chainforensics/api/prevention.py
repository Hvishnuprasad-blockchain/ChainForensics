from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from chainforensics.api.dependencies import get_db
from chainforensics.api.schemas import (
    PreventedAttackListResponse,
    PreventedAttackResponse,
)
from chainforensics.database.repository import (
    count_prevented_attacks,
    list_prevented_attacks,
)
from chainforensics.prevention.threat_registry import get_threat_registry

logger = logging.getLogger("chainforensics.api.prevention")
router = APIRouter(prefix="/api/v2/prevention", tags=["Proactive Prevention"])


@router.get("/attacks", response_model=PreventedAttackListResponse)
def get_prevented_attacks(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> PreventedAttackListResponse:
    """
    List proactively prevented attacks recorded by the tamper-proof threat registry.
    """
    attacks = list_prevented_attacks(db, limit=limit, offset=offset)
    total = count_prevented_attacks(db)

    items = [
        PreventedAttackResponse(
            id=a.id,
            source_ip=a.source_ip,
            destination_ip=a.destination_ip,
            destination_port=a.destination_port,
            attack_type=a.attack_type,
            prevented_at=a.prevented_at,
            origin_incident_hash=a.origin_incident_hash,
            prevention_reason=a.prevention_reason,
        )
        for a in attacks
    ]

    return PreventedAttackListResponse(
        items=items,
        total=total,
    )


@router.get("/registry")
def get_active_registry(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Get all active known malicious sources registered on the ledger.
    """
    registry = get_threat_registry()
    threats = registry.get_all_registered_threats(db=db)
    return {
        "registered_threats": threats,
        "total_active_threats": len(threats),
    }


@router.post("/sync")
def sync_registry(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Trigger manual re-sync of the known-threat registry from confirmed ledger events.
    """
    registry = get_threat_registry()
    synced = registry.sync_from_ledger(db)
    return {
        "status": "synchronized",
        "threats_loaded": synced,
    }
