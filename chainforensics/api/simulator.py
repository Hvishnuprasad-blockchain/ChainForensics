from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from chainforensics.api.dependencies import get_db
from chainforensics.database.repository import get_incident
from chainforensics.simulator.cicids_scenarios import get_all_scenarios, get_scenario_by_id
from chainforensics.simulator.service import (
    execute_live_cicids_attack_and_ai_recovery,
    get_sepolia_network_status,
)

logger = logging.getLogger("chainforensics.api.simulator")
router = APIRouter(prefix="/api/v2/simulator", tags=["Live Attack Simulator & AI Recovery"])


class ExecuteSimulationRequest(BaseModel):
    scenario_id: str = Field(..., description="Identifier of the CICIDS-2017 attack scenario (e.g. cicids-dos-hulk)")
    custom_intensity: Optional[int] = Field(None, description="Optional packet count override to test threshold behavior")
    commit_onchain: bool = Field(True, description="Whether to anchor the event and recovery proof directly onto Ethereum Sepolia")


@router.get("/scenarios")
def list_scenarios() -> dict[str, Any]:
    """
    Retrieve all curated attack scenarios extracted from the CICIDS-2017 dataset.
    """
    scenarios = get_all_scenarios()
    return {
        "total": len(scenarios),
        "dataset": "CICIDS-2017 Official Network Traffic Flow Dataset",
        "scenarios": scenarios,
    }


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> dict[str, Any]:
    """Retrieve detailed telemetry and metadata for a specific CICIDS-2017 scenario."""
    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return {"scenario": scenario}


@router.get("/blockchain/status")
def get_blockchain_status() -> dict[str, Any]:
    """
    Get live connection telemetry for Ethereum Sepolia testnet and the ForensicLedger contract.
    """
    return get_sepolia_network_status()


@router.post("/execute")
def execute_simulation(
    req: ExecuteSimulationRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Execute full live demo pipeline:
      1. Ingest real CICIDS-2017 dataset attack flow.
      2. Deterministic SHA-256 event canonicalization.
      3. Commit tamper-proof hash to Ethereum Sepolia blockchain (`logEvent`).
      4. Query live Groq LLM (`llama-3.1-8b-instant`) for contextual remediation playbook.
      5. Run automated multi-window recovery health tracking (`T+0s`, `T+15s`, `T+30s`).
      6. Commit verified recovery on Ethereum Sepolia (`markRecoveryVerified`).
      7. Persist forensic audit trail in database.
    """
    try:
        result = execute_live_cicids_attack_and_ai_recovery(
            db=db,
            scenario_id=req.scenario_id,
            custom_intensity=req.custom_intensity,
            commit_onchain=req.commit_onchain,
        )
        return result
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        logger.exception("Simulation execution failure: %s", exc)
        raise HTTPException(status_code=500, detail=f"Simulation error: {exc}")


@router.post("/recovery/track/{event_hash}")
def track_incident_recovery(
    event_hash: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Query or re-evaluate live automated recovery tracking for an existing incident.
    """
    incident = get_incident(db, event_hash)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident with hash {event_hash} not found.")

    return {
        "event_hash": incident.event_hash,
        "flow_id": incident.flow_id,
        "attack_type": incident.attack_type,
        "recovery_status": incident.recovery_status,
        "recovery_verified": bool(incident.recovery_verified),
        "enhanced_status": getattr(incident, "enhanced_status", "unknown"),
        "recovery_reason": incident.recovery_reason,
        "recovery_tx_hash": incident.recovery_transaction_hash,
        "recovery_etherscan_url": f"https://sepolia.etherscan.io/tx/{incident.recovery_transaction_hash}" if incident.recovery_transaction_hash else None,
        "timestamp": incident.event_timestamp,
    }
