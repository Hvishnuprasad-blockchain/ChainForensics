import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from chainforensics.api.dependencies import get_db, require_api_key
from chainforensics.api.schemas import (
    BaseMetricsResponse,
    IncidentListResponse,
    IncidentReplayResponse,
    IncidentResponse,
    TrafficDetectionRequest,
)
from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient
from chainforensics.database.repository import (
    count_incidents,
    create_incident,
    get_base_metrics,
    get_incident,
    list_incidents,
    update_blockchain_result,
    update_recovery_result,
)
from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)
from chainforensics.explainability.generator import generate_explanation
from chainforensics.recovery.provider import get_recovery_provider
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery
from chainforensics.recovery.enhanced_verifier import EnhancedRecoveryVerifier
from chainforensics.threat_scoring import assess_event_threat

logger = logging.getLogger("chainforensics.api.incidents")

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
    dependencies=[Depends(require_api_key)],
)


def _incident_to_response(incident) -> IncidentResponse:
    """
    Convert the SQLAlchemy Incident model into the
    public API response model.
    """

    import json

    try:
        raw_features = json.loads(
            incident.raw_features_json
        )
    except (TypeError, json.JSONDecodeError):
        raw_features = {}

    return IncidentResponse(
        id=incident.id,
        flow_id=incident.flow_id,
        timestamp=incident.event_timestamp,

        source_ip=incident.source_ip,
        source_port=incident.source_port,

        destination_ip=incident.destination_ip,
        destination_port=incident.destination_port,

        attack_type=incident.attack_type,
        confidence=incident.confidence,

        raw_features=raw_features,

        event_hash=incident.event_hash,

        detection_status=incident.detection_status,

        event_transaction_hash=(
            incident.event_transaction_hash
        ),
        event_block_number=(
            incident.event_block_number
        ),
        ledger_write_latency_seconds=(
            incident.ledger_write_latency_seconds
        ),

        recovery_status=(
            incident.recovery_status
        ),
        recovery_reason=(
            incident.recovery_reason
        ),
        recovery_entry_index=(
            incident.recovery_entry_index
        ),
        recovery_transaction_hash=(
            incident.recovery_transaction_hash
        ),
        recovery_verified=bool(
            incident.recovery_verified
        ),
        threat_level=getattr(incident, 'threat_level', None),
        threat_score=getattr(incident, 'threat_score', None),
        recovery_provider=getattr(incident, 'recovery_provider', None),
        enhanced_status=getattr(incident, 'enhanced_status', None),
    )


@router.get(
    "",
    response_model=IncidentListResponse,
)
def get_incidents(
    attack_type: str | None = Query(
        default=None,
    ),
    detection_status: str | None = Query(
        default=None,
    ),
    recovery_status: str | None = Query(
        default=None,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    """
    Return persisted forensic incidents.

    Optional filters:
        attack_type
        detection_status
        recovery_status
    """

    incidents = list_incidents(
        db,
        attack_type=attack_type,
        detection_status=detection_status,
        recovery_status=recovery_status,
        limit=limit,
        offset=offset,
    )

    return IncidentListResponse(
        items=[
            _incident_to_response(incident)
            for incident in incidents
        ],
        total=count_incidents(db),
    )


@router.get(
    "/metrics/base",
    response_model=BaseMetricsResponse,
)
def get_base_metrics_endpoint(
    db: Session = Depends(get_db),
) -> BaseMetricsResponse:
    """
    Return BASE framework metrics calculated from persisted incident history.
    """
    return BaseMetricsResponse(**get_base_metrics(db))


def process_traffic_detection(
    req: TrafficDetectionRequest,
    db: Session,
) -> IncidentReplayResponse:
    """
    Execute full pipeline for incoming traffic:
      canonicalize & hash -> explain -> recover -> commit on-chain -> persist in DB.
    """
    event = build_forensic_event(
        flow_id=req.flow_id,
        timestamp=req.timestamp,
        src_ip=req.source.ip,
        src_port=req.source.port,
        dst_ip=req.destination.ip,
        dst_port=req.destination.port,
        attack_type=req.attack_type,
        confidence=req.confidence,
        raw_features=req.raw_features,
    )
    event_hash = hash_forensic_event(event)

    existing = get_incident(db, event_hash)
    if existing is not None:
        return IncidentReplayResponse(incident=_incident_to_response(existing))

    explanation = get_recovery_provider().get_recommendation(event)
    recovery_res = simulate_recovery(event)

    tx_hash = None
    block_num = None
    latency = None
    rec_tx_hash = None
    rec_index = None
    is_verified = False
    enhanced_status = "fully_recovered" if recovery_res.status == "verified" else "escalated"

    rpc_url = os.environ.get("CHAINFORENSIS_RPC_URL")
    pk = os.environ.get("CHAINFORENSIS_PRIVATE_KEY")
    contract_addr = os.environ.get("CHAINFORENSIS_CONTRACT_ADDRESS")
    if rpc_url and pk and contract_addr:
        try:
            client = BlockchainClient(
                rpc_url=rpc_url,
                private_key=pk,
                contract_address=contract_addr,
                contract_abi=load_forensic_ledger_abi(),
                max_retries=1,
                base_delay_seconds=0.1,
            )
            write_res = client.log_event(event_hash, event_context=req.flow_id)
            tx_hash = write_res.tx_hash
            block_num = write_res.block_number
            latency = write_res.latency_seconds

            event_with_hash = dict(event)
            event_with_hash["_event_hash"] = event_hash
            enhanced_verifier = EnhancedRecoveryVerifier()
            enh_res = enhanced_verifier.verify(
                event=event_with_hash,
                simulation_result=recovery_res,
                client=client,
            )
            enhanced_status = enh_res.status
            is_verified = (enh_res.status == "fully_recovered")
            v1_ver = enh_res.v1_verification
            rec_index = v1_ver.get("entry_index")
            rec_tx_obj = v1_ver.get("transaction")
            rec_tx_hash = rec_tx_obj.tx_hash if rec_tx_obj else None
        except Exception as exc:
            logger.warning("Blockchain commitment omitted/failed during detection: %s", exc)
            enhanced_status = "fully_recovered" if recovery_res.status == "verified" else "escalated"

    # v2 Feature 3: Compute multi-factor threat score
    t_score, t_level = assess_event_threat(event, db=db)
    rec_provider = explanation.get("recovery_provider", "rule_based") if isinstance(explanation, dict) else "rule_based"

    incident = create_incident(
        db,
        event=event,
        event_hash=event_hash,
        detection_status="detected",
        explanation=explanation,
        threat_level=t_level,
        threat_score=t_score,
        recovery_provider=rec_provider,
    )
    if tx_hash is not None:
        update_blockchain_result(
            db,
            event_hash=event_hash,
            transaction_hash=tx_hash,
            block_number=block_num,
            latency_seconds=latency,
        )
    update_recovery_result(
        db,
        event_hash=event_hash,
        recovery_status=recovery_res.status,
        recovery_reason=recovery_res.reason,
        recovery_entry_index=rec_index,
        recovery_transaction_hash=rec_tx_hash,
        recovery_verified=is_verified,
        enhanced_status=enhanced_status,
    )
    db.refresh(incident)
    return IncidentReplayResponse(incident=_incident_to_response(incident))


@router.post(
    "/detect",
    response_model=IncidentReplayResponse,
    status_code=status.HTTP_201_CREATED,
)
def detect_incident(
    req: TrafficDetectionRequest,
    db: Session = Depends(get_db),
) -> IncidentReplayResponse:
    """
    Submit network traffic for real-time forensic detection and persistence.
    """
    return process_traffic_detection(req, db)


@router.get(
    "/{event_hash}",
    response_model=IncidentReplayResponse,
)
def get_incident_by_hash(
    event_hash: str,
    db: Session = Depends(get_db),
) -> IncidentReplayResponse:
    """
    Retrieve one complete persisted forensic incident.
    """

    incident = get_incident(
        db,
        event_hash,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return IncidentReplayResponse(
        incident=_incident_to_response(
            incident
        )
    )