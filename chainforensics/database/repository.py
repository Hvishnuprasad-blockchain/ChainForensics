from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from chainforensics.database.models import Incident, PreventedAttack


def create_incident(
    db: Session,
    *,
    event: dict[str, Any],
    event_hash: str,
    detection_status: str = "detected",
    explanation: dict[str, Any] | None = None,
    threat_level: str | None = None,
    threat_score: int | None = None,
    recovery_provider: str | None = None,
) -> Incident:
    """
    Create and persist the initial forensic incident.

    This stores the complete off-chain forensic event.
    """

    incident = Incident(
        flow_id=str(event["flow_id"]),
        event_timestamp=str(event["timestamp"]),

        source_ip=str(event["source"]["ip"]),
        source_port=int(event["source"]["port"]),

        destination_ip=str(event["destination"]["ip"]),
        destination_port=int(event["destination"]["port"]),

        attack_type=str(event["attack_type"]),
        confidence=float(event["confidence"]),

        raw_features_json=json.dumps(
            event.get("raw_features", {}),
            sort_keys=True,
            separators=(",", ":"),
        ),

        detection_status=detection_status,

        explanation_json=(
            json.dumps(
                explanation,
                sort_keys=True,
                separators=(",", ":"),
            )
            if explanation is not None
            else None
        ),

        event_hash=str(event_hash).lower(),

        recovery_status="pending",
        recovery_verified=False,

        threat_level=threat_level,
        threat_score=threat_score,
        recovery_provider=recovery_provider,
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def update_blockchain_result(
    db: Session,
    *,
    event_hash: str,
    transaction_hash: str | None,
    block_number: int | None,
    latency_seconds: float | None,
) -> Incident:
    """
    Store the real Sprint 2 blockchain write result.
    """

    incident = get_incident(db, event_hash)

    if incident is None:
        raise ValueError(
            f"Incident not found: {event_hash}"
        )

    incident.event_transaction_hash = (
        str(transaction_hash).lower()
        if transaction_hash is not None
        else None
    )

    incident.event_block_number = (
        int(block_number)
        if block_number is not None
        else None
    )

    incident.ledger_write_latency_seconds = (
        float(latency_seconds)
        if latency_seconds is not None
        else None
    )

    db.commit()
    db.refresh(incident)

    return incident


def update_recovery_result(
    db: Session,
    *,
    event_hash: str,
    recovery_status: str,
    recovery_reason: str | None = None,
    recovery_entry_index: int | None = None,
    recovery_transaction_hash: str | None = None,
    recovery_verified: bool = False,
    enhanced_status: str | None = None,
) -> Incident:
    """
    Store the Sprint 4 recovery result and optional v2 enhanced verification status.

    Escalated incidents can be stored without a recovery
    transaction or blockchain recovery write.
    """

    incident = get_incident(db, event_hash)

    if incident is None:
        raise ValueError(
            f"Incident not found: {event_hash}"
        )

    incident.recovery_status = str(recovery_status)

    incident.recovery_reason = (
        str(recovery_reason)
        if recovery_reason is not None
        else None
    )

    incident.recovery_entry_index = (
        int(recovery_entry_index)
        if recovery_entry_index is not None
        else None
    )

    incident.recovery_transaction_hash = (
        str(recovery_transaction_hash).lower()
        if recovery_transaction_hash is not None
        else None
    )

    incident.recovery_verified = bool(
        recovery_verified
    )

    if enhanced_status is not None:
        incident.enhanced_status = str(enhanced_status)

    db.commit()
    db.refresh(incident)

    return incident


def get_incident(
    db: Session,
    event_hash: str,
) -> Incident | None:
    """
    Retrieve one incident by its SHA-256 event hash.
    """

    statement = select(Incident).where(
        Incident.event_hash == str(event_hash).lower()
    )

    return db.scalar(statement)


def list_incidents(
    db: Session,
    *,
    attack_type: str | None = None,
    detection_status: str | None = None,
    recovery_status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Incident]:
    """
    Query incidents with optional filters.
    """

    statement = select(Incident)

    if attack_type is not None:
        statement = statement.where(
            Incident.attack_type == attack_type
        )

    if detection_status is not None:
        statement = statement.where(
            Incident.detection_status == detection_status
        )

    if recovery_status is not None:
        statement = statement.where(
            Incident.recovery_status == recovery_status
        )

    statement = (
        statement
        .order_by(Incident.id.desc())
        .offset(offset)
        .limit(limit)
    )

    return list(db.scalars(statement).all())


def count_incidents(db: Session) -> int:
    """
    Return the total number of persisted incidents.
    """

    from sqlalchemy import func

    statement = select(
        func.count(Incident.id)
    )

    return int(db.scalar(statement) or 0)


def get_base_metrics(db: Session) -> dict[str, Any]:
    """
    Calculate BASE framework metrics from persisted incident history.
    """
    from sqlalchemy import func

    total = count_incidents(db)
    if total == 0:
        return {
            "total_detected": 0,
            "ledger_write_latency_avg_seconds": None,
            "ledger_write_latency_min_seconds": None,
            "ledger_write_latency_max_seconds": None,
            "forensic_completeness_percent": 0.0,
            "recovery_verification_rate_percent": 0.0,
            "end_to_end_closed_loop_rate_percent": 0.0,
        }

    latencies = [
        val for val in db.scalars(
            select(Incident.ledger_write_latency_seconds).where(
                Incident.ledger_write_latency_seconds.is_not(None)
            )
        ).all()
        if val is not None
    ]

    avg_lat = sum(latencies) / len(latencies) if latencies else None
    min_lat = min(latencies) if latencies else None
    max_lat = max(latencies) if latencies else None

    logged_on_chain = db.scalar(
        select(func.count(Incident.id)).where(
            Incident.event_transaction_hash.is_not(None)
        )
    ) or 0

    verified_recovery = db.scalar(
        select(func.count(Incident.id)).where(
            Incident.recovery_verified.is_(True)
        )
    ) or 0

    closed_loop = db.scalar(
        select(func.count(Incident.id)).where(
            Incident.event_transaction_hash.is_not(None),
            Incident.recovery_status.in_(["verified", "escalated"]),
        )
    ) or 0

    return {
        "total_detected": total,
        "ledger_write_latency_avg_seconds": round(avg_lat, 4) if avg_lat is not None else None,
        "ledger_write_latency_min_seconds": round(min_lat, 4) if min_lat is not None else None,
        "ledger_write_latency_max_seconds": round(max_lat, 4) if max_lat is not None else None,
        "forensic_completeness_percent": round((logged_on_chain / total) * 100.0, 2),
        "recovery_verification_rate_percent": round((verified_recovery / total) * 100.0, 2),
        "end_to_end_closed_loop_rate_percent": round((closed_loop / total) * 100.0, 2),
    }


def create_prevented_attack(
    db: Session,
    *,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    attack_type: str,
    prevented_at: str,
    origin_incident_hash: str | None = None,
    prevention_reason: str = "Pre-emptively blocked: Known malicious source in verified on-chain threat registry",
) -> PreventedAttack:
    """
    v2 Feature 5: Record a proactively blocked attack attempt.
    """
    record = PreventedAttack(
        source_ip=str(source_ip),
        destination_ip=str(destination_ip),
        destination_port=int(destination_port),
        attack_type=str(attack_type),
        prevented_at=str(prevented_at),
        origin_incident_hash=str(origin_incident_hash).lower() if origin_incident_hash else None,
        prevention_reason=str(prevention_reason),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_prevented_attacks(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> list[PreventedAttack]:
    """
    List proactively prevented attacks in reverse chronological order.
    """
    statement = (
        select(PreventedAttack)
        .order_by(PreventedAttack.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.scalars(statement).all())


def count_prevented_attacks(db: Session) -> int:
    """
    Count total number of proactively blocked attacks.
    """
    from sqlalchemy import func
    statement = select(func.count(PreventedAttack.id))
    return int(db.scalar(statement) or 0)