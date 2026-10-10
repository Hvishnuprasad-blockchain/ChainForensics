from __future__ import annotations

from chainforensics.database.database import (
    Base,
    SessionLocal,
    engine,
)
from chainforensics.database.repository import (
    count_incidents,
    create_incident,
    get_base_metrics,
    get_incident,
    list_incidents,
    update_blockchain_result,
    update_recovery_result,
)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def test_real_incident_persistence() -> None:
    db = SessionLocal()

    try:
        event = {
            "flow_id": "SPRINT5-DB-TEST-001",
            "timestamp": "2026-09-29T12:00:00Z",
            "source": {
                "ip": "192.168.10.10",
                "port": 40010,
            },
            "destination": {
                "ip": "10.0.0.25",
                "port": 443,
            },
            "attack_type": "PortScan",
            "confidence": 0.95,
            "raw_features": {
                "packet_count": 100,
                "flow_duration": 2.41,
                "destination_port": 443,
            },
        }

        event_hash = "a" * 64

        # --------------------------------------------------------
        # Remove the previous test record if it already exists.
        # This makes the test safe to run repeatedly.
        # --------------------------------------------------------

        existing = get_incident(
            db,
            event_hash,
        )

        if existing is not None:
            db.delete(existing)
            db.commit()

        # --------------------------------------------------------
        # Create incident
        # --------------------------------------------------------

        incident = create_incident(
            db,
            event=event,
            event_hash=event_hash,
        )

        assert incident.id is not None
        assert incident.flow_id == "SPRINT5-DB-TEST-001"
        assert incident.attack_type == "PortScan"
        assert incident.confidence == 0.95

        # --------------------------------------------------------
        # Store blockchain result
        # --------------------------------------------------------

        update_blockchain_result(
            db,
            event_hash=event_hash,
            transaction_hash="0x" + ("1" * 64),
            block_number=123,
            latency_seconds=0.0484,
        )

        # --------------------------------------------------------
        # Store recovery result
        # --------------------------------------------------------

        update_recovery_result(
            db,
            event_hash=event_hash,
            recovery_status="verified",
            recovery_reason="Deterministic recovery succeeded.",
            recovery_entry_index=7,
            recovery_transaction_hash="0x" + ("2" * 64),
            recovery_verified=True,
        )

        # --------------------------------------------------------
        # Read incident back from SQLite
        # --------------------------------------------------------

        stored = get_incident(
            db,
            event_hash,
        )

        assert stored is not None

        assert stored.event_hash == event_hash

        assert stored.event_transaction_hash == (
            "0x" + ("1" * 64)
        )

        assert stored.event_block_number == 123

        assert stored.ledger_write_latency_seconds == 0.0484

        assert stored.recovery_status == "verified"

        assert stored.recovery_entry_index == 7

        assert stored.recovery_transaction_hash == (
            "0x" + ("2" * 64)
        )

        assert stored.recovery_verified is True

    finally:
        db.close()


def test_incident_filtering() -> None:
    db = SessionLocal()

    try:
        results = list_incidents(
            db,
            attack_type="PortScan",
        )

        assert len(results) >= 1

        assert all(
            incident.attack_type == "PortScan"
            for incident in results
        )

    finally:
        db.close()


def test_missing_incident_returns_none() -> None:
    db = SessionLocal()

    try:
        result = get_incident(
            db,
            "f" * 64,
        )

        assert result is None

    finally:
        db.close()


def test_count_incidents() -> None:
    db = SessionLocal()

    try:
        count = count_incidents(db)

        assert count >= 1

    finally:
        db.close()


def test_get_base_metrics() -> None:
    db = SessionLocal()

    try:
        metrics = get_base_metrics(db)

        assert isinstance(metrics, dict)
        assert "total_detected" in metrics
        assert "forensic_completeness_percent" in metrics
        assert "recovery_verification_rate_percent" in metrics
        assert "end_to_end_closed_loop_rate_percent" in metrics
        assert metrics["total_detected"] >= 1

    finally:
        db.close()
