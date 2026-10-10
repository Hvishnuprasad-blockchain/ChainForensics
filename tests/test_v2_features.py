from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from chainforensics.database.database import Base
from chainforensics.database.models import Incident, PreventedAttack
from chainforensics.database.repository import (
    create_incident,
    create_prevented_attack,
    get_incident,
    list_incidents,
    list_prevented_attacks,
    update_recovery_result,
)
from chainforensics.threat_scoring import (
    assess_event_threat,
    compute_threat_score,
)
from chainforensics.recovery.simulator import RecoverySimulationResult, simulate_recovery
from chainforensics.recovery.verifier import verify_recovery
from chainforensics.recovery.enhanced_verifier import (
    EnhancedRecoveryVerifier,
    EnhancedVerificationResult,
)
from chainforensics.prevention.threat_registry import (
    ThreatRecord,
    ThreatRegistryService,
)


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()


# ============================================================================
# FEATURE 3 TESTS: Multi-Factor Threat Scoring System
# ============================================================================

def test_compute_threat_score_levels():
    # Low threat
    score_low, level_low = compute_threat_score("BENIGN", 0.99, prior_offenses=0)
    assert level_low == "LOW"
    assert score_low < 30

    # Medium threat (e.g. PortScan low repeat)
    score_med, level_med = compute_threat_score("PortScan", 0.85, prior_offenses=0)
    assert level_med in ["LOW", "MEDIUM"]

    # High threat (e.g. DoS with repeat offenses)
    score_high, level_high = compute_threat_score("DoS", 0.95, prior_offenses=2)
    assert level_high in ["HIGH", "CRITICAL"]
    assert score_high >= 60

    # Critical threat (e.g. Infiltration or DDoS with heavy prior history)
    score_crit, level_crit = compute_threat_score("Infiltration", 0.99, prior_offenses=5)
    assert level_crit == "CRITICAL"
    assert score_crit >= 85


def test_assess_event_threat_with_db_history(in_memory_db):
    source_ip = "192.168.1.100"

    # Seed 2 prior malicious incidents for this IP
    for i in range(2):
        inc = Incident(
            flow_id=f"flow-prior-{i}",
            event_timestamp="2026-10-03T10:00:00Z",
            source_ip=source_ip,
            source_port=50000 + i,
            destination_ip="10.0.0.1",
            destination_port=80,
            attack_type="DoS",
            confidence=0.98,
            raw_features_json="{}",
            event_hash=f"{i:064x}",
            detection_status="detected",
        )
        in_memory_db.add(inc)
    in_memory_db.commit()

    event = {
        "flow_id": "flow-current",
        "attack_type": "DoS",
        "confidence": 0.98,
        "source": {"ip": source_ip, "port": 50005},
        "destination": {"ip": "10.0.0.1", "port": 80},
    }

    score, level = assess_event_threat(event, db=in_memory_db)
    assert level in ["HIGH", "CRITICAL"]
    assert score >= 70


# ============================================================================
# FEATURE 4 TESTS: Enhanced Multi-Check Recovery Verification
# ============================================================================

def test_enhanced_recovery_fully_recovered_with_onchain_write():
    verifier = EnhancedRecoveryVerifier(check_offsets=(0, 30, 60))

    event = {
        "flow_id": "flow-clean-portscan",
        "attack_type": "PortScan",
        "confidence": 0.95,
        "raw_features": {"packet_count": 80},  # Well below 200 * 0.70 = 140
        "_event_hash": "a" * 64,
    }

    mock_client = MagicMock()
    mock_client.get_entry_count.return_value = 1
    mock_client.get_entry.return_value = {"event_hash": "a" * 64}
    mock_client.mark_recovery_verified.return_value = MagicMock(
        tx_hash="0xabcdef1234567890",
        block_number=42,
    )

    result = verifier.verify(
        event=event,
        client=mock_client,
    )

    assert result.status == "fully_recovered"
    assert result.checks_passed == 3
    assert result.checks_total == 3
    assert result.blockchain_written is True
    # Confirm on-chain mark_recovery_verified was actually called
    mock_client.mark_recovery_verified.assert_called_once_with(0)


def test_enhanced_recovery_still_at_risk_produces_zero_onchain_writes():
    verifier = EnhancedRecoveryVerifier(check_offsets=(0, 30, 60))

    # Borderline metric: packet_count = 180 (threshold is 200, > 70% threshold)
    # Passes initially at T+0s, but flaps/fails at T+30s / T+60s
    event = {
        "flow_id": "flow-flapping-portscan",
        "attack_type": "PortScan",
        "confidence": 0.95,
        "raw_features": {"packet_count": 180},
        "_event_hash": "b" * 64,
    }

    mock_client = MagicMock()
    mock_client.get_entry_count.return_value = 1
    mock_client.get_entry.return_value = {"event_hash": "b" * 64}

    result = verifier.verify(
        event=event,
        client=mock_client,
    )

    # Outcome MUST be still_at_risk
    assert result.status == "still_at_risk"
    assert 0 < result.checks_passed < result.checks_total
    # CRITICAL: PROVE ZERO ON-CHAIN WRITES OCCURRED
    assert result.blockchain_written is False
    mock_client.mark_recovery_verified.assert_not_called()


def test_enhanced_recovery_escalated_produces_zero_onchain_writes():
    verifier = EnhancedRecoveryVerifier(check_offsets=(0, 30, 60))

    # Severe failure: packet_count = 900 (threshold 200)
    event = {
        "flow_id": "flow-unresolved-portscan",
        "attack_type": "PortScan",
        "confidence": 0.99,
        "raw_features": {"packet_count": 900},
        "_event_hash": "c" * 64,
    }

    mock_client = MagicMock()

    result = verifier.verify(
        event=event,
        client=mock_client,
    )

    assert result.status == "escalated"
    assert result.checks_passed == 0
    assert result.blockchain_written is False
    mock_client.mark_recovery_verified.assert_not_called()


def test_v1_verify_recovery_regression_intact():
    """Confirm v1's original verified/escalated mechanism still functions identically when invoked directly."""
    event = {
        "_event_hash": "d" * 64,
        "attack_type": "PortScan",
    }
    sim_success = RecoverySimulationResult(
        status="verified",
        attack_type="PortScan",
        action="Block IP",
        reason="PortScan packet rate reduced below threshold.",
    )
    mock_client = MagicMock()
    mock_client.get_entry_count.return_value = 1
    mock_client.get_entry.return_value = {"event_hash": "d" * 64}
    mock_client.mark_recovery_verified.return_value = MagicMock(tx_hash="0x999")

    # Direct v1 call
    v1_res = verify_recovery(
        event=event,
        simulation_result=sim_success,
        client=mock_client,
    )
    assert v1_res["status"] == "verified"
    assert v1_res["blockchain_write"] is True
    assert v1_res["entry_index"] == 0


# ============================================================================
# FEATURE 5 TESTS: Proactive Chain-Coordinated Attack Prevention
# ============================================================================

def test_threat_registry_proactive_prevention_flow(in_memory_db):
    malicious_ip = "198.51.100.77"
    origin_hash = "e" * 64

    # Step 1: Source IP gets an on-chain confirmed event in incident store
    confirmed_incident = Incident(
        flow_id="flow-initial-attack",
        event_timestamp="2026-10-03T11:00:00Z",
        source_ip=malicious_ip,
        source_port=44123,
        destination_ip="10.0.0.5",
        destination_port=80,
        attack_type="DoS",
        confidence=0.99,
        raw_features_json="{}",
        event_hash=origin_hash,
        detection_status="detected",
        event_transaction_hash="0xbeef12345678",
        recovery_verified=True,
    )
    in_memory_db.add(confirmed_incident)
    in_memory_db.commit()

    service = ThreatRegistryService()

    # Step 2: Sync registry from confirmed ledger records
    synced = service.sync_from_ledger(in_memory_db)
    assert synced >= 1

    threat_rec = service.check_source_ip(malicious_ip, db=in_memory_db)
    assert threat_rec is not None
    assert threat_rec.source_ip == malicious_ip
    assert threat_rec.event_hash == origin_hash

    # Step 3: Second traffic arrival from malicious_ip is pre-emptively prevented
    prevented_record = service.prevent_if_threat(
        source_ip=malicious_ip,
        destination_ip="10.0.0.5",
        destination_port=80,
        attack_type="DoS",
        timestamp="2026-10-03T11:05:00Z",
        db=in_memory_db,
    )

    assert prevented_record is not None
    assert isinstance(prevented_record, PreventedAttack)
    assert prevented_record.source_ip == malicious_ip
    assert prevented_record.origin_incident_hash == origin_hash
    assert "Pre-emptively blocked" in prevented_record.prevention_reason

    # Step 4: Verify prevented attack persisted in prevented_attacks table
    stored = list_prevented_attacks(in_memory_db)
    assert len(stored) == 1
    assert stored[0].source_ip == malicious_ip


def test_benign_traffic_not_prevented(in_memory_db):
    service = ThreatRegistryService()
    benign_ip = "10.0.0.200"

    prevented = service.prevent_if_threat(
        source_ip=benign_ip,
        destination_ip="10.0.0.5",
        destination_port=80,
        attack_type="BENIGN",
        timestamp="2026-10-03T11:10:00Z",
        db=in_memory_db,
    )

    # Benign / clean source should NOT be prevented
    assert prevented is None
