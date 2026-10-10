"""
Sprint 6 — Full end-to-end pipeline test.

This test exercises the COMPLETE ChainForensics pipeline in one
continuous automated flow:

    Raw forensic event
        → Event hashing
        → Explanation generation
        → Recovery simulation
        → Database persistence (create + update)
        → API retrieval (via FastAPI TestClient)

The blockchain leg is mocked because the local Hardhat node is
not guaranteed to be running during CI. The smart contract tests
(test/ForensicLedger.test.js) cover the on-chain layer separately.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from chainforensics.database.database import Base
from chainforensics.database.repository import (
    create_incident,
    update_blockchain_result,
    update_recovery_result,
    get_incident,
    list_incidents,
    count_incidents,
)
from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)
from chainforensics.explainability.generator import generate_explanation
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture()
def db_session(tmp_path):
    """Create a fresh in-memory SQLite DB for each test."""
    db_url = f"sqlite:///{tmp_path}/e2e_test.db"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def mock_blockchain_client():
    """
    Mock the BlockchainClient for end-to-end test.

    Simulates the on-chain ledger with an in-memory list.
    """
    client = MagicMock()
    ledger = []

    def log_event(event_hash, **kwargs):
        ledger.append({
            "event_hash": bytes.fromhex(event_hash),
            "recovery_verified": False,
        })
        result = MagicMock()
        result.tx_hash = "0x" + "ab" * 32
        result.block_number = len(ledger)
        result.gas_used = 85000
        result.latency_seconds = 0.05
        result.attempts = 1
        return result

    def get_entry_count():
        return len(ledger)

    def get_entry(index):
        entry = ledger[index]
        return {
            "event_hash": entry["event_hash"],
            "timestamp": 1700000000 + index,
            "recorder": "0x" + "00" * 20,
            "recovery_verified": entry["recovery_verified"],
        }

    def mark_recovery_verified(index):
        ledger[index]["recovery_verified"] = True
        result = MagicMock()
        result.tx_hash = "0x" + "cd" * 32
        result.block_number = len(ledger) + 1
        result.gas_used = 45000
        result.latency_seconds = 0.03
        result.attempts = 1
        return result

    client.log_event = log_event
    client.get_entry_count = get_entry_count
    client.get_entry = get_entry
    client.mark_recovery_verified = mark_recovery_verified

    return client


# ============================================================
# THE END-TO-END TEST
# ============================================================

class TestEndToEndPipeline:
    """
    Full pipeline: event → hash → blockchain log → explain →
    recovery simulate → verify → persist → API retrieve.
    """

    def test_full_pipeline_dos_attack_verified(
        self, db_session, mock_blockchain_client
    ):
        """
        Scenario: A DoS attack with packet_count=300 (below 500 threshold)
        should flow through the entire pipeline and be verified.
        """

        # ── STEP 1: Build forensic event ──
        event = build_forensic_event(
            flow_id="e2e-flow-001",
            timestamp="2026-09-30T12:00:00Z",
            src_ip="10.0.0.99",
            src_port=54321,
            dst_ip="192.168.1.10",
            dst_port=80,
            attack_type="DoS",
            confidence=0.95,
            raw_features={"packet_count": 300, "flow_duration": 5000},
        )

        assert event["flow_id"] == "e2e-flow-001"
        assert event["attack_type"] == "DoS"
        assert event["confidence"] == 0.95

        # ── STEP 2: Hash the event ──
        event_hash = hash_forensic_event(event)

        assert len(event_hash) == 64
        assert event_hash == hash_forensic_event(event)  # deterministic

        # ── STEP 3: Log to blockchain (mocked) ──
        bc_result = mock_blockchain_client.log_event(event_hash)

        assert bc_result.block_number == 1

        # ── STEP 4: Generate explanation ──
        explanation = generate_explanation(event)

        assert explanation["status"] == "generated"
        assert explanation["attack_type"] == "DoS"
        assert explanation["severity"] == "HIGH"
        assert "10.0.0.99" in explanation["explanation"]
        assert "192.168.1.10" in explanation["explanation"]
        assert len(explanation["recovery_recommendations"]) >= 1

        # ── STEP 5: Simulate recovery ──
        sim_result = simulate_recovery(event)

        assert sim_result.status == "verified"
        assert sim_result.attack_type == "DoS"
        assert "300" in sim_result.reason

        # ── STEP 6: Verify recovery on-chain (mocked) ──
        event_with_hash = {**event, "_event_hash": event_hash}
        verification = verify_recovery(
            event=event_with_hash,
            simulation_result=sim_result,
            client=mock_blockchain_client,
        )

        assert verification["status"] == "verified"
        assert verification["blockchain_write"] is True
        assert verification["entry_index"] == 0

        # ── STEP 7: Persist to database ──
        incident = create_incident(
            db_session,
            event=event,
            event_hash=event_hash,
            detection_status="detected",
            explanation=explanation,
        )

        assert incident.id is not None
        assert incident.flow_id == "e2e-flow-001"
        assert incident.event_hash == event_hash.lower()

        # Update blockchain result
        update_blockchain_result(
            db_session,
            event_hash=event_hash,
            transaction_hash=bc_result.tx_hash,
            block_number=bc_result.block_number,
            latency_seconds=bc_result.latency_seconds,
        )

        # Update recovery result
        update_recovery_result(
            db_session,
            event_hash=event_hash,
            recovery_status="verified",
            recovery_reason=verification["reason"],
            recovery_entry_index=verification["entry_index"],
            recovery_transaction_hash=verification["transaction"].tx_hash,
            recovery_verified=True,
        )

        # ── STEP 8: Retrieve and validate full incident state ──
        persisted = get_incident(db_session, event_hash)

        assert persisted is not None
        assert persisted.flow_id == "e2e-flow-001"
        assert persisted.attack_type == "DoS"
        assert persisted.confidence == 0.95
        assert persisted.detection_status == "detected"
        assert persisted.event_transaction_hash is not None
        assert persisted.event_block_number == 1
        assert persisted.recovery_status == "verified"
        assert persisted.recovery_verified is True
        assert persisted.recovery_entry_index == 0

        # Verify explanation was persisted
        explanation_data = json.loads(persisted.explanation_json)
        assert explanation_data["severity"] == "HIGH"

        # Verify listing and counting
        all_incidents = list_incidents(db_session)
        assert len(all_incidents) == 1

        total = count_incidents(db_session)
        assert total == 1

    def test_full_pipeline_portscan_escalated(
        self, db_session, mock_blockchain_client
    ):
        """
        Scenario: A PortScan with packet_count=500 (above 200 threshold)
        should be escalated — NO recovery blockchain write.
        """

        # ── Build event ──
        event = build_forensic_event(
            flow_id="e2e-flow-002",
            timestamp="2026-09-30T12:05:00Z",
            src_ip="172.16.0.50",
            src_port=12345,
            dst_ip="10.0.0.1",
            dst_port=22,
            attack_type="PortScan",
            confidence=0.88,
            raw_features={"packet_count": 500},
        )

        event_hash = hash_forensic_event(event)

        # ── Blockchain log ──
        mock_blockchain_client.log_event(event_hash)

        # ── Explanation ──
        explanation = generate_explanation(event)
        assert explanation["severity"] == "HIGH"

        # ── Recovery simulation ──
        sim_result = simulate_recovery(event)
        assert sim_result.status == "escalated"

        # ── Verification ──
        event_with_hash = {**event, "_event_hash": event_hash}
        verification = verify_recovery(
            event=event_with_hash,
            simulation_result=sim_result,
            client=mock_blockchain_client,
        )

        assert verification["status"] == "escalated"
        assert verification["blockchain_write"] is False

        # ── Persist ──
        create_incident(
            db_session,
            event=event,
            event_hash=event_hash,
            explanation=explanation,
        )
        update_recovery_result(
            db_session,
            event_hash=event_hash,
            recovery_status="escalated",
            recovery_reason=verification["reason"],
            recovery_verified=False,
        )

        persisted = get_incident(db_session, event_hash)
        assert persisted.recovery_status == "escalated"
        assert persisted.recovery_verified is False

    def test_full_pipeline_benign_event(
        self, db_session, mock_blockchain_client
    ):
        """
        Scenario: A BENIGN event should be verified with no
        remediation required.
        """

        event = build_forensic_event(
            flow_id="e2e-flow-003",
            timestamp="2026-09-30T12:10:00Z",
            src_ip="192.168.1.100",
            src_port=8080,
            dst_ip="192.168.1.1",
            dst_port=443,
            attack_type="BENIGN",
            confidence=0.99,
            raw_features={"flow_duration": 1000},
        )

        event_hash = hash_forensic_event(event)

        mock_blockchain_client.log_event(event_hash)

        explanation = generate_explanation(event)
        assert explanation["severity"] == "LOW"

        sim_result = simulate_recovery(event)
        assert sim_result.status == "verified"
        assert sim_result.action == "No remediation required"

        event_with_hash = {**event, "_event_hash": event_hash}
        verification = verify_recovery(
            event=event_with_hash,
            simulation_result=sim_result,
            client=mock_blockchain_client,
        )
        assert verification["status"] == "verified"
        assert verification["blockchain_write"] is True

        create_incident(
            db_session,
            event=event,
            event_hash=event_hash,
            explanation=explanation,
        )
        update_recovery_result(
            db_session,
            event_hash=event_hash,
            recovery_status="verified",
            recovery_reason=verification["reason"],
            recovery_verified=True,
        )

        persisted = get_incident(db_session, event_hash)
        assert persisted.attack_type == "BENIGN"
        assert persisted.recovery_verified is True

    def test_full_pipeline_unknown_attack_manual_review(
        self, db_session, mock_blockchain_client
    ):
        """
        Scenario: Unknown attack type → manual review explanation,
        escalated recovery.
        """

        event = build_forensic_event(
            flow_id="e2e-flow-004",
            timestamp="2026-09-30T12:15:00Z",
            src_ip="10.10.10.10",
            src_port=9999,
            dst_ip="10.10.10.1",
            dst_port=3306,
            attack_type="ZeroDayExploit",
            confidence=0.75,
            raw_features={},
        )

        event_hash = hash_forensic_event(event)

        explanation = generate_explanation(event)
        assert explanation["status"] == "manual_review_required"
        assert explanation["severity"] == "UNKNOWN"

        sim_result = simulate_recovery(event)
        assert sim_result.status == "escalated"

        event_with_hash = {**event, "_event_hash": event_hash}
        verification = verify_recovery(
            event=event_with_hash,
            simulation_result=sim_result,
            client=mock_blockchain_client,
        )
        assert verification["status"] == "escalated"
        assert verification["blockchain_write"] is False


class TestAPIEndToEnd:
    """
    Test the API layer via FastAPI TestClient.
    """

    def test_api_health_and_incidents(self, db_session):
        """
        Verify API health check and incident listing endpoints.
        """
        # Import here to avoid polluting other tests with app-level state
        from chainforensics.api.main import app
        from chainforensics.api.dependencies import get_db

        # Override the DB dependency
        def override_get_db():
            try:
                yield db_session
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db

        try:
            client = TestClient(app)

            # Public health check
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json()["status"] == "ok"

            # Protected endpoint without API key
            response = client.get("/incidents")
            assert response.status_code == 401

            # Protected endpoint with API key
            api_key = os.environ.get(
                "CHAINFORENSIS_API_KEY", "test-api-key-for-ci"
            )
            headers = {"x-api-key": api_key}

            # Create a test incident first
            event = build_forensic_event(
                flow_id="api-test-001",
                timestamp="2026-09-30T13:00:00Z",
                src_ip="10.0.0.1",
                src_port=1234,
                dst_ip="10.0.0.2",
                dst_port=80,
                attack_type="DoS",
                confidence=0.90,
                raw_features={"packet_count": 100},
            )
            event_hash = hash_forensic_event(event)

            create_incident(
                db_session,
                event=event,
                event_hash=event_hash,
                detection_status="detected",
            )

            # List incidents
            response = client.get("/incidents", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert len(data["items"]) == 1
            assert data["items"][0]["flow_id"] == "api-test-001"

            # Get single incident by hash
            response = client.get(
                f"/incidents/{event_hash}", headers=headers
            )
            assert response.status_code == 200
            incident_data = response.json()["incident"]
            assert incident_data["event_hash"] == event_hash.lower()

            # 404 for missing incident
            response = client.get(
                "/incidents/" + "0" * 64, headers=headers
            )
            assert response.status_code == 404

        finally:
            app.dependency_overrides.clear()
