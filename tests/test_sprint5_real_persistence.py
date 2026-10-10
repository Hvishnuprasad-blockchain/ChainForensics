from __future__ import annotations

import os
import time
import uuid

from dotenv import load_dotenv

from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient
from chainforensics.database.database import SessionLocal
from chainforensics.database.repository import (
    create_incident,
    get_incident,
    update_blockchain_result,
    update_recovery_result,
)
from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery


load_dotenv()


def create_client() -> BlockchainClient:
    return BlockchainClient(
        rpc_url=os.environ["CHAINFORENSIS_RPC_URL"],
        private_key=os.environ["CHAINFORENSIS_PRIVATE_KEY"],
        contract_address=os.environ[
            "CHAINFORENSIS_CONTRACT_ADDRESS"
        ],
        contract_abi=load_forensic_ledger_abi(),
        max_retries=3,
        base_delay_seconds=0.5,
    )


def build_real_incident() -> dict:
    return build_forensic_event(
        flow_id=f"CF-SPRINT5-DB-{uuid.uuid4().hex[:8]}",
        timestamp=time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        src_ip="192.168.50.10",
        src_port=45001,
        dst_ip="10.0.0.25",
        dst_port=443,
        attack_type="PortScan",
        confidence=0.95,
        raw_features={
            "packet_count": 100,
            "flow_duration": 2.41,
            "destination_port": 443,
        },
    )


def test_real_sprint4_incident_is_persisted() -> None:
    client = create_client()
    db = SessionLocal()

    try:
        # ========================================================
        # 1. Build REAL forensic event
        # ========================================================

        event = build_real_incident()

        event_hash = hash_forensic_event(event)

        # IMPORTANT:
        # Sprint 4 verifier expects the hash inside the event.
        event["_event_hash"] = event_hash

        print()
        print("=" * 70)
        print("SPRINT 5 REAL INCIDENT PERSISTENCE TEST")
        print("=" * 70)

        print("Flow ID:", event["flow_id"])
        print("Event hash:", event_hash)

        # ========================================================
        # 2. REAL blockchain write
        # ========================================================

        log_result = client.log_event(
            event_hash,
            event_context=event["flow_id"],
        )

        print(
            "Blockchain transaction:",
            log_result.tx_hash,
        )

        print(
            "Blockchain block:",
            log_result.block_number,
        )

        print(
            "Ledger latency:",
            log_result.latency_seconds,
            "seconds",
        )

        # ========================================================
        # 3. Persist initial incident
        # ========================================================

        incident = create_incident(
            db,
            event=event,
            event_hash=event_hash,
            detection_status="detected",
        )

        assert incident.event_hash == event_hash

        # ========================================================
        # 4. Persist REAL blockchain result
        # ========================================================

        update_blockchain_result(
            db,
            event_hash=event_hash,
            transaction_hash=log_result.tx_hash,
            block_number=log_result.block_number,
            latency_seconds=log_result.latency_seconds,
        )

        # ========================================================
        # 5. REAL Sprint 4 recovery simulation
        # ========================================================

        simulation = simulate_recovery(event)

        print(
            "Recovery simulation:",
            simulation.status,
        )

        print(
            "Recovery reason:",
            simulation.reason,
        )

        # ========================================================
        # 6. REAL Sprint 4 recovery verification
        # ========================================================

        verification = verify_recovery(
            event=event,
            simulation_result=simulation,
            client=client,
        )

        print(
            "Final recovery status:",
            verification["status"],
        )

        # ========================================================
        # 7. Persist REAL recovery result
        # ========================================================

        recovery_status = verification["status"]

        recovery_transaction = verification.get(
            "transaction"
        )

        recovery_tx_hash = None

        if recovery_transaction is not None:

            recovery_tx_hash = getattr(
                recovery_transaction,
                "tx_hash",
                None,
            )

            if recovery_tx_hash is None:
                recovery_tx_hash = getattr(
                    recovery_transaction,
                    "transaction_hash",
                    None,
                )

            if recovery_tx_hash is not None:
                recovery_tx_hash = str(
                    recovery_tx_hash
                ).lower()

        update_recovery_result(
            db,
            event_hash=event_hash,
            recovery_status=recovery_status,
            recovery_reason=verification.get(
                "reason",
                simulation.reason,
            ),
            recovery_entry_index=verification.get(
                "entry_index"
            ),
            recovery_transaction_hash=recovery_tx_hash,
            recovery_verified=(
                recovery_status == "verified"
            ),
        )

        # ========================================================
        # 8. Read incident back from SQLite
        # ========================================================

        stored = get_incident(
            db,
            event_hash,
        )

        assert stored is not None

        # ========================================================
        # 9. Verify real forensic data
        # ========================================================

        assert stored.flow_id == event["flow_id"]

        assert stored.event_hash == event_hash

        assert stored.attack_type == "PortScan"

        assert stored.confidence == 0.95

        # ========================================================
        # 10. Verify REAL blockchain data
        # ========================================================

        assert (
            stored.event_transaction_hash
            == str(log_result.tx_hash).lower()
        )

        assert (
            stored.event_block_number
            == log_result.block_number
        )

        assert (
            stored.ledger_write_latency_seconds
            == log_result.latency_seconds
        )

        # ========================================================
        # 11. Verify REAL recovery data
        # ========================================================

        assert (
            stored.recovery_status
            == recovery_status
        )

        if recovery_status == "verified":

            assert stored.recovery_verified is True

            assert (
                stored.recovery_entry_index
                is not None
            )

            assert (
                stored.recovery_transaction_hash
                is not None
            )

        else:

            assert stored.recovery_verified is False

        # ========================================================
        # 12. Final confirmation
        # ========================================================

        print()
        print("=" * 70)
        print("REAL SQLITE PERSISTENCE VERIFIED")
        print("=" * 70)

        print(
            "Incident ID:",
            stored.id,
        )

        print(
            "Event hash:",
            stored.event_hash,
        )

        print(
            "Blockchain TX:",
            stored.event_transaction_hash,
        )

        print(
            "Blockchain block:",
            stored.event_block_number,
        )

        print(
            "Ledger latency:",
            stored.ledger_write_latency_seconds,
        )

        print(
            "Recovery status:",
            stored.recovery_status,
        )

        print(
            "Recovery verified:",
            stored.recovery_verified,
        )

    finally:
        db.close()
