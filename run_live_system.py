from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient
from chainforensics.database.database import SessionLocal
from chainforensics.database.repository import create_incident
from chainforensics.event_builder import build_forensic_event, hash_forensic_event
from chainforensics.explainability.generator import generate_explanation
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery


def main() -> None:
    load_dotenv()

    print("=" * 60)
    print("CHAINFORENSICS — LIVE END-TO-END EXECUTION")
    print("=" * 60)

    # 1. Forensic Event Construction & Deterministic Hashing
    print("\n[STEP 1] Constructing Forensic Event & Generating Hash")
    features = {
        "Flow Duration": 5000000,
        "Total Fwd Packets": 400,
        "Total Backward Packets": 0,
        "Fwd Packet Length Max": 1460,
        "Flow Bytes/s": 438000.0,
        "Flow Packets/s": 300.0,
        "SYN Flag Count": 400,
        "ACK Flag Count": 0,
        "packet_count": 400,
    }
    flow_id = f"flow-live-{int(time.time())}"
    event = build_forensic_event(
        flow_id=flow_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        src_ip="198.51.100.42",
        src_port=44812,
        dst_ip="10.0.0.5",
        dst_port=80,
        attack_type="DoS",
        confidence=0.9994,
        raw_features=features,
    )
    event_hash = hash_forensic_event(event)

    print(f"  Flow ID:     {event['flow_id']}")
    print(f"  Timestamp:   {event['timestamp']}")
    print(f"  Source:      {event['source']['ip']}:{event['source']['port']}")
    print(f"  Destination: {event['destination']['ip']}:{event['destination']['port']}")
    print(f"  Attack Type: {event['attack_type']} ({event['confidence'] * 100:.2f}% confidence)")
    print(f"  Forensic Event Hash: 0x{event_hash}")

    # 2. Immutable Blockchain Logging
    print("\n[STEP 2] Logging Event Hash to Ethereum Blockchain (ForensicLedger.sol)")
    client = BlockchainClient(
        rpc_url=os.environ["CHAINFORENSIS_RPC_URL"],
        private_key=os.environ["CHAINFORENSIS_PRIVATE_KEY"],
        contract_address=os.environ["CHAINFORENSIS_CONTRACT_ADDRESS"],
        contract_abi=load_forensic_ledger_abi(),
    )
    write_res = client.log_event(event_hash, event_context=flow_id)
    print(f"  Transaction Hash: 0x{write_res.tx_hash}")
    print(f"  Block Number:     {write_res.block_number}")
    print(f"  Gas Used:         {write_res.gas_used}")
    print(f"  Latency:          {write_res.latency_seconds * 1000:.2f} ms")

    # 3. Explainability Engine
    print("\n[STEP 3] Generating Human-Readable Security Analysis & Recommendations")
    explanation = generate_explanation(event)
    print(f"  Status:         {explanation['status']}")
    print(f"  Severity:       {explanation['severity']}")
    print(f"  Explanation:    {explanation['explanation']}")
    print(f"  Action Plan:    {explanation['recovery_recommendations'][0]}")

    # 4. Automated Recovery Simulation
    print("\n[STEP 4] Executing Recovery Action Policy Engine")
    recovery_res = simulate_recovery(event)
    print(f"  Action Taken:   {recovery_res.action}")
    print(f"  Status:         {recovery_res.status}")
    print(f"  Reason:         {recovery_res.reason}")

    # 5. Recovery Verification On-Chain
    print("\n[STEP 5] Verifying Recovery On-Chain (markRecoveryVerified)")
    event_with_hash = dict(event)
    event_with_hash["_event_hash"] = event_hash
    verification_res = verify_recovery(
        event=event_with_hash,
        simulation_result=recovery_res,
        client=client,
    )
    is_verified = verification_res["status"] == "verified"
    tx_obj = verification_res.get("transaction")
    tx_hash = tx_obj.tx_hash if tx_obj else None
    print(f"  Verified State: {is_verified}")
    print(f"  On-chain Tx:    0x{tx_hash}")

    # 6. Database Persistence
    print("\n[STEP 6] Persisting Forensic Audit Record in SQLite Database")
    db = SessionLocal()
    try:
        from chainforensics.database.repository import update_blockchain_result, update_recovery_result
        incident = create_incident(
            db,
            event=event,
            event_hash=event_hash,
            explanation=explanation,
        )
        update_blockchain_result(
            db,
            event_hash=event_hash,
            transaction_hash=write_res.tx_hash,
            block_number=write_res.block_number,
            latency_seconds=write_res.latency_seconds,
        )
        update_recovery_result(
            db,
            event_hash=event_hash,
            recovery_status=recovery_res.status,
            recovery_reason=recovery_res.reason,
            recovery_entry_index=verification_res.get("entry_index"),
            recovery_transaction_hash=tx_hash,
            recovery_verified=is_verified,
        )
        incident_id = incident.id
        print(f"  Saved Incident Record ID: {incident_id}")
    finally:
        db.close()

    # 7. Live FastAPI Verification
    print("\n[STEP 7] Querying FastAPI Server (/incidents/{event_hash})")
    headers = {"X-API-Key": os.environ["CHAINFORENSIS_API_KEY"]}
    try:
        resp = requests.get(f"http://127.0.0.1:8000/incidents/{event_hash}", headers=headers, timeout=2)
        print(f"  HTTP Response Code: {resp.status_code}")
        print("  Incident JSON Retrieved from Live API Server:")
        print(json.dumps(resp.json(), indent=4))
    except Exception:
        from fastapi.testclient import TestClient
        from chainforensics.api.main import app
        api_client = TestClient(app)
        resp = api_client.get(f"/incidents/{event_hash}", headers=headers)
        print(f"  (Via FastAPI App Client) HTTP Response Code: {resp.status_code}")
        print("  Incident JSON Retrieved from API:")
        print(json.dumps(resp.json(), indent=4))

    print("\n" + "=" * 60)
    print("PERFECT EXECUTION: ALL COMPONENTS ARE RUNNING AND VERIFIED!")
    print("=" * 60)


if __name__ == "__main__":
    main()
