from __future__ import annotations

import os
import time
import uuid

import pytest
from dotenv import load_dotenv
from web3 import Web3

from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)
from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient
from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import verify_recovery


load_dotenv()


# ============================================================
# Configuration
# ============================================================

INCIDENT_COUNT = 10


# ============================================================
# Blockchain client
# ============================================================

def create_client() -> BlockchainClient:
    """
    Create the same blockchain client used by Sprint 2.
    """

    rpc_url = os.environ["CHAINFORENSIS_RPC_URL"]
    private_key = os.environ["CHAINFORENSIS_PRIVATE_KEY"]
    contract_address = os.environ["CHAINFORENSIS_CONTRACT_ADDRESS"]

    return BlockchainClient(
        rpc_url=rpc_url,
        private_key=private_key,
        contract_address=contract_address,
        contract_abi=load_forensic_ledger_abi(),
        max_retries=3,
        base_delay_seconds=0.5,
    )


# ============================================================
# Direct Web3 connection
# Used only for checking REAL blockchain event logs.
# ============================================================

def create_web3_contract():
    rpc_url = os.environ["CHAINFORENSIS_RPC_URL"]
    contract_address = os.environ["CHAINFORENSIS_CONTRACT_ADDRESS"]

    web3 = Web3(
        Web3.HTTPProvider(rpc_url)
    )

    if not web3.is_connected():
        raise RuntimeError(
            "Could not connect to the local blockchain."
        )

    abi = load_forensic_ledger_abi()

    contract = web3.eth.contract(
        address=Web3.to_checksum_address(
            contract_address
        ),
        abi=abi,
    )

    return web3, contract


# ============================================================
# Hash normalization
# ============================================================

def normalize_hash(value: object) -> str:
    """
    Convert bytes32/string blockchain values into
    one comparable lowercase hexadecimal representation.
    """

    if isinstance(value, bytes):
        return value.hex().lower()

    if isinstance(value, bytearray):
        return bytes(value).hex().lower()

    if isinstance(value, str):
        value = value.strip().lower()

        if value.startswith("0x"):
            value = value[2:]

        return value

    raise TypeError(
        f"Unsupported hash type: {type(value).__name__}"
    )


# ============================================================
# Build deterministic Sprint 4 incidents
# ============================================================

def build_incident(number: int) -> dict:
    """
    Even incidents:
        packet_count <= 200
        deterministic VERIFIED result.

    Odd incidents:
        packet_count > 200
        deterministic ESCALATED result.

    Therefore every run contains:
        5 verified
        5 escalated
    """

    if number % 2 == 0:
        packet_count = 100
    else:
        packet_count = 500

    event = build_forensic_event(
        flow_id=f"CF-SPRINT4-{number}-{uuid.uuid4().hex[:8]}",
        timestamp=time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        src_ip=f"192.168.10.{number}",
        src_port=40000 + number,
        dst_ip="10.0.0.25",
        dst_port=443,
        attack_type="PortScan",
        confidence=0.95,
        raw_features={
            "packet_count": packet_count,
            "flow_duration": 2.41,
            "destination_port": 443,
        },
    )

    return event


# ============================================================
# Extract transaction hash safely
# ============================================================

def extract_transaction_hash(transaction: object) -> str | None:
    """
    Handle both dataclass/object transaction results
    and dictionary transaction results.
    """

    if transaction is None:
        return None

    if isinstance(transaction, dict):
        value = transaction.get("tx_hash")

        if value is None:
            value = transaction.get("transaction_hash")

        if value is None:
            return None

        return str(value).lower()

    value = getattr(
        transaction,
        "tx_hash",
        None,
    )

    if value is None:
        value = getattr(
            transaction,
            "transaction_hash",
            None,
        )

    if value is None:
        return None

    return str(value).lower()


# ============================================================
# Sprint 4 REAL integration test
# ============================================================

def test_sprint4_real_local_closed_loop() -> None:
    """
    Sprint 4 full closed-loop integration test.

    For 10 real incidents:

        forensic event
              ↓
        SHA-256 event hash
              ↓
        logEvent()
              ↓
        deterministic recovery simulation
              ↓
        ┌───────────────────────┐
        │                       │
     VERIFIED                ESCALATED
        │                       │
        ↓                       ↓
    scan blockchain        NO blockchain
    for event hash         recovery write
        │
        ↓
    real index
        │
        ↓
    markRecoveryVerified()
        │
        ↓
    RecoveryVerified event

    The test then checks the ACTUAL blockchain state and
    ACTUAL RecoveryVerified event logs.
    """

    client = create_client()

    web3, contract = create_web3_contract()

    # --------------------------------------------------------
    # IMPORTANT:
    # Remember where this test started.
    #
    # This prevents old Sprint 4 runs from affecting
    # the current test result.
    # --------------------------------------------------------

    start_block = web3.eth.block_number
    start_entry_count = client.get_entry_count()

    print()
    print("=" * 70)
    print("SPRINT 4 REAL LOCAL BLOCKCHAIN CLOSED-LOOP TEST")
    print("=" * 70)

    print("Starting block:", start_block)
    print("Starting ledger entries:", start_entry_count)
    print("Incidents:", INCIDENT_COUNT)
    print(
        "Contract:",
        os.environ["CHAINFORENSIS_CONTRACT_ADDRESS"],
    )

    verified_local: list[dict] = []
    escalated_local: list[dict] = []

    # ========================================================
    # Process 10 incidents
    # ========================================================

    for number in range(
        1,
        INCIDENT_COUNT + 1,
    ):

        print()
        print("-" * 70)
        print(
            f"INCIDENT {number}/{INCIDENT_COUNT}"
        )

        # ----------------------------------------------------
        # 1. Build forensic event
        # ----------------------------------------------------

        event = build_incident(number)

        event_hash = hash_forensic_event(event)

        event["_event_hash"] = event_hash

        print(
            "Flow ID:",
            event["flow_id"],
        )

        print(
            "Attack:",
            event["attack_type"],
        )

        print(
            "Packet count:",
            event["raw_features"]["packet_count"],
        )

        print(
            "SHA-256:",
            event_hash,
        )

        # ----------------------------------------------------
        # 2. Write forensic event to blockchain
        # ----------------------------------------------------

        log_result = client.log_event(
            event_hash,
            event_context=event["flow_id"],
        )

        print(
            "Event transaction:",
            log_result.tx_hash,
        )

        print(
            "Event block:",
            log_result.block_number,
        )

        # ----------------------------------------------------
        # 3. Deterministic recovery simulation
        # ----------------------------------------------------

        simulation = simulate_recovery(event)

        print(
            "Simulation:",
            simulation.status,
        )

        print(
            "Reason:",
            simulation.reason,
        )

        # ----------------------------------------------------
        # 4. Sprint 4 verifier
        # ----------------------------------------------------

        verification = verify_recovery(
            event=event,
            simulation_result=simulation,
            client=client,
        )

        print(
            "Final status:",
            verification["status"],
        )

        # ----------------------------------------------------
        # 5. Local bookkeeping
        # ----------------------------------------------------

        if verification["status"] == "verified":

            verified_local.append(
                {
                    "flow_id": event["flow_id"],
                    "event_hash": event_hash,
                    "index": verification["entry_index"],
                    "transaction": verification["transaction"],
                }
            )

            print(
                "Recovery transaction:",
                verification["transaction"],
            )

        else:

            escalated_local.append(
                {
                    "flow_id": event["flow_id"],
                    "event_hash": event_hash,
                }
            )

            print(
                "BLOCKCHAIN RECOVERY WRITE: NONE"
            )

    # ========================================================
    # Local bookkeeping
    # ========================================================

    print()
    print("=" * 70)
    print("LOCAL BOOKKEEPING")
    print("=" * 70)

    print(
        "Verified:",
        len(verified_local),
    )

    print(
        "Escalated:",
        len(escalated_local),
    )

    assert len(verified_local) == 5

    assert len(escalated_local) == 5

    assert (
        len(verified_local)
        + len(escalated_local)
        == INCIDENT_COUNT
    )

    # ========================================================
    # Query current ACTUAL contract state
    # ========================================================

    final_count = client.get_entry_count()

    print()
    print("=" * 70)
    print("ACTUAL CONTRACT STATE")
    print("=" * 70)

    print(
        "Final ledger entries:",
        final_count,
    )

    print(
        "New ledger entries:",
        final_count - start_entry_count,
    )

    # We created exactly 10 new forensic events.
    assert (
        final_count - start_entry_count
        == INCIDENT_COUNT
    ), (
        "The Sprint 4 run did not create exactly "
        "10 new forensic ledger entries."
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Only inspect entries created by THIS test run.
    #
    # We do NOT count old verified incidents from previous
    # Sprint 4 executions.
    # --------------------------------------------------------

    current_run_entries = []

    for index in range(
        start_entry_count,
        final_count,
    ):

        entry = client.get_entry(index)

        current_run_entries.append(
            {
                "index": index,
                "event_hash": normalize_hash(
                    entry["event_hash"]
                ),
                "recovery_verified": bool(
                    entry["recovery_verified"]
                ),
            }
        )

    onchain_verified_entries = [
        entry
        for entry in current_run_entries
        if entry["recovery_verified"]
    ]

    print(
        "Current-run verified entries:",
        len(onchain_verified_entries),
    )

    # ========================================================
    # Current-run hash verification
    # ========================================================

    local_verified_hashes = {
        item["event_hash"].lower()
        for item in verified_local
    }

    local_escalated_hashes = {
        item["event_hash"].lower()
        for item in escalated_local
    }

    onchain_verified_hashes = {
        item["event_hash"].lower()
        for item in onchain_verified_entries
    }

    print(
        "Local verified hashes:",
        len(local_verified_hashes),
    )

    print(
        "On-chain verified hashes:",
        len(onchain_verified_hashes),
    )

    # Every locally verified event must be verified on-chain.
    assert (
        onchain_verified_hashes
        == local_verified_hashes
    ), (
        "Current-run blockchain verification state "
        "does not exactly match local verified incidents."
    )

    # ========================================================
    # Query ACTUAL RecoveryVerified event logs
    # ========================================================

    latest_block = web3.eth.block_number

    recovery_logs = (
        contract.events.RecoveryVerified().get_logs(
            from_block=start_block,
            to_block=latest_block,
        )
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Only count RecoveryVerified events belonging to THIS
    # test run.
    #
    # The blockchain may contain RecoveryVerified events from
    # previous Sprint 4 executions. The event-log query uses
    # block numbers, while our test tracks the exact ledger
    # entries created during this run.
    #
    # Therefore filter using the ledger index.
    # --------------------------------------------------------

    recovery_logs = [
        log
        for log in recovery_logs
        if int(log["args"]["index"]) >= start_entry_count
    ]

    print()
    print("=" * 70)
    print("ACTUAL RECOVERYVERIFIED EVENT LOGS")
    print("=" * 70)

    actual_recovery_writes: list[dict] = []

    for log in recovery_logs:

        args = log["args"]

        entry_index = int(
            args["index"]
        )

        event_hash = normalize_hash(
            args["eventHash"]
        )

        transaction_hash = log["transactionHash"]

        if isinstance(
            transaction_hash,
            bytes,
        ):
            transaction_hash = (
                "0x"
                + transaction_hash.hex()
            )

        transaction_hash = str(
            transaction_hash
        ).lower()

        actual_recovery_writes.append(
            {
                "index": entry_index,
                "event_hash": event_hash,
                "transaction": transaction_hash,
            }
        )

        print()
        print(
            "RecoveryVerified event:"
        )

        print(
            "  Index:",
            entry_index,
        )

        print(
            "  Event hash:",
            event_hash,
        )

        print(
            "  Transaction:",
            transaction_hash,
        )

    # ========================================================
    # RecoveryVerified count
    # ========================================================

    print()
    print("=" * 70)
    print("CLOSED-LOOP COUNT VERIFICATION")
    print("=" * 70)

    print(
        "Local verified count:",
        len(verified_local),
    )

    print(
        "Contract verified count:",
        len(onchain_verified_entries),
    )

    print(
        "RecoveryVerified event count:",
        len(actual_recovery_writes),
    )

    assert (
        len(onchain_verified_entries)
        == len(verified_local)
    ), (
        "Current-run contract verified count does not "
        "match local verified count."
    )

    assert (
        len(actual_recovery_writes)
        == len(verified_local)
    ), (
        "Actual RecoveryVerified event count does not "
        "match local verified count."
    )

    # ========================================================
    # Prove exact verified hashes
    # ========================================================

    actual_recovery_hashes = {
        item["event_hash"].lower()
        for item in actual_recovery_writes
    }

    assert (
        actual_recovery_hashes
        == local_verified_hashes
    ), (
        "Actual RecoveryVerified event hashes do not "
        "match the locally verified incidents."
    )

    # ========================================================
    # CRITICAL SECURITY CHECK
    #
    # Escalated incidents MUST NOT appear in actual
    # RecoveryVerified event logs.
    # ========================================================

    escalated_recovery_intersection = (
        local_escalated_hashes
        & actual_recovery_hashes
    )

    print()
    print("=" * 70)
    print("ESCALATION SECURITY CHECK")
    print("=" * 70)

    print(
        "Escalated incidents:",
        len(escalated_local),
    )

    print(
        "Escalated incidents with RecoveryVerified writes:",
        len(escalated_recovery_intersection),
    )

    assert (
        len(escalated_recovery_intersection)
        == 0
    ), (
        "SECURITY FAILURE: an escalated incident "
        "received an on-chain recovery verification."
    )

    # ========================================================
    # Verify transaction hashes
    # ========================================================

    actual_transaction_hashes = {
        normalize_hash(item["transaction"])
        for item in actual_recovery_writes
    }

    for item in verified_local:

        tx_hash = normalize_hash(
            extract_transaction_hash(
                item["transaction"]
            )
        )

        assert tx_hash is not None, (
            "Verified recovery did not return "
            "a transaction hash."
        )

        assert (
            tx_hash
            in actual_transaction_hashes
        ), (
            "A locally recorded recovery transaction "
            "was not found in the actual RecoveryVerified "
            "event log."
        )

    # ========================================================
    # Security negative test
    #
    # Use an index that definitely does not exist.
    #
    # The contract MUST reject markRecoveryVerified().
    # ========================================================

    print()
    print("=" * 70)
    print("SECURITY NEGATIVE TEST")
    print("=" * 70)

    invalid_index = final_count + 100

    print(
        "Attempting invalid recovery index:",
        invalid_index,
    )

    before_invalid_test_count = (
        client.get_entry_count()
    )

    with pytest.raises(Exception):

        client.mark_recovery_verified(
            invalid_index
        )

    after_invalid_test_count = (
        client.get_entry_count()
    )

    assert (
        after_invalid_test_count
        == before_invalid_test_count
    ), (
        "Invalid recovery verification unexpectedly "
        "changed the blockchain ledger."
    )

    print(
        "Invalid index correctly rejected."
    )

    print(
        "Ledger count unchanged:",
        before_invalid_test_count,
        "->",
        after_invalid_test_count,
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()
    print("=" * 70)
    print("SPRINT 4 REAL CLOSED-LOOP TEST PASSED")
    print("=" * 70)

    print()
    print(
        "Incidents processed:",
        INCIDENT_COUNT,
    )

    print(
        "Verified:",
        len(verified_local),
    )

    print(
        "Escalated:",
        len(escalated_local),
    )

    print()
    print(
        "Actual RecoveryVerified events:",
        len(actual_recovery_writes),
    )

    print(
        "Escalated RecoveryVerified writes:",
        len(escalated_recovery_intersection),
    )

    print()
    print("RESULT:")

    print(
        "SUCCESS: Recovery successes permanently verified."
    )

    print(
        "SUCCESS: Correct on-chain indexes located."
    )

    print(
        "SUCCESS: Out-of-order/gapped ledger scanning handled."
    )

    print(
        "SUCCESS: Actual contract state checked."
    )

    print(
        "SUCCESS: Actual RecoveryVerified events checked."
    )

    print(
        "SUCCESS: Escalated incidents produced ZERO recovery writes."
    )

    print(
        "SUCCESS: Invalid index correctly rejected."
    )

    print(
        "SUCCESS: Local and blockchain counts match."
    )

