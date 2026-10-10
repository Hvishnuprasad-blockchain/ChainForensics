from __future__ import annotations

import hashlib
import logging
import os
import uuid

from dotenv import load_dotenv

from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient


load_dotenv()


def build_test_event_hash() -> str:
    """
    Create the base deterministic SHA-256 hash for the Sprint 2
    integration test.
    """

    event = {
        "event_id": "sprint2-local-integration-001",
        "attack_type": "DoS",
        "confidence": 0.9987,
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "timestamp": "2026-09-29T09:00:00Z",
    }

    canonical = str(sorted(event.items())).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def build_unique_test_event_hash() -> str:
    """
    Create a unique SHA-256 hash for every test execution.

    This prevents repeated local test runs from failing because
    ForensicLedger correctly rejects duplicate hashes.
    """

    base_hash = build_test_event_hash()

    unique_value = f"{base_hash}:{uuid.uuid4().hex}"

    return hashlib.sha256(
        unique_value.encode("utf-8")
    ).hexdigest()


def create_client() -> BlockchainClient:
    """
    Create the Sprint 2 blockchain client from .env configuration.
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


def normalize_bytes32(value: object) -> str:
    """
    Convert Solidity bytes32 returned by Web3 into a canonical
    lowercase 0x-prefixed hexadecimal string.
    """

    if isinstance(value, bytes):
        return "0x" + value.hex()

    if isinstance(value, bytearray):
        return "0x" + bytes(value).hex()

    if isinstance(value, str):
        value = value.strip()

        if value.startswith("0x"):
            return value.lower()

        return "0x" + value.lower()

    raise TypeError(
        f"Unexpected bytes32 value type: {type(value).__name__}"
    )


def test_python_client_local_hardhat_round_trip() -> None:
    """
    Sprint 2 integration test:

        Python client
            ↓
        Hardhat RPC
            ↓
        ForensicLedger.logEvent()
            ↓
        Transaction receipt
            ↓
        ForensicLedger.getEntry()
            ↓
        Python verification
    """

    logging.basicConfig(level=logging.INFO)

    client = create_client()

    # Generate a fresh hash for every test execution.
    event_hash = build_unique_test_event_hash()

    before_count = client.get_entry_count()

    print()
    print("=== SPRINT 2 PYTHON -> HARDHAT INTEGRATION ===")
    print("Before count:", before_count)
    print("Event hash:", event_hash)

    # ---------------------------------------------------------
    # WRITE EVENT TO BLOCKCHAIN
    # ---------------------------------------------------------

    result = client.log_event(
        event_hash,
        event_context="sprint2-local-integration-001",
    )

    print("Transaction hash:", result.tx_hash)
    print("Block number:", result.block_number)
    print("Gas used:", result.gas_used)
    print("Latency:", result.latency_seconds)
    print("Attempts:", result.attempts)

    # ---------------------------------------------------------
    # VERIFY ENTRY COUNT
    # ---------------------------------------------------------

    after_count = client.get_entry_count()

    assert after_count == before_count + 1, (
        "Blockchain entry count did not increase by exactly one."
    )

    # ---------------------------------------------------------
    # READ THE ENTRY BACK
    # ---------------------------------------------------------

    entry = client.get_entry(before_count)

    print("Read-back entry:", entry)

    # ---------------------------------------------------------
    # VERIFY EVENT HASH
    # ---------------------------------------------------------

    returned_hash = normalize_bytes32(
        entry["event_hash"]
    )

    expected_hash = (
        "0x" + event_hash
    ).lower()

    print("Expected hash:", expected_hash)
    print("Returned hash:", returned_hash)

    assert returned_hash == expected_hash, (
        "The event hash returned by the blockchain does not "
        "match the hash submitted by the Python client."
    )

    # ---------------------------------------------------------
    # VERIFY RECORDER
    # ---------------------------------------------------------

    assert entry["recorder"].lower() == (
        client.account.address.lower()
    ), (
        "The blockchain recorder address does not match "
        "the Python client's account."
    )

    # ---------------------------------------------------------
    # VERIFY RECOVERY STATE
    # ---------------------------------------------------------

    assert entry["recovery_verified"] is False, (
        "A newly recorded event must not be recovery verified."
    )

    # ---------------------------------------------------------
    # SUCCESS
    # ---------------------------------------------------------

    print("ROUND-TRIP: PASS")
    print("=== SPRINT 2 INTEGRATION COMPLETE ===")