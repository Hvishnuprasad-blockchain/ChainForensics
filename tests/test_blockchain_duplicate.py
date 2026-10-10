from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

from chainforensics.blockchain.abi import load_forensic_ledger_abi
from chainforensics.blockchain.client import BlockchainClient


load_dotenv()


def create_client() -> BlockchainClient:
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


def test_python_client_rejects_duplicate_event():
    """
    Sprint 2 security test.

    Proves duplicate-hash protection through the
    Python blockchain client.
    """

    logging.basicConfig(level=logging.INFO)

    client = create_client()

    # Use a hash that is NOT permanently reused between test runs.
    # The timestamp makes each test execution unique.
    import hashlib
    import time

    event_hash = hashlib.sha256(
        f"sprint2-duplicate-security-{time.time_ns()}".encode("utf-8")
    ).hexdigest()

    print("\n=== SPRINT 2 PYTHON CLIENT DUPLICATE TEST ===")
    print("Event hash:", event_hash)

    # ---------------------------------------------------------
    # First write must succeed.
    # ---------------------------------------------------------

    first = client.log_event(
        event_hash,
        event_context="sprint2-duplicate-security-first",
    )

    print("First transaction:", first.tx_hash)
    print("First gas used:", first.gas_used)
    print("First latency:", first.latency_seconds)
    print("First attempts:", first.attempts)

    # ---------------------------------------------------------
    # Second write with the SAME hash must fail.
    # ---------------------------------------------------------

    try:
        client.log_event(
            event_hash,
            event_context="sprint2-duplicate-security-second",
        )

    except Exception as exc:
        print("Duplicate rejection: PASS")
        print("Exception type:", type(exc).__name__)
        print("Exception:", exc)

    else:
        raise AssertionError(
            "Duplicate event hash was accepted. "
            "Duplicate protection is not working."
        )

    print("=== DUPLICATE PROTECTION PROVEN ===")