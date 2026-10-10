"""
ChainForensics — Sprint 2 Test Suite: Immutable Blockchain Forensic Ledger

Tests cover:
  1. Deterministic event building & SHA-256 canonical hashing (Novelty Pillar 1)
  2. BlockchainClient local Hardhat integration (write, read, count)
  3. Real measured latency & gas tracking
  4. Duplicate-hash rejection (tamper / replay defense)
  5. Invalid input rejection (empty hash, wrong length, non-hex, negative index)
  6. Exponential backoff retry mechanism on RPC failure
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
import pytest

from chainforensics.event_builder import (
    build_forensic_event,
    canonicalize_event,
    hash_forensic_event,
)
from chainforensics.blockchain.client import BlockchainClient, BlockchainWriteResult
from chainforensics.blockchain.abi import load_forensic_ledger_abi


LOGGER = logging.getLogger(__name__)


# =====================================================================
# 1. UNIT: Event Builder & Deterministic Canonical Hashing
# =====================================================================

class TestEventBuilderDeterminism:
    """Verifies Novelty Pillar 1: identical logical content must hash identically."""

    def test_hash_is_deterministic_regardless_of_dict_insertion_order(self):
        # Two dicts with exact same keys/values but inserted in different orders
        event_1 = {
            "flow_id": "flow-alpha-99",
            "timestamp": "2026-09-30T10:00:00Z",
            "source": {"ip": "192.168.1.100", "port": 49152},
            "destination": {"ip": "10.0.0.1", "port": 80},
            "attack_type": "DoS",
            "confidence": 0.9942,
            "raw_features": {"Flow Duration": 12000, "Total Fwd Packets": 45},
        }

        event_2 = {
            "raw_features": {"Total Fwd Packets": 45, "Flow Duration": 12000},
            "confidence": 0.9942,
            "destination": {"port": 80, "ip": "10.0.0.1"},
            "timestamp": "2026-09-30T10:00:00Z",
            "source": {"port": 49152, "ip": "192.168.1.100"},
            "attack_type": "DoS",
            "flow_id": "flow-alpha-99",
        }

        hash_1 = hash_forensic_event(event_1)
        hash_2 = hash_forensic_event(event_2)

        assert len(hash_1) == 64
        assert len(hash_2) == 64
        assert hash_1 == hash_2, "Hashes must be identical regardless of key order"

    def test_canonicalize_produces_compact_json_without_whitespace(self):
        event = {"b": 2, "a": 1}
        raw_bytes = canonicalize_event(event)
        # Should be compact: b'{"a":1,"b":2}'
        assert raw_bytes == b'{"a":1,"b":2}'

    def test_build_forensic_event_standardizes_types(self):
        event = build_forensic_event(
            flow_id="FL-101",
            timestamp="2026-09-30T12:00:00Z",
            src_ip="10.0.0.5",
            src_port=8080,
            dst_ip="10.0.0.1",
            dst_port=443,
            attack_type="PortScan",
            confidence=0.999,
            raw_features={"packet_count": 250},
        )
        assert event["flow_id"] == "FL-101"
        assert event["source"]["port"] == 8080
        assert event["destination"]["ip"] == "10.0.0.1"
        assert isinstance(event["confidence"], float)


# =====================================================================
# 2. UNIT: Input Validation on Blockchain Client
# =====================================================================

class TestBlockchainClientInputValidation:
    """Verifies BlockchainClient rejects invalid or malformed arguments before RPC."""

    @pytest.fixture
    def dummy_client(self):
        return BlockchainClient(
            rpc_url="http://127.0.0.1:8545",
            private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            contract_abi=load_forensic_ledger_abi(),
            max_retries=1,
            base_delay_seconds=0.01,
        )

    def test_rejects_empty_hash(self, dummy_client):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            dummy_client.log_event("")

    def test_rejects_short_hash(self, dummy_client):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            dummy_client.log_event("abcdef12345")

    def test_rejects_non_hex_hash(self, dummy_client):
        with pytest.raises(ValueError, match="non-hexadecimal"):
            dummy_client.log_event("z" * 64)

    def test_rejects_negative_index(self, dummy_client):
        with pytest.raises(ValueError, match="cannot be negative"):
            dummy_client.get_entry(-1)

    def test_rejects_non_int_index(self, dummy_client):
        with pytest.raises(TypeError, match="must be an integer"):
            dummy_client.get_entry("0")  # type: ignore


# =====================================================================
# 3. UNIT & INTEGRATION: RPC Retry & Backoff Logic
# =====================================================================

class TestRPCRetryAndBackoff:
    """Proves exponential backoff and retry behavior on transient/terminal failures."""

    def test_exponential_backoff_timing_and_attempts(self):
        """Points to an unreachable port, verifies 3 retries (4 attempts) and backoff."""
        client = BlockchainClient(
            rpc_url="http://127.0.0.1:59998",
            private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            contract_abi=load_forensic_ledger_abi(),
            max_retries=3,
            base_delay_seconds=0.05,
        )

        t_start = time.perf_counter()
        with pytest.raises(Exception):
            client.get_entry_count()
        t_elapsed = time.perf_counter() - t_start

        # Backoff delays: 0.05 * 2^0 (0.05) + 0.05 * 2^1 (0.10) + 0.05 * 2^2 (0.20) = 0.35s minimum
        assert t_elapsed >= 0.25, f"Expected at least 0.25s elapsed backoff, got {t_elapsed:.3f}s"

    def test_transient_failure_recovers_on_retry(self):
        """Verifies that if an operation succeeds on retry, the result is returned cleanly."""
        client = BlockchainClient(
            rpc_url="http://127.0.0.1:8545",
            private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            contract_abi=load_forensic_ledger_abi(),
            max_retries=3,
            base_delay_seconds=0.01,
        )

        attempts = 0

        def flaky_operation():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionError("Temporary RPC network glitch")
            return 42

        result = client._with_retry("test_flaky", flaky_operation)
        assert result == 42
        assert attempts == 3


# =====================================================================
# 4. INTEGRATION: Local Hardhat Node Live Tests (When Node is Active)
# =====================================================================

@pytest.fixture(scope="module")
def live_hardhat_client():
    rpc_url = os.getenv("CHAINFORENSIS_RPC_URL", "http://127.0.0.1:8545")
    priv_key = os.getenv(
        "CHAINFORENSIS_PRIVATE_KEY",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    contract_addr = os.getenv(
        "CHAINFORENSIS_CONTRACT_ADDRESS",
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    )

    client = BlockchainClient(
        rpc_url=rpc_url,
        private_key=priv_key,
        contract_address=contract_addr,
        contract_abi=load_forensic_ledger_abi(),
        max_retries=2,
        base_delay_seconds=0.1,
    )
    try:
        # Check node availability
        client.get_entry_count()
    except Exception as exc:
        pytest.skip(f"Hardhat local node is not reachable at {rpc_url}: {exc}")
    return client


class TestLiveHardhatIntegration:
    """Tests real transactions against the running Hardhat node."""

    def test_log_event_and_round_trip(self, live_hardhat_client):
        # Generate fresh hash
        test_hash = hashlib.sha256(f"test-roundtrip-{uuid.uuid4().hex}".encode()).hexdigest()
        
        before_count = live_hardhat_client.get_entry_count()
        write_result = live_hardhat_client.log_event(test_hash, event_context="pytest-roundtrip")

        assert isinstance(write_result, BlockchainWriteResult)
        assert write_result.tx_hash.startswith("0x") or len(write_result.tx_hash) == 64
        assert write_result.gas_used > 0
        assert write_result.latency_seconds > 0.0
        assert write_result.attempts == 1

        after_count = live_hardhat_client.get_entry_count()
        assert after_count == before_count + 1

        # Read back
        entry = live_hardhat_client.get_entry(before_count)
        returned_hash = "0x" + entry["event_hash"].hex() if isinstance(entry["event_hash"], bytes) else entry["event_hash"]
        expected_hash = "0x" + test_hash.lower()
        assert returned_hash.lower() == expected_hash.lower()
        assert entry["recovery_verified"] is False

    def test_duplicate_hash_rejection(self, live_hardhat_client):
        test_hash = hashlib.sha256(f"test-dup-{uuid.uuid4().hex}".encode()).hexdigest()

        # First write succeeds
        live_hardhat_client.log_event(test_hash, event_context="pytest-dup-1")

        # Second write with same hash must revert
        with pytest.raises(Exception) as excinfo:
            live_hardhat_client.log_event(test_hash, event_context="pytest-dup-2")

        error_msg = str(excinfo.value)
        assert ("reverted" in error_msg.lower() or 
                "duplicatehash" in error_msg.lower() or 
                "transaction reverted" in error_msg.lower())
