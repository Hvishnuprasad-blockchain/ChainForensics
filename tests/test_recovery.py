from dataclasses import dataclass
from unittest.mock import Mock

from chainforensics.recovery.simulator import simulate_recovery
from chainforensics.recovery.verifier import (
    find_event_index,
    verify_recovery,
)


# ============================================================
# Test helper
# ============================================================

@dataclass
class FakeSimulationResult:
    status: str
    attack_type: str = "PortScan"
    action: str = "Restrict and investigate scanning source"
    reason: str = "Test recovery result"


# ============================================================
# Fake blockchain client
# ============================================================

class FakeBlockchainClient:
    """
    Fake blockchain used for unit testing.

    It contains deliberately non-sequential-looking event
    hashes so the verifier must scan the chain instead of
    assuming the local incident index.
    """

    def __init__(self):
        self.entries = [
            {
                "event_hash": bytes.fromhex(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                "recorder": "0x1111",
                "recovery_verified": False,
            },
            {
                "event_hash": bytes.fromhex(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                "recorder": "0x2222",
                "recovery_verified": False,
            },
            {
                "event_hash": bytes.fromhex(
                    "cccccccccccccccccccccccccccccccc"
                    "cccccccccccccccccccccccccccccccc"
                ),
                "recorder": "0x3333",
                "recovery_verified": False,
            },
        ]

        self.mark_calls = []

    def get_entry_count(self):
        return len(self.entries)

    def get_entry(self, index):
        return self.entries[index]

    def mark_recovery_verified(self, index):
        self.mark_calls.append(index)

        return {
            "tx_hash": "0xtest-recovery-transaction",
            "index": index,
        }


# ============================================================
# TEST 1
# Successful recovery must write exactly once
# ============================================================

def test_verified_success_calls_mark_recovery_verified_once():

    client = FakeBlockchainClient()

    event_hash = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    event = {
        "flow_id": "CF-TEST-VERIFIED-001",
        "attack_type": "PortScan",
        "_event_hash": event_hash,
    }

    simulation = FakeSimulationResult(
        status="verified",
        reason="Recovery condition resolved.",
    )

    result = verify_recovery(
        event=event,
        simulation_result=simulation,
        client=client,
    )

    assert result["status"] == "verified"

    assert result["entry_index"] == 1

    assert result["blockchain_write"] is True

    # EXACTLY ONE blockchain write.
    assert client.mark_calls == [1]


# ============================================================
# TEST 2
# Verify correct index is found by scanning
# ============================================================

def test_find_event_index_scans_actual_chain():

    client = FakeBlockchainClient()

    event_hash = (
        "cccccccccccccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccc"
    )

    index = find_event_index(
        client=client,
        event_hash=event_hash,
    )

    assert index == 2


# ============================================================
# TEST 3
# Unknown hash must return None
# ============================================================

def test_find_event_index_returns_none_when_missing():

    client = FakeBlockchainClient()

    event_hash = (
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd"
    )

    index = find_event_index(
        client=client,
        event_hash=event_hash,
    )

    assert index is None


# ============================================================
# TEST 4
# Failed recovery MUST NOT touch blockchain
# ============================================================

def test_escalated_failure_does_not_write_blockchain():

    client = FakeBlockchainClient()

    event = {
        "flow_id": "CF-TEST-ESCALATED-001",
        "attack_type": "PortScan",
        "_event_hash": (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    }

    simulation = FakeSimulationResult(
        status="escalated",
        reason="Recovery condition remains unresolved.",
    )

    result = verify_recovery(
        event=event,
        simulation_result=simulation,
        client=client,
    )

    assert result["status"] == "escalated"

    assert result["blockchain_write"] is False

    # CRITICAL SPRINT 4 REQUIREMENT:
    # absolutely NO blockchain write.
    assert client.mark_calls == []


# ============================================================
# TEST 5
# Real deterministic simulator success
# ============================================================

def test_simulator_verified_for_recovered_portscan():

    event = {
        "attack_type": "PortScan",
        "raw_features": {
            "packet_count": 150,
        },
    }

    result = simulate_recovery(event)

    assert result.status == "verified"


# ============================================================
# TEST 6
# Real deterministic simulator failure
# ============================================================

def test_simulator_escalates_unresolved_portscan():

    event = {
        "attack_type": "PortScan",
        "raw_features": {
            "packet_count": 500,
        },
    }

    result = simulate_recovery(event)

    assert result.status == "escalated"