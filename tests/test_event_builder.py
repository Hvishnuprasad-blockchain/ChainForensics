from chainforensics.event_builder import (
    build_forensic_event,
    hash_forensic_event,
)


def test_hash_is_deterministic_regardless_of_dict_order():
    event_a = {
        "flow_id": "flow-001",
        "timestamp": "2026-09-29T10:00:00Z",
        "source": {
            "ip": "10.0.0.1",
            "port": 1234,
        },
        "destination": {
            "ip": "10.0.0.2",
            "port": 443,
        },
        "attack_type": "DoS",
        "confidence": 0.98,
        "raw_features": {
            "Flow Duration": 1000,
            "Total Fwd Packets": 10,
        },
    }

    event_b = {
        "raw_features": {
            "Total Fwd Packets": 10,
            "Flow Duration": 1000,
        },
        "confidence": 0.98,
        "attack_type": "DoS",
        "destination": {
            "port": 443,
            "ip": "10.0.0.2",
        },
        "source": {
            "port": 1234,
            "ip": "10.0.0.1",
        },
        "timestamp": "2026-09-29T10:00:00Z",
        "flow_id": "flow-001",
    }

    hash_a = hash_forensic_event(event_a)
    hash_b = hash_forensic_event(event_b)

    assert hash_a == hash_b