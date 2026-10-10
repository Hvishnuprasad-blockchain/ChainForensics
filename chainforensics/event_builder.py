from __future__ import annotations

import hashlib
import json
from typing import Any


def build_forensic_event(
    *,
    flow_id: str,
    timestamp: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    attack_type: str,
    confidence: float,
    raw_features: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a deterministic forensic event.

    This is the common event builder used by the
    ChainForensics detection, blockchain, and
    explainability pipelines.
    """

    return {
        "flow_id": str(flow_id),
        "timestamp": str(timestamp),
        "source": {
            "ip": str(src_ip),
            "port": int(src_port),
        },
        "destination": {
            "ip": str(dst_ip),
            "port": int(dst_port),
        },
        "attack_type": str(attack_type),
        "confidence": float(confidence),
        "raw_features": raw_features,
    }


def canonicalize_event(event: dict[str, Any]) -> bytes:
    """
    Convert a forensic event into deterministic canonical JSON bytes.

    RATIONALE (Novelty Pillar 1 - Tamper Evidence):
    In Python, dictionaries preserve insertion order, and JSON encoders
    can emit keys in arbitrary order unless explicitly sorted. If two
    identical logical forensic events have keys inserted in different orders,
    un-sorted serialization would generate different SHA-256 digests.
    
    By strictly enforcing `sort_keys=True` and compact separators (',', ':'),
    identical logical content is guaranteed to produce byte-for-byte identical
    representations regardless of language, platform, or dictionary insertion
    order. This mathematical determinism is the foundational bedrock of the
    tamper-evidence and replay-protection claims on the blockchain ledger.
    """

    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_forensic_event(event: dict[str, Any]) -> str:
    """
    Generate the SHA-256 hash of a forensic event.

    Returns:
        64-character hexadecimal SHA-256 hash.
    """

    canonical_bytes = canonicalize_event(event)

    return hashlib.sha256(canonical_bytes).hexdigest()