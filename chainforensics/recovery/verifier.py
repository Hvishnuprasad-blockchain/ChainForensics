from __future__ import annotations

from typing import Any


class RecoveryVerificationError(Exception):
    """Raised when recovery verification cannot be completed safely."""


def _normalize_hash(value: Any) -> str:
    """
    Convert blockchain hash representations into
    comparable lowercase hexadecimal strings.

    Supports:
        bytes
        bytearray
        0x-prefixed strings
        normal hexadecimal strings
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
        f"Unsupported blockchain hash type: "
        f"{type(value).__name__}"
    )


def find_event_index(
    client: Any,
    event_hash: str,
) -> int | None:
    """
    Find the correct on-chain ledger index by scanning
    every actual blockchain entry.

    We deliberately DO NOT assume:

        local incident number == blockchain index
    """

    expected_hash = _normalize_hash(
        event_hash
    )

    count = client.get_entry_count()

    # Search in reverse: recently logged events are at the end of the ledger (O(1) in practice)
    for index in range(count - 1, -1, -1):

        entry = client.get_entry(index)

        blockchain_hash = _normalize_hash(
            entry["event_hash"]
        )

        if blockchain_hash == expected_hash:
            return index

    return None


def verify_recovery(
    *,
    event: dict[str, Any],
    simulation_result: Any,
    client: Any,
) -> dict[str, Any]:
    """
    Sprint 4 closed-loop verification.

    VERIFIED:

        simulation succeeded
            ↓
        find matching blockchain hash
            ↓
        find real blockchain index
            ↓
        markRecoveryVerified(index)

    ESCALATED:

        simulation failed
            ↓
        NO blockchain write
    """

    event_hash = event.get(
        "_event_hash"
    )

    if not event_hash:

        raise RecoveryVerificationError(
            "Event does not contain '_event_hash'. "
            "The blockchain matching hash is required."
        )

    status = str(
        getattr(
            simulation_result,
            "status",
            "",
        )
    ).lower()

    # =========================================================
    # FAILURE / ESCALATION
    # =========================================================

    if status != "verified":

        return {
            "status": "escalated",
            "attack_type": event.get(
                "attack_type",
                "UNKNOWN",
            ),
            "event_hash": event_hash,
            "blockchain_write": False,
            "reason": getattr(
                simulation_result,
                "reason",
                "Recovery verification failed.",
            ),
        }

    # =========================================================
    # SUCCESS
    # =========================================================

    index = find_event_index(
        client=client,
        event_hash=event_hash,
    )

    # ---------------------------------------------------------
    # Hash not found
    # ---------------------------------------------------------

    if index is None:

        raise RecoveryVerificationError(
            "Recovery simulation succeeded, "
            "but the matching forensic event "
            "was not found on-chain. "
            "Blockchain verification was NOT written."
        )

    # ---------------------------------------------------------
    # ONLY BLOCKCHAIN WRITE IN THIS VERIFIER
    # ---------------------------------------------------------

    transaction_result = (
        client.mark_recovery_verified(
            index
        )
    )

    # ---------------------------------------------------------
    # RETURN VERIFIED RESULT
    # ---------------------------------------------------------

    return {
        "status": "verified",
        "attack_type": event.get(
            "attack_type",
            "UNKNOWN",
        ),
        "event_hash": event_hash,
        "entry_index": index,
        "blockchain_write": True,
        "transaction": transaction_result,
        "reason": getattr(
            simulation_result,
            "reason",
            "Recovery successfully verified.",
        ),
    }