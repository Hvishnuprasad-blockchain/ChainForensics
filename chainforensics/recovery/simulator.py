from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RecoverySimulationResult:
    """
    Deterministic result of a simulated recovery action.
    """

    status: str
    attack_type: str
    action: str
    reason: str


# ---------------------------------------------------------
# Deterministic recovery rules
# ---------------------------------------------------------
#
# The simulator intentionally does NOT use random values.
#
# Success/failure is determined from actual forensic-event
# values.
#
# This gives us:
#
# SAME EVENT -> SAME RESULT
#
# The rules are documented and therefore reproducible.
# ---------------------------------------------------------


def _numeric_feature(
    event: dict[str, Any],
    name: str,
) -> float | None:
    """
    Safely read a numeric raw feature.
    """

    value = event.get("raw_features", {}).get(name)

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    return None


def simulate_recovery(
    event: dict[str, Any],
) -> RecoverySimulationResult:
    """
    Simulate execution and verification of the top recovery action.

    Deterministic success/failure rules:

    BENIGN
        Always succeeds because no malicious condition requires
        remediation.

    PortScan
        Success when packet_count <= 200.
        Failure when packet_count > 200.

    DoS
        Success when packet_count <= 500.
        Failure when packet_count > 500.

    BruteForce
        Success when failed_attempts <= 20.
        Failure when failed_attempts > 20.

    SQLInjection
        Success when suspicious_queries <= 10.
        Failure when suspicious_queries > 10.

    Unknown attack types
        Escalated because there is no safe automated recovery
        procedure defined.

    Missing required feature
        Escalated because the system cannot safely claim that
        the underlying condition was resolved.

    These thresholds are simulation stand-ins for infrastructure
    verification. They deliberately favor an honest escalation
    when the evidence required to prove recovery is unavailable.
    """

    attack_type = str(event.get("attack_type", "")).strip()

    # -----------------------------------------------------
    # BENIGN
    # -----------------------------------------------------

    if attack_type == "BENIGN":
        return RecoverySimulationResult(
            status="verified",
            attack_type=attack_type,
            action="No remediation required",
            reason=(
                "The event is classified as BENIGN, so there is "
                "no malicious condition requiring recovery."
            ),
        )

    # -----------------------------------------------------
    # PORT SCAN
    # -----------------------------------------------------

    if attack_type == "PortScan":
        packet_count = _numeric_feature(event, "packet_count")

        if packet_count is None:
            return RecoverySimulationResult(
                status="escalated",
                attack_type=attack_type,
                action="Restrict and investigate scanning source",
                reason=(
                    "Recovery could not be verified because "
                    "packet_count is missing."
                ),
            )

        if packet_count <= 200:
            return RecoverySimulationResult(
                status="verified",
                attack_type=attack_type,
                action="Restrict and investigate scanning source",
                reason=(
                    f"Simulated verification succeeded because "
                    f"packet_count={packet_count:g} is within the "
                    f"recovery threshold of 200."
                ),
            )

        return RecoverySimulationResult(
            status="escalated",
            attack_type=attack_type,
            action="Restrict and investigate scanning source",
            reason=(
                f"Simulated recovery failed because "
                f"packet_count={packet_count:g} remains above "
                f"the recovery threshold of 200."
            ),
        )

    # -----------------------------------------------------
    # DOS
    # -----------------------------------------------------

    if attack_type == "DoS":
        packet_count = _numeric_feature(event, "packet_count")

        if packet_count is None:
            return RecoverySimulationResult(
                status="escalated",
                attack_type=attack_type,
                action="Rate-limit the source and protect availability",
                reason=(
                    "Recovery could not be verified because "
                    "packet_count is missing."
                ),
            )

        if packet_count <= 500:
            return RecoverySimulationResult(
                status="verified",
                attack_type=attack_type,
                action="Rate-limit the source and protect availability",
                reason=(
                    f"Simulated verification succeeded because "
                    f"packet_count={packet_count:g} is within the "
                    f"recovery threshold of 500."
                ),
            )

        return RecoverySimulationResult(
            status="escalated",
            attack_type=attack_type,
            action="Rate-limit the source and protect availability",
            reason=(
                f"Simulated recovery failed because "
                f"packet_count={packet_count:g} remains above "
                f"the recovery threshold of 500."
            ),
        )

    # -----------------------------------------------------
    # BRUTE FORCE
    # -----------------------------------------------------

    if attack_type == "BruteForce":
        failed_attempts = _numeric_feature(
            event,
            "failed_attempts",
        )

        if failed_attempts is None:
            return RecoverySimulationResult(
                status="escalated",
                attack_type=attack_type,
                action="Lock or rate-limit the targeted account",
                reason=(
                    "Recovery could not be verified because "
                    "failed_attempts is missing."
                ),
            )

        if failed_attempts <= 20:
            return RecoverySimulationResult(
                status="verified",
                attack_type=attack_type,
                action="Lock or rate-limit the targeted account",
                reason=(
                    f"Simulated verification succeeded because "
                    f"failed_attempts={failed_attempts:g} is within "
                    f"the recovery threshold of 20."
                ),
            )

        return RecoverySimulationResult(
            status="escalated",
            attack_type=attack_type,
            action="Lock or rate-limit the targeted account",
            reason=(
                f"Simulated recovery failed because "
                f"failed_attempts={failed_attempts:g} remains above "
                f"the recovery threshold of 20."
            ),
        )

    # -----------------------------------------------------
    # SQL INJECTION
    # -----------------------------------------------------

    if attack_type == "SQLInjection":
        suspicious_queries = _numeric_feature(
            event,
            "suspicious_queries",
        )

        if suspicious_queries is None:
            return RecoverySimulationResult(
                status="escalated",
                attack_type=attack_type,
                action="Block suspicious queries and inspect the application",
                reason=(
                    "Recovery could not be verified because "
                    "suspicious_queries is missing."
                ),
            )

        if suspicious_queries <= 10:
            return RecoverySimulationResult(
                status="verified",
                attack_type=attack_type,
                action="Block suspicious queries and inspect the application",
                reason=(
                    f"Simulated verification succeeded because "
                    f"suspicious_queries={suspicious_queries:g} is within "
                    f"the recovery threshold of 10."
                ),
            )

        return RecoverySimulationResult(
            status="escalated",
            attack_type=attack_type,
            action="Block suspicious queries and inspect the application",
            reason=(
                f"Simulated recovery failed because "
                f"suspicious_queries={suspicious_queries:g} remains above "
                f"the recovery threshold of 10."
            ),
        )

    # -----------------------------------------------------
    # UNKNOWN ATTACK TYPE
    # -----------------------------------------------------

    return RecoverySimulationResult(
        status="escalated",
        attack_type=attack_type or "UNKNOWN",
        action="Manual incident investigation",
        reason=(
            "No deterministic automated recovery procedure exists "
            "for this attack type. Manual review is required."
        ),
    )