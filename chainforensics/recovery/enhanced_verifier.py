from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Optional

from chainforensics.recovery.simulator import RecoverySimulationResult, simulate_recovery
from chainforensics.recovery.verifier import verify_recovery

logger = logging.getLogger("chainforensics.recovery.enhanced_verifier")


@dataclass(frozen=True)
class WindowCheck:
    """Telemetry checkpoint at a specific time offset."""
    check_index: int
    offset_seconds: int
    status: str  # 'pass' | 'fail'
    metric_value: float
    threshold: float
    detail: str


@dataclass(frozen=True)
class EnhancedVerificationResult:
    """
    v2 Feature 4 multi-check time-windowed verification result.
    Outcomes:
      - fully_recovered: All multi-window checks pass. On-chain confirmation written.
      - still_at_risk: Inconsistent or borderline checks. NO on-chain write; monitoring flagged.
      - escalated: All checks fail. Unresolved attack; no on-chain recovery confirmation.
    """
    status: str  # 'fully_recovered' | 'still_at_risk' | 'escalated'
    checks_passed: int
    checks_total: int
    checks: list[dict[str, Any]]
    blockchain_written: bool
    v1_verification: dict[str, Any]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "checks_passed": self.checks_passed,
            "checks_total": self.checks_total,
            "checks": self.checks,
            "blockchain_written": self.blockchain_written,
            "v1_verification": self.v1_verification,
            "summary": self.summary,
        }


class EnhancedRecoveryVerifier:
    """
    v2 Feature 4: Full Multi-Check Recovery Verification.

    Architectural design:
      An additive layer in front of v1's existing verifier.
      Performs 3 time-windowed checks (T+0s, T+30s, T+60s) to guard against the
      'false quiet' phenomenon common in network security incidents.
    """

    def __init__(self, check_offsets: tuple[int, ...] = (0, 30, 60)):
        self.check_offsets = check_offsets

    def evaluate_checks(
        self,
        event: dict[str, Any],
        initial_sim: Optional[RecoverySimulationResult] = None,
        custom_telemetry_series: Optional[list[dict[str, Any]]] = None,
    ) -> list[WindowCheck]:
        """
        Evaluate recovery status across multiple time windows.
        Uses real event features and simulates temporal decay/drift over observation windows.
        """
        sim = initial_sim or simulate_recovery(event)
        attack_type = str(event.get("attack_type", "")).strip()
        raw_features = event.get("raw_features", {}) or {}

        # Identify primary metric and safety threshold
        if attack_type == "PortScan":
            primary_metric = float(raw_features.get("packet_count", 0))
            threshold = 200.0
        elif attack_type == "DoS":
            primary_metric = float(raw_features.get("packet_count", 0))
            threshold = 500.0
        elif attack_type == "BruteForce":
            primary_metric = float(raw_features.get("failed_attempts", 0))
            threshold = 20.0
        elif attack_type == "SQLInjection":
            primary_metric = float(raw_features.get("suspicious_queries", 0))
            threshold = 10.0
        elif attack_type == "BENIGN":
            primary_metric = 0.0
            threshold = 1.0
        else:
            primary_metric = 999.0
            threshold = 0.0

        checks: list[WindowCheck] = []

        for i, offset in enumerate(self.check_offsets):
            if custom_telemetry_series and i < len(custom_telemetry_series):
                telemetry = custom_telemetry_series[i]
                metric = float(telemetry.get("metric_value", primary_metric))
                passed = bool(telemetry.get("passed", metric <= threshold))
                detail = str(telemetry.get("detail", f"Custom window T+{offset}s check"))
            else:
                # Deterministic time-drift simulation:
                # If primary metric was > threshold, attack is unresolved -> all checks fail
                # If primary metric was <= 70% threshold -> resilient remediation -> all checks pass
                # If primary metric was borderline (70% - 100% threshold) -> residual jitter causes later window to fail
                if sim.status != "verified":
                    metric = primary_metric * (1.0 + (i * 0.1))
                    passed = False
                    detail = f"Telemetry at T+{offset}s exceeds threshold ({metric:.1f} > {threshold:.1f}): {sim.reason}"
                else:
                    if attack_type == "BENIGN":
                        metric = 0.0
                        passed = True
                        detail = f"T+{offset}s: System baseline normal"
                    elif primary_metric > (threshold * 0.70):
                        # Borderline: T+0 passes, but later window suffers residual traffic burst
                        if i == 0:
                            metric = primary_metric
                            passed = True
                            detail = f"T+{offset}s: Initial mitigation active ({metric:.1f} <= {threshold:.1f})"
                        else:
                            metric = primary_metric * (1.0 + (i * 0.20))
                            passed = False
                            detail = f"T+{offset}s: Borderline mitigation flapped ({metric:.1f} > {threshold:.1f})"
                    else:
                        # Fully recovered: robust suppression across all windows
                        metric = primary_metric * max(0.2, (1.0 - (i * 0.35)))
                        passed = True
                        detail = f"T+{offset}s: Traffic safely stabilized ({metric:.1f} <= {threshold:.1f})"

            checks.append(
                WindowCheck(
                    check_index=i + 1,
                    offset_seconds=offset,
                    status="pass" if passed else "fail",
                    metric_value=round(metric, 2),
                    threshold=threshold,
                    detail=detail,
                )
            )

        return checks

    def verify(
        self,
        *,
        event: dict[str, Any],
        simulation_result: Optional[RecoverySimulationResult] = None,
        client: Any = None,
        custom_telemetry_series: Optional[list[dict[str, Any]]] = None,
    ) -> EnhancedVerificationResult:
        """
        Execute enhanced verification and map to on-chain confirmation where appropriate.
        """
        sim = simulation_result or simulate_recovery(event)
        checks = self.evaluate_checks(
            event=event,
            initial_sim=sim,
            custom_telemetry_series=custom_telemetry_series,
        )

        passed_count = sum(1 for c in checks if c.status == "pass")
        total_count = len(checks)
        checks_dicts = [asdict(c) for c in checks]

        if passed_count == total_count:
            status = "fully_recovered"
            summary = (
                f"All {total_count} time-windowed checks passed. "
                "Infrastructure remediated cleanly. Committing on-chain verification."
            )
            v1_res = {}
            on_chain_written = False
            if client is not None and event.get("_event_hash"):
                try:
                    v1_res = verify_recovery(
                        event=event,
                        simulation_result=sim,
                        client=client,
                    )
                    on_chain_written = bool(v1_res.get("blockchain_write", False))
                except Exception as exc:
                    logger.warning("v1 verify_recovery call error during full recovery: %s", exc)
                    v1_res = {"status": "error", "error": str(exc), "blockchain_write": False}
            else:
                v1_res = {"status": "verified", "blockchain_write": False, "note": "No client/event_hash provided"}

        elif passed_count == 0:
            status = "escalated"
            summary = f"All {total_count} time-windowed checks failed. Attack unresolved; escalation confirmed."
            v1_res = {
                "status": "escalated",
                "attack_type": event.get("attack_type", "UNKNOWN"),
                "event_hash": event.get("_event_hash"),
                "blockchain_write": False,
                "reason": sim.reason,
            }
            on_chain_written = False

        else:
            status = "still_at_risk"
            summary = (
                f"Inconsistent verification ({passed_count}/{total_count} checks passed). "
                "Residual anomaly detected during observation window. Flagged for monitoring; on-chain confirmation withheld."
            )
            v1_res = {
                "status": "still_at_risk",
                "attack_type": event.get("attack_type", "UNKNOWN"),
                "event_hash": event.get("_event_hash"),
                "blockchain_write": False,
                "reason": "Intermittent or borderline mitigation stability.",
            }
            on_chain_written = False

        return EnhancedVerificationResult(
            status=status,
            checks_passed=passed_count,
            checks_total=total_count,
            checks=checks_dicts,
            blockchain_written=on_chain_written,
            v1_verification=v1_res,
            summary=summary,
        )
