"""
evaluation/base_metrics.py — BASE Framework Quantitative Evaluation.

Novelty Pillar 4: Measurable Evaluation.
Computes BASE framework metrics strictly from REAL stored incident history in SQLite,
never from estimates or hard-coded assumptions.

Metrics Computed:
  1. Total Detected: Total volume of parsed and detected forensic threats.
  2. Ledger Write Latency: Real on-chain commitment latency (min, avg, max in seconds).
  3. Forensic Completeness %: Proportion of detected incidents successfully anchored on-chain.
  4. Recovery Verification Rate %: Proportion of incidents reaching verified mitigation.
  5. End-to-End Closed-Loop Rate %: Proportion of incidents completing detection -> blockchain -> explainability -> recovery -> persistence.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

# Ensure parent directory is on import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from chainforensics.database.models import Incident


@dataclass(frozen=True)
class BaseMetricsReport:
    total_detected: int
    ledger_write_latency_avg_seconds: float | None
    ledger_write_latency_min_seconds: float | None
    ledger_write_latency_max_seconds: float | None
    forensic_completeness_percent: float
    recovery_verification_rate_percent: float
    end_to_end_closed_loop_rate_percent: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_base_metrics(database_url: str | None = None) -> BaseMetricsReport:
    """
    Compute BASE framework metrics from the actual database session.
    """
    if database_url is None:
        database_url = os.environ.get(
            "CHAINFORENSIS_DATABASE_URL",
            "sqlite:///./chainforensics.db",
        )

    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()

    try:
        total = int(session.scalar(select(func.count(Incident.id))) or 0)

        if total == 0:
            return BaseMetricsReport(
                total_detected=0,
                ledger_write_latency_avg_seconds=None,
                ledger_write_latency_min_seconds=None,
                ledger_write_latency_max_seconds=None,
                forensic_completeness_percent=0.0,
                recovery_verification_rate_percent=0.0,
                end_to_end_closed_loop_rate_percent=0.0,
            )

        # 1. Latency metrics from real logs
        latencies = [
            float(val)
            for val in session.scalars(
                select(Incident.ledger_write_latency_seconds).where(
                    Incident.ledger_write_latency_seconds.is_not(None)
                )
            ).all()
            if val is not None
        ]

        avg_lat = round(sum(latencies) / len(latencies), 4) if latencies else None
        min_lat = round(min(latencies), 4) if latencies else None
        max_lat = round(max(latencies), 4) if latencies else None

        # 2. Forensic Completeness: On-chain event transaction exists
        on_chain_count = int(
            session.scalar(
                select(func.count(Incident.id)).where(
                    Incident.event_transaction_hash.is_not(None)
                )
            )
            or 0
        )
        completeness_pct = round((on_chain_count / total) * 100.0, 2)

        # 3. Recovery Verification Rate: recovery_verified is True
        verified_count = int(
            session.scalar(
                select(func.count(Incident.id)).where(
                    Incident.recovery_verified.is_(True)
                )
            )
            or 0
        )
        rec_verification_rate = round((verified_count / total) * 100.0, 2)

        # 4. End-to-End Closed-Loop Rate: on-chain logged and terminal recovery status
        closed_loop_count = int(
            session.scalar(
                select(func.count(Incident.id)).where(
                    Incident.event_transaction_hash.is_not(None),
                    Incident.recovery_status.in_(["verified", "escalated"]),
                )
            )
            or 0
        )
        closed_loop_rate = round((closed_loop_count / total) * 100.0, 2)

        return BaseMetricsReport(
            total_detected=total,
            ledger_write_latency_avg_seconds=avg_lat,
            ledger_write_latency_min_seconds=min_lat,
            ledger_write_latency_max_seconds=max_lat,
            forensic_completeness_percent=completeness_pct,
            recovery_verification_rate_percent=rec_verification_rate,
            end_to_end_closed_loop_rate_percent=closed_loop_rate,
        )
    finally:
        session.close()


def print_evaluation_report(report: BaseMetricsReport) -> None:
    print("=" * 65)
    print("CHAINFORENSICS — BASE FRAMEWORK EVALUATION REPORT (NOVELTY PILLAR 4)")
    print("=" * 65)
    print(f"Total Incidents Detected:          {report.total_detected}")
    print(f"Forensic Completeness Rate:        {report.forensic_completeness_percent:.2f}%")
    print(f"Recovery Verification Rate:        {report.recovery_verification_rate_percent:.2f}%")
    print(f"End-to-End Closed-Loop Rate:       {report.end_to_end_closed_loop_rate_percent:.2f}%")
    print("-" * 65)
    print("On-Chain Ledger Write Latency (Synchronous Mining Verification):")
    if report.ledger_write_latency_avg_seconds is not None:
        print(f"  Average Latency:                 {report.ledger_write_latency_avg_seconds:.4f} s")
        print(f"  Minimum Latency:                 {report.ledger_write_latency_min_seconds:.4f} s")
        print(f"  Maximum Latency:                 {report.ledger_write_latency_max_seconds:.4f} s")
    else:
        print("  Latency Data:                    N/A (No on-chain transactions yet)")
    print("=" * 65)


if __name__ == "__main__":
    report = compute_base_metrics()
    print_evaluation_report(report)
