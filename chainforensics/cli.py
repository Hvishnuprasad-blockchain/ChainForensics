"""
ChainForensics — Sprint 1: CLI Entrypoint

Re-runnable retraining command for the detection engine.

Usage:
    python -m chainforensics.cli retrain <csv_path> [--models-dir DIR] [--logs-dir DIR]

Example:
    python -m chainforensics.cli retrain data/raw/Tuesday-WorkingHours.pcap_ISCX.csv
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .ingestion import load_csv
from .model import SUPPORTED_CLASSES, train_and_persist

LOGGER = logging.getLogger(__name__)


def _setup_logging() -> None:
    """Configure structured logging to stdout at INFO level."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


def _cmd_retrain(args: argparse.Namespace) -> int:
    """Execute the retrain sub-command."""
    csv_path = Path(args.csv_path)

    LOGGER.info("retrain_start csv_path=%s", csv_path)

    # ── Ingest ──
    frame, stats = load_csv(csv_path)

    print(
        f"\nINGESTION SUMMARY\n"
        f"  Source:              {stats.source}\n"
        f"  Rows read:          {stats.rows_read}\n"
        f"  Rows returned:      {stats.rows_returned}\n"
        f"  Rows rejected:      {stats.rows_rejected}\n"
        f"  Columns fixed:      {stats.leading_space_columns_fixed}\n"
        f"  Inf cells:          {stats.inf_cells}\n"
        f"  NaN cells:          {stats.nan_cells}\n"
        f"  Unknown labels:     {stats.unknown_label_rows}\n"
    )

    # ── Train ──
    artifact_path, metadata = train_and_persist(
        frame,
        models_dir=args.models_dir,
        logs_dir=args.logs_dir,
    )

    print(f"MODEL_ARTIFACT={artifact_path}")
    print(f"MODEL_VERSION={metadata['model_version']}")
    print(
        f"TRAINING_DURATION={metadata['training_duration_seconds']:.2f}s"
    )
    print()

    # ── Classification report ──
    print("CLASSIFICATION REPORT:")
    print("-" * 65)
    print(f"  {'Class':<14} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print("-" * 65)

    for label in SUPPORTED_CLASSES:
        m = metadata["metrics"].get(label, {})
        print(
            f"  {label:<14} {m.get('precision', 0):.4f}"
            f"     {m.get('recall', 0):.4f}"
            f"     {m.get('f1-score', 0):.4f}"
            f"     {int(m.get('support', 0)):>6}"
        )

    print("-" * 65)
    accuracy = metadata["metrics"].get("accuracy", 0)
    print(f"  {'Accuracy':<14} {accuracy:.4f}")
    print()

    # ── Suspiciously-perfect check ──
    all_perfect = all(
        metadata["metrics"].get(label, {}).get("f1-score", 0) == 1.0
        for label in SUPPORTED_CLASSES
    )
    if all_perfect:
        print(
            "⚠  WARNING: All classes report perfect F1=1.0.\n"
            "   This is suspicious and may indicate:\n"
            "   (a) Data leakage (train/test split not truly independent),\n"
            "   (b) An unrealistically separable synthetic dataset, or\n"
            "   (c) Very small sample sizes where perfect scores are trivial.\n"
            "   Investigate before trusting these numbers in production.\n"
        )

    # ── Class distribution ──
    print("CLASS DISTRIBUTION:")
    for cls, count in metadata["class_distribution"].items():
        print(f"  {cls}: {count}")
    print()

    return 0


def main() -> int:
    """CLI entrypoint."""
    _setup_logging()

    parser = argparse.ArgumentParser(
        prog="chainforensics",
        description="ChainForensics AI Detection Engine CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── retrain sub-command ──
    retrain_parser = subparsers.add_parser(
        "retrain",
        help="Train a new detection model from a CSV file.",
    )
    retrain_parser.add_argument(
        "csv_path",
        help="Path to the CSV training data file.",
    )
    retrain_parser.add_argument(
        "--models-dir",
        default="models",
        help="Directory to save model artifacts (default: models/).",
    )
    retrain_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory to save training logs (default: logs/).",
    )

    args = parser.parse_args()

    if args.command == "retrain":
        return _cmd_retrain(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
