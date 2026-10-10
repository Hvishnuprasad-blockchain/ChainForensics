from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .exceptions import SchemaValidationError


LOGGER = logging.getLogger(__name__)

LABEL_COLUMN = "Label"

SUPPORTED_LABELS = frozenset({
    "BENIGN",
    "DoS",
    "PortScan",
    "BruteForce",
})

CICIDS_LABEL_MAP = {
    "BENIGN": "BENIGN",

    # DoS
    "DoS": "DoS",
    "DDoS": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",

    # Port Scan
    "PortScan": "PortScan",

    # Brute Force
    "BruteForce": "BruteForce",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack â€“ Brute Force": "BruteForce",
    "Web Attack - Brute Force": "BruteForce",
}


@dataclass(frozen=True)
class IngestionStats:
    source: str
    rows_read: int
    rows_returned: int
    rows_rejected: int
    leading_space_columns_fixed: int
    inf_cells: int
    nan_cells: int
    unknown_label_rows: int


def _normalize_columns(frame: pd.DataFrame):
    original = list(frame.columns)

    normalized = [
        str(column).strip()
        for column in original
    ]

    if len(set(normalized)) != len(normalized):
        raise SchemaValidationError(
            "CSV contains duplicate column names after whitespace normalization."
        )

    out = frame.copy()
    out.columns = normalized

    changed = sum(
        original_name != normalized_name
        for original_name, normalized_name in zip(original, normalized)
    )

    return out, changed


def _normalize_labels(frame: pd.DataFrame):
    if LABEL_COLUMN not in frame.columns:
        raise SchemaValidationError(
            "Required label column 'Label' is missing."
        )

    labels = (
        frame[LABEL_COLUMN]
        .astype("string")
        .str.strip()
    )

    # Find labels that Sprint 1 does not support.
    unknown_mask = ~labels.isin(CICIDS_LABEL_MAP)

    unknown_count = int(unknown_mask.sum())

    if unknown_count:
        examples = sorted(
            labels[unknown_mask]
            .dropna()
            .unique()
            .tolist()
        )[:10]

        LOGGER.warning(
            "unsupported_labels_rejected count=%d examples=%s",
            unknown_count,
            examples,
        )

    # Keep only supported rows.
    valid_mask = ~unknown_mask

    out = frame.loc[valid_mask].copy()

    # Convert CICIDS2017 labels into Sprint 1 labels.
    out[LABEL_COLUMN] = (
        labels.loc[valid_mask]
        .map(CICIDS_LABEL_MAP)
        .astype("string")
    )

    return out, unknown_count


def load_csv(
    path: str | Path,
    *,
    logger: logging.Logger = LOGGER,
):
    """
    Read CSV strictly as data.

    Cell contents are never evaluated or executed.

    Unsupported labels are rejected rather than stopping the
    complete ingestion process.
    """

    p = Path(path)

    if not p.is_file():
        raise SchemaValidationError(
            f"CSV file does not exist: {path}"
        )

    # Read the CSV.
    frame = pd.read_csv(
        p,
        low_memory=False,
    )

    rows_read = len(frame)

    # Normalize column names.
    frame, columns_changed = _normalize_columns(frame)

    if LABEL_COLUMN not in frame.columns:
        raise SchemaValidationError(
            "Required label column 'Label' is missing."
        )

    # Check numeric columns for invalid values.
    numeric = (
        frame
        .drop(columns=[LABEL_COLUMN], errors="ignore")
        .select_dtypes(include="number")
    )

    inf_cells = int(
        numeric
        .isin([float("inf"), float("-inf")])
        .sum()
        .sum()
    )

    nan_cells = int(
        numeric
        .isna()
        .sum()
        .sum()
    )

    # Normalize labels and reject unsupported rows.
    frame, unknown_label_rows = _normalize_labels(frame)

    rows_returned = len(frame)
    rows_rejected = rows_read - rows_returned

    logger.info(
        "csv_ingested "
        "source=%s "
        "rows_read=%d "
        "rows_returned=%d "
        "rows_rejected=%d "
        "leading_space_columns_fixed=%d "
        "inf_cells=%d "
        "nan_cells=%d "
        "unknown_label_rows=%d",
        str(p),
        rows_read,
        rows_returned,
        rows_rejected,
        columns_changed,
        inf_cells,
        nan_cells,
        unknown_label_rows,
    )

    return frame, IngestionStats(
        source=str(p),
        rows_read=rows_read,
        rows_returned=rows_returned,
        rows_rejected=rows_rejected,
        leading_space_columns_fixed=columns_changed,
        inf_cells=inf_cells,
        nan_cells=nan_cells,
        unknown_label_rows=unknown_label_rows,
    )